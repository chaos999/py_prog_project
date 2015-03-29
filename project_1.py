#!/usr/bin/env python3

import sys
import json
import re
from dns import resolver,reversename,exception
from twisted.names.dns import RRHeader
from collections import defaultdict

raw_cache = defaultdict(list)
normalized_cache = defaultdict(list)
error_cache = defaultdict(list)
ip_addr_cache = {}
dn_cache = {}
discovered_cache = []
summary_cache = defaultdict(list)
	
line_token_count = 0
skipped_token_count = 0
skipped_token_normal = 0
fqdn_count = 0
pqdn = 0
ipv4_count = 0
error_count = 0
lines_processed = 0
uniq_ip_count = 0


def main():

	# Input File Processing
    if (len(sys.argv) != 2):
        print "Please give filename to process"
        filename = raw_input("Enter Filename: ")               
    file_to_process = open(filename, 'r')
    
    j_file = 'json_readable_file'
    output_JD = open(j_file, 'w')
	       

	# Store line numbers and associated unprocessed lines of file
    lnum = 0
    raw_data = {}
    for line in file_to_process:
    	lnum += 1
    	raw_data[lnum] = line
    
    lines_processed = lnum
    print "L is ", (lnum)
    	
    TKN_map = extract_token(raw_data)
    get_token_ready(TKN_map)
    line_token_count = (skipped_token_count + ipv4_count + fqdn_count)
    summary_cache = {"linesWithToken": line_token_count,\
    		"totalFQDN": fqdn_count,\
			"totalIPv4": ipv4_count, "totalErrors": error_count,\
			"tokenSkippedAlreadySeen": skipped_token_count,\
			"errors": error_cache,\
			"discoveredInformation": discovered_cache}
    
    json.dump(summary_cache, output_JD, indent=4, sort_keys=True)

def extract_token(raw_lines):
	token_map = {}
	for key, value in raw_lines.items():
		token1 = value.partition('#')[0]
		token = token1.strip()
		if (token != ''):
			token_map[key] = token
	#token_map = {key: list(value) for key, value in raw_lines.items()}
    
	for keys,values in token_map.items():
		#if(values==5):
		#print type(keys), len(keys)
		print (keys)
   		print(values)
   	
   	return token_map
    	

def get_token_ready(ext_tokens):
	global skipped_token_count	
	global ipv4_count
	global uniq_ip_count
	global raw_cache
	global fqdn_count
	raw_cache['localhost'] = [0]
	normalized_cache['localhost'] = [0]
	for keys,values in ext_tokens.items():
		if((values == 'localhost.') or (values == 'localhost')):
			print "DUPE"
			skipped_token_count += 1
			raw_cache['localhost'].append(keys)
			normalized_cache['localhost'].append(keys)
			continue
		elif (values in raw_cache.keys()):
			raw_cache[values].append(keys)
			skipped_token_count += 1
		else:
			if is_token_validIpv4(values):
				print "VALID-IP", values
				ipv4_count += 1
				print "VV", values, keys
				print "VV-R", raw_cache
				raw_cache[values].append(keys)
				addr=reversename.from_address(values)
				print "VV-GGGGGG", raw_cache
				try:
					ip_to_fqdn = str(resolver.query(addr,"PTR")[0])
				except Exception:
					print "ERROR resolving IP_to_FQDN"
					
				#normalized_cache[values] = keys
				normalized_cache[values].append(keys)
				print "IP1", ip_addr_cache
				print "DS1", discovered_cache
				ip_addr_cache["occurences"] = {"as" : values, "in line" : keys }
				ip_addr_cache["normalized"] = values
				ip_addr_cache["discoveredName"] = ip_to_fqdn
				ip_addr_cache["type"] = "IPv4"
				uniq_ip_count += 1
				discovered_cache.append(dict(ip_addr_cache))
				print "IP2", ip_addr_cache
				print "DS2", discovered_cache
						
			elif is_token_validHostname(values):
				fqdn_a_records = []
				fqdn_cname_recs = []
				print "HOST VALID", values, keys
				fqdn_count += 1
				raw_cache[values].append(keys)
				#raw_cache[values] = keys
				try:
					a_recs = dns.resolver.query(values, "A")
					for recs in a_recs:
						fqdn_a_records.append(recs)
				except Exception:
					print "ERROR while getting A records"
					
				#normalized_cache[values] = keys
				normalized_cache[values].append(keys)
				dn_cache["type"] = "DN"
				dn_cache["occurences"] = {"as": values, "in line": keys }
				dn_cache["normalized"] = values
				dn_cache["recordsAType"] = fqdn_a_records

				try:
					c_recs = dns.resolver.query(values, "CNAME")
					for crecs in c_recs:
						fqdn_cname_recs.append(crecs)
				except Exception:
					print "ERROR while getting CNAME records"	
					
				#normalized_cache[values] = keys
				normalized_cache[values].append(keys)
				dn_cache["type"] = "DN"
				dn_cache["occurences"] = {"as": values, "in line": keys }
				dn_cache["normalized"] = values
				dn_cache["recordsCTypes"] = fqdn_cname_recs			
				
					
				
			
			
def	is_token_validIpv4(token):
	IP = token.split(".")
	if len(IP) != 4:
		return False
	for octet in IP:
		if not octet.isdigit():
			return False
		if not (0 <= int(octet) <= 255):
			return False
	return True
		

def is_token_validHostname(hostname):
	if len(hostname) > 255:
		return False
	if hostname.endswith("."):
		hostname = hostname[:-1]
	allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
	valid = all(allowed.match(x) for x in hostname.split("."))
	return valid	
				


    	
   
    
    	
if __name__ == '__main__':
	main()