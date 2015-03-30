#!/usr/bin/env python

import sys
import json
import re
from dns import resolver,reversename,exception
import dns.exception
from dns.resolver import Resolver, NXDOMAIN, NoNameservers, Timeout, NoAnswer
from twisted.names.dns import RRHeader
from collections import defaultdict
from dns.exception import DNSException

raw_cache = defaultdict(list)
normalized_cache = defaultdict(list)
error_cache = defaultdict(list)
ip_addr_cache = {}
dn_cache = {}
discovered_cache = []
total_error_cache = []
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
    
    try:               
     	file_to_process = open(filename, 'r')
    except:
    	print "Unable to open the file", filename, "Exiting - Try again" 
    	exit(2)
    
    j_file = 'json_readable_file'
    output_JD = open(j_file, 'w')
	       

	# Store line numbers and associated unprocessed lines of file
    lnum = 0
    raw_data = {}
    for line in file_to_process:
    	lnum += 1
    	raw_data[lnum] = line
    
    lines_processed = lnum

    	
    TKN_map = extract_token(raw_data)
    get_token_ready(TKN_map)
    line_token_count = (skipped_token_count + ipv4_count + fqdn_count)
    summary_cache = {"linesWithToken": line_token_count,\
    		"totalFQDN": fqdn_count,\
			"totalIPv4": ipv4_count, "totalErrors": error_count,\
			"tokenSkippedAlreadySeen": skipped_token_count,\
			"errors": total_error_cache,\
			"discoveredInformation": discovered_cache}
    json.dump(summary_cache, output_JD, indent=4, sort_keys=True)

def extract_token(raw_lines):
	token_map = {}
	for key, value in raw_lines.items():
		token1 = value.partition('#')[0]
		token = token1.strip()
		if (token != ''):
			token_map[key] = token
   	
   	return token_map
    	

def get_token_ready(ext_tokens):
	global skipped_token_count	
	global ipv4_count
	global uniq_ip_count
	global raw_cache
	global fqdn_count
	global error_count
	raw_cache['localhost'] = [0]
	normalized_cache['localhost'] = [0]
	for keys,values in ext_tokens.items():
		if((values == 'localhost.') or (values == 'localhost')):
			skipped_token_count += 1
			raw_cache['localhost'].append(keys)
			normalized_cache['localhost'].append(keys)
			continue
		elif (values in raw_cache.keys()):
			raw_cache[values].append(keys)
			skipped_token_count += 1
		else:
			if is_token_validIpv4(values):
				ipv4_count += 1
				raw_cache[values].append(keys)
				addr=reversename.from_address(values)
				try:
					ip_to_fqdn = str(resolver.query(addr,"PTR")[0])
					Ex_Flg = False
					normalized_cache[values].append(keys)
					ip_addr_cache["occurences"] = {"as" : values, "in line" : keys }
					ip_addr_cache["normalized"] = values
					ip_addr_cache["discoveredName"] = ip_to_fqdn
					ip_addr_cache["type"] = "IPv4"
					uniq_ip_count += 1
				except NoNameservers:
					Ex_Flg = True
					Ex_Msg = "ERROR while getting A records"
				except Timeout:
					Ex_Flg = True
					Ex_Msg = "Timeout during resolution of ", addr
				except DNSException:
					Ex_Flg = True
					Ex_Msg = "ERROR - Unhandled Exception"
				
				if(Ex_Flg):
					error_count += 1
					error_cache["type"] = "ERROR - seen while IP to FQDN check"
					error_cache["occurances"] = {"as": values,"in line": keys }
					error_cache["normalized"] = str(addr)
					error_cache["ErrMessage"] = str(Ex_Msg)
					total_error_cache.append(dict(error_cache))	
				else:
					discovered_cache.append(dict(ip_addr_cache))

						
			elif is_token_validHostname(values):
				fqdn_a_records = []
				fqdn_cname_recs = []
				fqdn_count += 1
				raw_cache[values].append(keys)
				try:
					a_recs = dns.resolver.query(values, "A")
					if len(a_recs) > 0:
						Ex_FlgA = False
						for recs in a_recs:
							fqdn_a_records.append(str(recs))
						normalized_cache[values].append(keys)
						dn_cache["type"] = "DN"
						dn_cache["occurances"] = {"as": values, "in line": keys }
						dn_cache["normalized"] = values
						dn_cache["recordsAType"] = fqdn_a_records
				except NXDOMAIN:
					Ex_FlgA = True
					Ex_MsgA = "Non-Existant Domain ", values
				except NoNameservers:
					Ex_FlgA = True
					Ex_MsgA = "ERROR while getting A records"
				except Timeout:
					Ex_FlgA = True
					Ex_MsgA = "Timeout during resolution of ", values
				except DNSException:
					Ex_FlgA = True
					Ex_MsgA = "ERROR - Unhandled Exception"
					
				if(Ex_FlgA):
					error_count += 1
					error_cache["type"] = "ERROR - seen while A & CName record fetch"
					error_cache["occurences"] = {"as": values,"in line": keys }
					error_cache["normalized"] = values
				else:
					fqdn_count += 1
					discovered_cache.append(dict(dn_cache))
					
				try:
					c_recs = dns.resolver.query(values, "CNAME")
					if len(c_recs) > 0:
						Ex_FlgC = False
						for crecs in c_recs:
							fqdn_cname_recs.append(str(crecs))
						normalized_cache[values].append(keys)
						dn_cache["type"] = "DN"
						dn_cache["occurences"] = {"as": values, "in line": keys }
						dn_cache["normalized"] = values
						dn_cache["recordsCType"] = fqdn_cname_recs
				except NXDOMAIN:
					Ex_FlgC = True
					Ex_MsgC = "Non-Existant Domain ", values
				except NoNameservers:
					Ex_FlgC = True
					Ex_MsgC = "ERROR while getting CName records"
				except Timeout:
					Ex_FlgC = True
					Ex_MsgC = "Timeout during resolution of ", values
				except DNSException:
					Ex_FlgC = True
					Ex_MsgC = "ERROR - Unhandled Exception"					
				if(Ex_FlgC):
					error_count += 1
					if(Ex_FlgA):
						error_cache["ErrMessage"] = {"For A records": str(Ex_MsgA),\
													"For CName records":\
													str(Ex_MsgC)}
					else:
						error_cache["ErrMessage"] = {"For CName records":\
													 str(Ex_MsgC)}								
					error_cache["type"] = "ERROR - seen while A & CName record fetch"
					error_cache["occurences"] = {"as": values,"in line": keys }
					error_cache["normalized"] = values
					total_error_cache.append(dict(error_cache))
				else:
					fqdn_count += 1
					discovered_cache.append(dict(dn_cache))
					if(Ex_FlgA):
						error_cache["ErrMessage"] = {"For A records": str(Ex_MsgA)}
						total_error_cache.append(dict(error_cache))
	
					
		
				
					
				
			
			
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