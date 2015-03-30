<h2>Python Project-1</h2>
This is a readme file for Python Project-1

<h4>Abstract</h4>
This project creates a simple DNS Utility. 
The features of this Utility are
	- accepts a raw input file
	- cleans up the lines and extracts tokens
	- normalizes the tokens to IP addresses, PQDNs, FQDNs
	- Reports Discovered Information and Errors in a readable format
 
<h4>Important source files</h4>
	project_1.py
		- Version 1 : 
			- Functionality works and Output can be seen (example provided below)
			- Missing/TODO:
			  - some more errors conditions will be added in subsequent versions
			  - lookup for PQDN
			  - better formatting
		- Version 2 :
			  - Fixed an issue with Discovering Info
		- Version 3 :
			  - added all Error Conditions
			  - Discovered A & CName records also
			  - cleanup of source code
			  - better formatting
		- Version 4 :
			  - Fixed Version 3 issues 
			  	- removed empty strings, fixed Cname records and added Error check code
			  	  IP address validation
		- Version 5 :
			  - Error Messages for A & CName records had overlapping info, so formatted
			    and reduced that
	
<h4>Issues</h4>


<h4>Execution & Usage</h4>
	Program verified with Python Version - 2.7.5 on a Mac (OS X - 10.9.5)
	Also added the source/input file used below - sample_input.txt
	

<h5>Examples</h5>
	json_readable_file
	sample_input.txt


<br />

