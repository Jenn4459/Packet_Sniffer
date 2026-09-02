# Architecture
This project is a low-level packet capture, parsing, and real-time 
signature-based intrusion detection program using the libpcap library. 
The program is written in 4 phases

### Phase 1 - Packet Capture
1. SETUP
	- Call `pcap_create(const char *source, char *errbuff)` to open a handle 
	  for a live capture
		- source is the network interface name, ex. `eth0` or `en0` 
		- error buffer stores error message if the call fails
		- this function returns a pointer to a pcap_t struct
	- Activate the handle with `pcap_activate(pcap_t *p)` to tell pcap what 
	  device we are sniffing on
		- if the function fails, close the handle with `pcap_close()`
2. FINDING THE INTERFACE
	- Call `pcap_findalldevs()` to get a list of available network interfaces
		- Use `pcap_freealldevs()`
		- `pcap_lookupdev()` returns the first device on the list that is not a 
		   loopback network interface 
3. OPEN THE DEVICE
	- Call `pcap_datalink()` to determine the type of link-layer the device 
	  provides and to use that type when processing the packet contents
		- *NOTE: * can call `pcap_t *pcap_open_live(char *device, int snaplen, 
		  int promisc, int to_ms,char *ebuf)` INSTEAD of `pcap_create()` and 
		  `pcap_activate()` to create a sniffing session
4. (OPTIONAL) CREATING A RULE SET
	- `pcap_compile()` to compile filter expression to a pseudo-machine-language
	   code program
	- `pcap_freecode` to free a filter program
	- `pcap_setfilter` to get a filter for a pcap_t
	- use a char pointer to set the rule
		- ex. `char *rule = "tcp and port 443";` 
5. PACKET SNIFFING LOOP
	- Call `pcap_loop()` to sniff multiple packets
		- Requires packet_handler callback function to properly handle packets
	- ***Always make sure to properly handle any errors that occur from the use 
	  of any of these functions - DONT keep running a program if the function 
	  failed**
	- ***DONT FORGET to use*** `pcap_close()` ***when finished sniffing***

### Phase 2 - Paceket Parsing
- parsing consists of using a callback function (`packet_handler()`) inside 
  of `pcap_loop()` to parse the packets

`packet_handler()` should do the following:
1. Declare the containers:
		const struct sniff_ethernet 
		const struct sniff_ip *ip; 
		const struct sniff_tcp *tcp; 
		const char *payload; 

		u_int size_ip;
		u_int size_tcp;
2.  Typecast:
		ethernet = (struct sniff_ethernet*)(packet);
		ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
		size_ip = IP_HL(ip)*4;
		if (size_ip < 20) {
			printf("   * Invalid IP header length: %u bytes\n", size_ip);
			return;
		}
		tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
		size_tcp = TH_OFF(tcp)*4;
		if (size_tcp < 20) {
			printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
			return;
		}
		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	DONT FORGET TO ERROR CHECK
- Once we declare the containers and do our typecasting, we can pass along the 
  packet info to our phase 3 functions.


### Phase 3 - Threat Detector
1. Checking flags
	- TCP flags defined in sniff_tcp and can be checked against the incoming 
	  TCP header
	- Payload flags combinations to look for:
		- Xmas attack: FIN, PSH, URG
		- Null scan: check for lack of any flags at all
		- SYN-FIN combo
2. Malicious payload signatures
	- NOTE: I am aware that most packets are encrypted nowadays, but I decided to write this part of the program for learning / showcasing purposes
	- use `memmem()` to search the payload for malicious signatures
	- malicious signatures to look for:
		- SQL Injection (1)
			- `"' OR '1'='1'"`
		- XSS (2)
			- `"<script>alert(1)</script>"`
			- `<img src=x onerror=alert(1)>`
			- `<img src=x onerror=alert1>`
			- https://medium.com/@Udeshna/most-common-xss-payloads-10699faabaad
		- Remote Code Execution (3)
			- `"/bin/sh"` or `"/bin/bash"`
			- `"$(cat /etc/passwd)"`
			- check for backtics
			- `"; "`
		- Buffer Overflow
			- `"\x90\x90\x90\x90"` or `"\x41\x41\x41\x41"`
	- Hardcode the signatures into the signatures functions and use memmem() to find if there are any instances of them inside the payloads
3. Suspicious packets rate (*rates for this were determined by GoogleAI)
	- RST attack
		- Check for massive spike in RST flags
		- (maybe check when calculating the pps, what percentage of packages have RST flag on)
	- FIN flood
		- check if only the FIN flag is on (maybe also check if the previous packet also only had the FIN flag on?)
	- use pcap_stats() to track the pps 
		- in pcap_loop, keep a count to keep track of packages
		- call pcap_stats(), subtract from count, and divide by the time difference (since last check) to get pps, check if pps is acceptable time
		- determine acceptable pps range and compare with current pps

- for flag and payload signature checks, the function returned 1 of 4 numbers
  as follows:
	- 0: no issues
	- 1: XMAS for flags, SQL injection for signatures
	- 2: NULL for flags, XSS for signatures
	- 3: SYN-FIN for flags, RCE for signatures
- rst and syn flood returned true is threat was found and false otherwise

### Phase 4 - Output Summary
This is the most straight forward step. The results of the threat checkers, are
passed into this function, then the function outputs based on whether the 
threats were CRITICAL or MEDIUM
	- CRITICAL threats are ones in which every threat checking function returned
	  either a true or nonzero value
	- MEDIUM threats are ones in which one or more (but not all) threats were
	  found
	- If no threats were found, nothing was output
Output was appended to a file: sniff_results.txt


# Testing

### Phase 1
- finding_interface() and setup() testing was conducted in unit_test.c
- filter_set() was tested in terminal:
    - Commands:
        - sudo ./sniffer
        - sudo ./sniffer 'icmp'

### Phase 2
- callback function (packet_handler) tested in unit_test.c
	- testing file was generated from the command `sudo tcpdump -i eth0 -w 
	  test_traffic.pcap tcp and ip` and passed into the packet_handle function
	- results were printed to the terminal which included ethernet, ip, tcp, 
	  and payload sizes and payload data
		- 	`printf("\n================ PACKET TEST ================\n");
			printf("Ethernet Header Size : %d bytes (Fixed)\n", SIZE_ETHERNET);
			printf("IP Header Size       : %u bytes\n", size_ip);
			printf("TCP Header Size      : %u bytes\n", size_tcp);
			printf("Calculated Payload   : %u bytes\n", payload_len);
			printf("Payload Data (Text)  : ");
			for (u_int i = 0; i < payload_len; i++) {
				if (payload[i] >= 32 && payload[i] <= 126) {
					printf("%c", payload[i]);
				} else {
					printf(".");
				}
			}
			printf("\n=============================================\n");`

### Phase 3
- threat functions were testing via unit_test.c - each function was tested with
  an assert to determin
	- check_flags was passed a sniff_tcp struct that had no alarming flag 
	  combinations on, a struct with XMAS attacks on, a struct with no flags
	  on, and a struct with the SYN-FIN flags on
	- signatures_test was given a test payload, test payloads included:
		- a good payload: "GET /index.php?user=john_doe HTTP/1.1\r\nHost: localhost\r\n\r\n"
		- a SQL injection: "' OR '1'='1"
		- a XSS injection: "<script>alert(1)</script>"
		- an RCE attack: "`"
	- check_rates were given a specific number of 'clean' packages 
		- for check_rst_rates, the number of packets was checked for every 60
		  packets. if the number of rst packets reached 10% of the total package
		  amount, 'true' was returned
		  - 54 clean packages and 6 rst packages packages were sent into the 
		   function
		  	- packets 1-59 asserted as false since we hadn't reached the 
			  threshold yet, and the 60th packet asserted as true since we got 
			  to 0.1 on the threat rate
		- testing was exactly the same for check_syn_rates except it was tested
		  at a larger threshold (1000) and a larger rate of 60%
		- NOTE: rates were determined by GoogleAI
	
	- each test used assert() to ensure that the correct value was returned
	  from each function

### Phase 4
- the output function was passed in the results of the threat checker functions,
  therefore, to check it, I only passed in specific parameters and visually
  checked that the output matched the input

### Final testing
As threats were unlikely to occur naturally on my own local network, I tested 
the program by including certain commands into the terminal to elicit a positive
attack by the program

These commands included:
	- echo "GET /?user=' OR '1'='1" | nc -w 1 127.0.0.1 80
	- echo "/bin/bash $(cat /etc/passwd)" | nc -w 1 127.0.0.1 80
	- nmap -p 1-100 127.0.0.1

**Final Notes**: GoogleAI did help with certain aspects of this project including
               determining the rates and buffer size for check_rst_rates and 
			   check_syn_rates, and for calculating the payload_len as well as 
			   general clarifications regards topics or info that I was unsure 
			   of