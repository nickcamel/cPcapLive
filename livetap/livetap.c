#include "inc/livetap.h"
#include <stdlib.h> // atoi


int main(int argc, char *argv[]) {
	
	// Parse input arguments
	int status = parse_input(argc, argv);
	if (status==1) {
		return 1;		
	}	
	
	// Find devices connected and pick one.
	if (find_and_pick_device()!=0) {
		return 1;
	}
	
	// Use device to scan network SSID's
	if (pkt_proc_type==BEACON_PROC_TYPE) {
		scan_and_pick_ssid();
	}
	
	// Setup PCAP session (PCAP-session handle, snaplen, filter etc..)
	if (setup_pcap_session()!=0){
		return 1;
	}
	
	
	//_______________________
	/* Start sniffing packets */
	//_______________________
	printf("\nWaiting for packets...\n\n");
	int i_pkt;
	
	// Switch packet processing function depending on type
	switch (pkt_proc_type) {
		case BEACON_PROC_TYPE:
			for (i_pkt=0; i_pkt<n_pkts_rcv; i_pkt++){
				// PCAP loop with 1 packet at a time.
				pcap_loop(hdl_pcap, 1, process_beacon_packet, (u_char *) "pcap C version");
			}
			break;
		
		case DUMP_PROC_TYPE:
			for (i_pkt=0; i_pkt<n_pkts_rcv; i_pkt++){
				// PCAP loop with 1 packet at a time.
				pcap_loop(hdl_pcap, 1, process_simple_packet, (u_char *) "pcap C version");
			}
			break;
		default:
			break;
	}

	
	//_______________________
	/* Close program */
	//_______________________
	close_session();
	
	return 0;
}



void process_simple_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer) {
	// Just a draft of string/hex dump. Idea is to modify and extract necessary bytes.
	
	int linktype = pcap_datalink(hdl_pcap);
	printf("\nLink Type: %d (goto: http://www.tcpdump.org/linktypes.html) \n", linktype);
	
	// Print out header info
	long int hdr_time = header->ts.tv_sec/1000000 + header->ts.tv_usec;
	unsigned int caplen = header->caplen;
	
	printf("Header.\n Timestamp: %ld\n Length: %d\n CapLen: %d\n", hdr_time, header->len, caplen);
	printf("Snaplen: %d\n", snaplen);
	
	// Print out Captured Buffer (in HEX and STRING)
	// Looping to caplen since caplen<=snaplen. I.e if caplen is less than snaplen, no need to print nulls.
	int ibyte;
	int ichar;
	
	if (HEXDUMP==1) {
		printf("\n\n________________\nHex dump:\n");
		
		for (ibyte = 0; ibyte<caplen; ibyte++) {
				printf("0x%02x ", buffer[ibyte]);
				if ((ibyte+1)%16==0) {
					printf("\n");
					
					for (ichar = ibyte-15; ichar<=ibyte; ichar++) {					
						printf("%4c ", (char) buffer[ichar]);
					}
					
					printf("\n");
				}
		}
	}
	
	if (STRINGDUMP==1) {
		printf("\n\n________________\nString dump:\n");		
		for (ichar = 0; ichar<caplen; ichar++) {
			
			if ((ichar+1)%32==0) {
				printf("\n");
			}
			
			u_char false_char = (u_char) 46;
			u_char true_char = (u_char) buffer[ichar];
			
			u_char t_char = 	(buffer[ichar]>=48 && buffer[ichar]<=57) || 
								(buffer[ichar]>=65 && buffer[ichar]<=90) || 
								(buffer[ichar]>=97 && buffer[ichar]<=122) ? true_char/*buffer[ichar]*/ : false_char;
			printf("%c", (char) t_char);
			
		}

		printf("\n\n");
	}
	
}


/* libpcap library function for processing packages. */
void process_beacon_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer) {
	
	// Designed for beacon extraction and timing evaluation.
	
	if (PRNT==1) {
		printf("Arg in %s\n", args);
	}
	// [dev_if]
	//printf("Header.\n Timestamp: %d\n Length: %d\n CapLen: %d\n",header->ts,header->len,header->caplen);
	//int hdr_size = header->len;
	//printf("Size of header : %d\n", hdr_size);
	//printf("Size of buffer %d\n", sizeof(buffer));
	//u_char * dbyte;
	//printf("%d\n", header->ts.tv_sec*1000 + header->ts.tv_usec/1000);
	
	
	/* Check if packet is beacon */
	if ( (int) buffer[0] == BEACON_IND ) {
		
		if (PRNT==1)
			printf("It's a beacon\n");
		
		/* Extract beacon timestamp from packet (8 bytes). */
		long int time_stamp = 0;		
		int i_stamp;
		
		for (i_stamp = 0; i_stamp<BEACON_TSTMP_N_BYTES; i_stamp++) {
			time_stamp += (long int) buffer[i_stamp+BEACON_TSTMP_BYTE_OFFS] << (i_stamp*N_BITS_PER_BYTE);
		}
		
		/* Check if it's a beacon from our own network. */	
		
		// Init ssid string
		int len_ssid = strlen(NETWORK_SSID);
		char ssid[len_ssid+1];
		
		// Parse buffer bytes belonging to SSID-field
		int is;
		for (is=0; is<len_ssid; is++) {			
			ssid[is] = (char) buffer[38+is];			
		}
		
		// Set last element to NULL (necessary?)
		ssid[len_ssid] = 0;	
		
		if (strcmp(ssid,NETWORK_SSID)!=0) {
			printf("ssid mismatch\n");
			return;			
		}
		
		
		/* Compute intervals of beacon, gtod and pcap-header timestamps. */
		if (is_first_time) {
			
			// We will only enter here once. Just to pick up the first timestamp.
			// Later on (in is_first_time==1) we will get a new timestamp and... well.. you can have alook yourself.
			
			// Get beacon time stamp (already parsed above)
			t_beacon[0] = time_stamp;
			
			// Get system gtod time stamp (still not sure this is the way to go... gettimeofday)
			gettimeofday(&tv0, NULL);			
			//clock_gettime(CLOCK_MONOTONIC, &tv0); // Alt. Timer. dont forget to change scale_xx when going back to gettimeofday()
			
			// Set the gtod time.
			t_gtod[0] = tv0.tv_sec*scale_sec + tv0.tv_usec/scale_usec;
			
			// Get the PCAP-header timestamp. (Not to be confused with Beacon Timestamp from buffer. This is from PCAP-header)
			t_header[0] = header->ts.tv_sec*scale_sec + header->ts.tv_usec/scale_usec;
			
			// Indicate that we never again want to enter this part of the code.
			is_first_time=false;
			
			if (PRNT==1)
			{
				printf("Beacon %ld\nGTOD %ld\nPCAP %ld\n\n",
					t_beacon[0],
					t_gtod[0],
					t_header[0]);
			}
			
			// Print header to files.			
			if (PRNTTOFILES==1)
			{
				fprintf(data_file, "%s\n", "dBeacon   dGTOD   dPcap   dBeacon-dGTOD  dBeacon-dPcap dGTOD-dPcap");
				fprintf(time_file, "Beacon\tGTOD\tPCAP\n");
			}
			
			// Make a header print.
			printf("dBeacon   dGTOD   dPcap   dBeacon-dGTOD  dBeacon-dPcap\n");
			
			
		}
		else if (!is_first_time) {
			
			/* Get the timestamps again (see above) */
			
			// Get current beacon time stamp
			t_beacon[1] = time_stamp;			
			
			// Get current gtod time stamp
			gettimeofday(&tv0, NULL);
			
			t_gtod[1] = tv0.tv_sec*scale_sec + tv0.tv_usec/scale_usec;
			//clock_gettime(CLOCK_MONOTONIC, &tv0);
						
			t_header[1] = header->ts.tv_sec*scale_sec + header->ts.tv_usec/scale_usec;

			
			/* Compute the interval between our two time stamps */
			
			// Interval for beacon time stamps
			long int t_beacon_delta = (t_beacon[1]-t_beacon[0])/scale_beacon;
			// ... and interval for elapsed gtod time stamps
			long int t_gtod_delta = (t_gtod[1]-t_gtod[0]);
			// ... and interval for header time stamps
			long int t_header_delta = t_header[1] - t_header[0];
			
			/* Present
				So what we really present here is the following.
				Beacon:	Interval between two beacon time stamps (timestamps found in packet-buffer). 
			 			This interval should be rather stable since it's generated by AP.
				System:	Interval between package arrivals. When a package arrives, 
						we save the time and the interval represents the time it takes until next package arrives.
				Header: Same as System, but we extract the timestamp of the packet header, 
						which is stamped with the current time when PCAP lib finds the packet and not when WE in this code get notified.
				
				At first we believed that the two intervals (Beacon and System) would be rather identical, BUT as it seems, 
				packages are NOT picked up by software the exact time (or rather with a fixed latency) that they arrive.
				We have some latency in both directions. So if we pick a packet a few ms too late once, it's be compensated for during the next packages.				
			*/
			if (PRNT==1) {
				
				printf("Beacon delta: %ld\n", t_beacon_delta);
				printf("System delta: %ld\n", t_gtod_delta);
				printf("Pcap delta: %ld\n", t_header_delta);				
				printf("Delta: %ld\n", t_beacon_delta-t_header_delta);
				
			} else {
				
				if (PRNTTOFILES==1) {
					fprintf(data_file, "%6.0ld %8.0ld %8.0ld %6.0ld %14.0ld %10.0ld\n", 
						t_beacon_delta, 
						t_gtod_delta, 
						t_header_delta,
						t_beacon_delta-t_gtod_delta,
						t_beacon_delta-t_header_delta,
						t_gtod_delta-t_header_delta);
					
					fprintf(time_file, "%ld\t%ld\t%ld\n",
						t_beacon[1],
						t_gtod[1],
						t_header[1]);
				}
				
				
				//printf("dBeacon   dGTOD   dPcap   dBeacon-dGTOD  dBeacon-dPcap\n");
				printf("%6.0ld %8.0ld %8.0ld %6.0ld %14.0ld\n\n", 
					t_beacon_delta, 
					t_gtod_delta, 
					t_header_delta,
					t_beacon_delta-t_gtod_delta,
					t_beacon_delta-t_header_delta);
				
				if (PRNT==1) {
					printf("Beacon %ld\nGTOD %ld\nPCAP %ld\n\n",
						t_beacon[1],
						t_gtod[1],
						t_header[1]);	
				}					
			}
			
			
			
			// Now, let latest timestamp be the starting point for next interval computation.
			t_beacon[0] = t_beacon[1];
			t_gtod[0] = t_gtod[1];
			t_header[0] = t_header[1];
			
		}
		else {
			// [dev_if] should not arrive here if code works :)
			printf("What the hell. count is : %d\n", is_first_time);
		}
		
	}
	else {
		// If filter is compiled to correctly filter out beacons we should not end up here.
		// If experimenting, to filter other packets, then of course.. we might end up here.
		printf("Not a beacon! Filter working? \n");
	}
	 

}



int find_and_pick_device() {
	//_______________________
	/* Picking the device */
	//_______________________
	
	// First get the list of available devices
	printf("Finding available devices ... \n\n");	
	
	// Yes, I know I don't really need the dev_nok parameter and can insert the pcap_findalldevs in if (?).
	int dev_nok = pcap_findalldevs(&all_devs_if, errbuf);

	if(dev_nok || sizeof(all_devs_if)==0)
	{
		printf("Error finding devices : %s" , errbuf);
		return 1;
	}	
	
	// Print out the device-information of devices found
	for (dev_if = all_devs_if; dev_if != NULL; dev_if = dev_if->next) {
		
		printf("Device [%d]: %s %s\n", n_dev, dev_if->name, dev_if->description);
		strcpy(dev_names[n_dev],dev_if->name);
		
		// Increment number of devices
		n_dev++;
	}
	
	// Check if any devices were found. 
	// Since "no devices found" will not result in any errors in pcap_findalldevs(), 
	//	but we dont want to continue if no device is found.
	if (n_dev==0) 
	{
		printf("No devices found!\nMake sure you have superuser privileges!\n\nSee ya\n\n\n");
		return 1;
	}
	
	// Let user pick a device
	int i_dev;
	printf("\nChoose a device [?]: ");
	scanf("%d", &i_dev);
	my_dev_name = dev_names[i_dev];
	printf("\nDevice %s chosen \n\n\n", my_dev_name);
	
	return 0;
	
}


void scan_and_pick_ssid() {
	printf("Scanning...\n");
	char scan_ssid[60] = "iwlist ";
	strcat(scan_ssid, my_dev_name);
	strcat(scan_ssid, " scan | grep SSID");
	//system(scan_ssid);
	
	
	// http://stackoverflow.com/questions/646241/c-run-a-system-command-and-get-output
	FILE *fp;
	
	char str_scan_ssid[100];
	//char str_comp[20] = "doesn't support"; Used this for comparing string from fgets, but the when failing to scan, fgets doesn't catch the terminal print...
	fp = popen(scan_ssid, "r");
	
	// When device does not support scanning, terminal will print
	// "Device does not support..." but str_scan_ssid will not catch it, hence comp to NULL
	if (fgets(str_scan_ssid, 100, fp) == NULL) {
		printf("Device cannot be used for scanning!!\n\n");		
	}
	else {		
		do {
			printf("%s", str_scan_ssid);
		} 
		while (fgets(str_scan_ssid, 100, fp) != NULL);
	}
	
	pclose(fp);
	
	printf("\nFilter by SSID.\n");
	printf("Type in an SSID, without quotes (case sensitive): ");

	scanf("%s", usr_ssid);
	NETWORK_SSID = usr_ssid;

	// Recompute snaplen
	snaplen += strlen(NETWORK_SSID);

	
	
}


int setup_pcap_session() {
	
	//____________________________________
	/* Initialize and setup PCAP session */
	//____________________________________
		 
	if (AUTOCHECK_NETMASK==1 && pcap_lookupnet(my_dev_name, &dev_ipn, &dev_netmask, errbuf) != -1) {
		// It's all good. And we've updated the netmask
	} else {
		// We're not dealing with a physical interface. Interface is however based on a physical device.
		// Oooor some other problems occured.		
		if (AUTOCHECK_NETMASK==1) {
			// Means there was actually an error
			printf("Err: %s\n", errbuf);
		}
		printf("\nDidn't get netmask. Default netmask set!\n");
		dev_ipn = 0;
		dev_netmask = DEF_NETMASK;	
	}
	
	printf("Netmask:\t");
	printf("%d.%d.%d.%d\n", dev_netmask&0xFF, dev_netmask>>8&0xFF, dev_netmask>>16&0xFF, dev_netmask>>24&0xFF);
	printf("ip&netmask:\t");
	printf("%d.%d.%d.%d\n", dev_ipn&0xFF, dev_ipn>>8&0xFF, dev_ipn>>16&0xFF, dev_ipn>>24&0xFF);
	
	
	/* Open pcap session */
	hdl_pcap = pcap_create(my_dev_name, errbuf);
	
	// If you want to use pcap_open_live. 
	// 1. remove all pcap_set_options below. 
	// 2. It's not possible to "set"_rfmon, since "set"ing options is not allwoed after handle creation.
	// pcap_open_live(my_dev_name,snaplen,flags,timeout,errbuf);

	if ((pcap_set_snaplen(hdl_pcap, snaplen)!=0) ||
	(pcap_set_timeout(hdl_pcap, timeout)!=0) || 
	(pcap_set_promisc(hdl_pcap, flags)!=0) ){			
		pcap_perror(hdl_pcap, "Option set error.\n");
		return 1;
	}
	printf("Snaplen:\t%d\nTimeout:\t%d\nPromisc:\t%d\n\n", snaplen, timeout, flags);
	
	
	/* Check for RFMON */
	// (I know my device (D-Link DWA-125) does not support rfmon, but we might be using some other device.)
	if (pcap_can_set_rfmon(hdl_pcap)==1) {
		
		printf("RFMON seems(!) possible...(Device might disassociate from AP if set!)\nSet RFMON? [1][0]");
		
		scanf("%d", &set_rfmon);
		
		if (set_rfmon==1) {
			
			// Try to set RFMON
			if (pcap_set_rfmon(hdl_pcap, 1)!=0) {
				pcap_perror(hdl_pcap, "Didn't work after all.\n");
				set_rfmon = 0;
			}
			
		}
		else if (set_rfmon==0) {			
			printf("RFMON not set\n");
			
		} else {
			
			printf("Valid options are 0 (no) and 1 (yes)\nRFMON not set\n");
			set_rfmon = 0;
		}
	}
	else {;
		
		printf("RFMON not available\n");
	}
	
	// Activate handler.
	// Handler must be activated after all above options have been set to handler.
	if (pcap_activate(hdl_pcap)!=0){
		
		pcap_perror(hdl_pcap, "Error activating PCAP handle.\n");
		return 1;
	}
	
	/* Compile and set the filter */
	if (pkt_proc_type==BEACON_PROC_TYPE) {
		filter_expr = "link[0]==0x80";
	}
	
	// Compile the filter for this pcap session/handle
	if (pcap_compile(hdl_pcap, &mybpf, filter_expr, optim, dev_netmask) != 0) {
		pcap_perror(hdl_pcap, "Could not compile filter.\n");
		return 1;
	}
	
	// Check if filter can be set
	if ( pcap_setfilter(hdl_pcap, &mybpf) != 0) {
		pcap_perror(hdl_pcap, "Could not set filter.\n");
		return 1;
	}
	
	
	
	
	if (PRNTTOFILES==1) 
	{
		// Open file handles to empty, writable (w) and updatable (+) files.
		data_file = fopen("data_file.txt", "w+");	
		time_file = fopen("time_file.txt", "w+");	
	}
	
	
	return 0;
	
}


void close_session() {
	
	// Close file handles
	if (PRNTTOFILES==1) {
		fclose(data_file);
		fclose(time_file);
	}
	
	// Restore RF_MON
	if (set_rfmon==1) {
		pcap_set_rfmon(hdl_pcap, 0);
		printf("Setting RFMON off!\n");
	}
	
	// Close the PCAP-session handle
	pcap_close(hdl_pcap);
	
}

int parse_input(int argc, char * argv[]) {
	
	int iar;
	for (iar=1; iar<argc; iar+=2) {
				
		if (*argv[iar]=='-') { /* pointer (*) to derefence the value */			
			switch (*(argv[iar]+1)) { /* +1 to get next character after dash (-). I.e pointer_value+1step. pointer (*) to derefernce the value.*/
				case 'n':
					// Number of packets to receive
					n_pkts_rcv = atoi((argv[iar+1])); /* +1 to get next pointer (i.e next input after option) */
					printf("Packet count: %d\n", n_pkts_rcv);
					break;
				case 't':
					// Type of processing
					printf("Packet Processing Type: ");
					if (strcmp("BEACON", argv[iar+1])==0) {
						printf("%s\n", argv[iar+1]);
						pkt_proc_type = BEACON_PROC_TYPE;
					} 
					else if (strcmp("DUMP", argv[iar+1])==0) {
						printf("%s\n", argv[iar+1]);
						pkt_proc_type = DUMP_PROC_TYPE;
					}
					else {
						print_err_help(argv[iar+1]);
						return 1;
					}
					break;
				case 's':
					// Set packet snapshot lenght
					snaplen = atoi( argv[iar+1] );
					printf("Snaplen: %d\n", snaplen);
					break;
				case 'h':
					print_help();
					return 1;
					break;
				default:
					print_err_help(argv[iar]);
					return 1;
					break;
			}
			
		}
		else {
			print_err_help(argv[iar]);
			return 1;
		}
		
		
	}
	
	return 0;
}

void print_help() {
		
	printf("Synopsis: \n\t livetap -tag [val] \n\n");
	printf("-n [count]\tCount. Number of packets to process. DEFAULT %d \n\n", DEFAULT_N_PACKETS);
	printf("-t [type]\tType. Processing types:\n\t\tBEACON\n\t\tDUMP\n\n");
	printf("-s [pkt_length]\tSnapshot length. Number of bytes to extract from packets. DEFAULT %d \n\n", snaplen);
	printf("-h \tHelp. Print this help message\n\n");
					
}

void print_err_help(char * argin) {
	printf("\n\nOption '%s' not valid\n\n", argin);
	print_help();
}
