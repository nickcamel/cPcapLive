#ifndef HEADERLIVETAP
#define HEADERLIVETAP

#include "defines.h"
#include "setup.h"

#include <pcap.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

int find_and_pick_device();
void scan_and_pick_ssid();
int setup_pcap_session();
void close_session();
int parse_input(int, char * argv[]);
void print_help();
void print_err_help(char * argv);

/* 	Declare packet-processing function.
	Body of function is defined by developer, however, pcap-lib defines the inputs.
*/
void process_beacon_packet(u_char *, const struct pcap_pkthdr *, const u_char * usr_defined_str);
void process_simple_packet(u_char *, const struct pcap_pkthdr *, const u_char * usr_defined_str);


//_____________
/*  SETUP */
//_____________
int flags = 1;								// Promiscouos mode. capture all packets  
int timeout = 0;							// In [ms]. 0 = wait for ever for packet to arrive

// Filter parameters 
// NOTE: If we dont compile a filter, snaplen will have on effect. (I think).
// However, we need a filter here to filter out beacons and avoid "Not a beacon"-alerts
int optim = 0;								//? "Optimize resulting code from pcap_compile" ?
bpf_u_int32 dev_netmask;					// Netmask
bpf_u_int32 dev_ipn;						// Ip number. Ipaddr&Netmask

//__________________________
/*  DECLARATION AND INIT */
//__________________________

// Init timestamp variables for use in PCAP subfunction.
// We need some 'global' variable for time computation
// Beacon, System and Pcp-Header time stamps
// Beacon: Time stamp sent by AP (value-base in no correlation with system time)
// System: Time stamp picked up in this program as soon as we detect packet capture.
// Header: Time stamp put in header as soon as pcap-lib captures a packet.
// Investigation shows that System and Header values use same base (timeval!)
long int t_beacon[2], t_gtod[2], t_header[2];

// How many packets to try and capture. "Try" since a packet is not always caught when e.g using pcap-dispatch.
int n_pkts_rcv = DEFAULT_N_PACKETS;

// Struct used in calls to 'gettimeofday()'
struct timeval tv0; 

// Counter for skipping first time_stamp. (We need at least to stamps to compute the interval right?)
bool is_first_time = true;

// Experimented with different time scales to represent the intervals
// Values also depend on type of clock. E.g the timespec gives sec and nsec, timeval gives sec and usec. Aaaanyway...
int scale_sec = 1000000; // ==>us
int scale_usec = 1; // ==> us
int scale_beacon = 1; // beacon in us hence ==> us

// Users is asked to set rfmon if rfmon seems possible
int set_rfmon = 0; 

// File handles (in case we want to print results to files)
FILE * data_file;
FILE * time_file;



// NOTE: If RFMON not set, the this must be set to the SSID which
// your device is connected to.
char * NETWORK_SSID;				// Choose what WLAN-SSID to listen to.
char usr_ssid[32];					// Inputted SSID by user. Max 32 chars
// char usr_ssid;					// This will not work. Must pre-allocate

//_________________________________________________________
/* Handles and other variables necessary for computation */
//_________________________________________________________

pcap_t *hdl_pcap;					/* PCAP-Session handle */
pcap_if_t *all_devs_if, *dev_if;	/* Device interfaces */
struct bpf_program mybpf;			/* Filter program */ // Should be "struct bpf_program * mybpf"  ??;
char errbuf[PCAP_ERRBUF_SIZE];		/* Error string */
int n_dev = 0;						/* Init number of devices */	
char dev_names[10][100]; 			/* Init device names' char. Max 10 devices here. Yes, hardcoded. What? */
char * my_dev_name;					/* My device name. Name of chosen device */





#endif