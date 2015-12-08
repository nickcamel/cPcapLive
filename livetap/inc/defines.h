#ifndef HEADERDEFINES
#define HEADERDEFINES

//_____________
/*  DEFINES */
//_____________
#define PRNT 0						// Printing out dev_if info to terminal
#define PRNTTOFILES 0				// Print results to files
#define HEXDUMP 1					// Print HEX dump
#define STRINGDUMP 1				// Print String dump. Only 0-9, a-z and A-Z
#define DEFAULT_N_PACKETS 150		// Number of packets to receive if no user input.
#define N_BITS_PER_BYTE 8			// Define number of bits per byte. 
#define BEACON_IND 128				// Beacon indicator byte-value.
#define BEACON_MIN_N_BYTES 40		// Beacon minimum number of bytes (in order to process timestamps)
#define BEACON_TSTMP_N_BYTES 8		// Beacon Timestamp number of bytes
#define BEACON_TSTMP_BYTE_OFFS 24	// Beacon Timestamp byte offset
#define AUTOCHECK_NETMASK 0			// Tryies to look up netmask from device.
#define DEF_NETMASK 0xFFFFFFFF

typedef enum {
	DUMP_PROC_TYPE,
	BEACON_PROC_TYPE
} PKT_PROC_TYPE;

#endif