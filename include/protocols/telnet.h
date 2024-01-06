#ifndef TELNET_PROTOCOL_H
#define TELNET_PROTOCOL_H

#include "headers.h"

/**
 * @file telnet_protocol.h
 * @brief Telnet Protocol Parsing Functions
 */

/**
 * @brief Parse the Telnet protocol header
 *
 * This function parses the Telnet protocol header and prints relevant information.
 *
 * @param packet The packet data
 * @param verbose Verbosity level
 * @param prof Profundity level
 * @param size Size of the Telnet packet
 */
void parse_telnet(const u_char *packet, int verbose, int prof, int size);

// TELNET FLAGS
#define TELNET_BINARY 0x00
#define TELNET_ECHO 0x01
#define TELNET_RECONNECTION 0x02
#define TELNET_SUPPRESS_GO_AHEAD 0x03
#define TELNET_APPROX_MESSAGE_SIZE_NEGOTIATION 0x04
#define TELNET_STATUS 0x05
#define TELNET_TIMING_MARK 0x06
#define TELNET_RCTE 0x07
#define TELNET_OLW 0x08
#define TELNET_OPS 0x09
#define TELNET_OCRD 0x0A
#define TELNET_OHTS 0x0B
#define TELNET_OHTD 0x0C
#define TELNET_OFD 0x0D
#define TELNET_OVT 0x0E
#define TELNET_OVTD 0x0F
#define TELNET_OLFD 0x10
#define TELNET_EXTEND_ASCII 0x11
#define TELNET_LOGOUT 0x12
#define TELNET_BYTE_MACRO 0x13
#define TELNET_DATA_ENTRY_TERMINAL 0x14
#define TELNET_SUPDUP 0x15
#define TELNET_SUPDUP_OUTPUT 0x16
#define TELNET_SEND_LOCATION 0x17
#define TELNET_TERMINAL_TYPE 0x18
#define TELNET_END_OF_RECORD 0x19
#define TELNET_TUID 0x1A
#define TELNET_OUTMRK 0x1B
#define TELNET_TTYLOC 0x1C
#define TELNET_3270_REGIME 0x1D
#define TELNET_X3_PAD 0x1E
#define TELNET_NAWS 0x1F
#define TELNET_TERMINAL_SPEED 0x20
#define TELNET_TOGGLE_FLOW_CONTROL 0x21
#define TELNET_LINEMODE 0x22
#define TELNET_X_DISPLAY_LOCATION 0x23
#define TELNET_OLD_ENVIRONMENT_VARIABLES 0x24
#define TELNET_AUTHENTICATION 0x25
#define TELNET_ENCRYPTION 0x26
#define TELNET_NEW_ENVIRONMENT_VARIABLES 0x27
#define TELNET_TN3270E 0x28
#define TELNET_XAUTH 0x29
#define TELNET_CHARSET 0x2A
#define TELNET_REMOTE_SERIAL_PORT 0x2B
#define TELNET_COM_PORT_CONTROL 0x2C
#define TELNET_SUPPRESS_LOCAL_ECHO 0x2D
#define TELNET_START_TLS 0x2E
#define TELNET_KERMIT 0x2F  
#define TELNET_SEND_URL 0x30
#define TELNET_FORWARD_X 0x31
#define TELNET_PRAGMA_LOGON 0x32    
#define TELNET_SSPI_LOGON 0x33
#define TELNET_PRAGMA_HEARTBEAT 0x34    
#define TELNET_EXOPL 0xFF



#define TELNET_IAC 0xFF
#define TELNET_DONT 0xFE
#define TELNET_DO 0xFD
#define TELNET_WONT 0xFC
#define TELNET_WILL 0xFB
#define TELNET_SB 0xFA
#define TELNET_GA 0xF9
#define TELNET_EL 0xF8
#define TELNET_EC 0xF7
#define TELNET_AYT 0xF6
#define TELNET_AO 0xF5
#define TELNET_IP 0xF4
#define TELNET_BREAK 0xF3
#define TELNET_DM 0xF2
#define TELNET_NOP 0xF1
#define TELNET_SE 0xF0

#endif  // TELNET_PROTOCOL_H