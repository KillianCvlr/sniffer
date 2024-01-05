#ifndef H_HEADERS
#define H_HEADERS

#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <net/if_arp.h>

#define IP_HEADER_LENGTH(ip)    (((ip)->ip_vhl) & 0x0f)
#define IP_VERSION(ip)          (((ip)->ip_vhl) >> 4)

/*	Used Headers ********************************************************/

#include "bootp.h"

// Structure of the DNS header
struct dns_header {
    uint16_t id;          // Query identifier
    uint16_t flags;       // Flags (QR, Opcode, AA, TC, RD, RA, Z, RCODE)
    uint16_t qdcount;     // Number of questions in the Question section
    uint16_t ancount;     // Number of entries in the Answer section
    uint16_t nscount;     // Number of entries in the Authority section
    uint16_t arcount;
};

//DNS FLAGS
#define DNS_QR 0x8000
#define DNS_OPCODE 0x7800
#define DNS_AA 0x0400
#define DNS_TC 0x0200
#define DNS_RD 0x0100
#define DNS_RA 0x0080
#define DNS_Z 0x0070
#define DNS_RCODE 0x000F


// Structure of the HTTP header
struct http_header {
    // HTTP request line
    char method[10];       // HTTP method (GET, POST, etc.)
    char uri[256];         // URI of the requested resource
    char version[10];      // HTTP version (HTTP/1.0, HTTP/1.1, etc.)

    // HTTP response line
    uint16_t status_code;  // HTTP status code (200 OK, 404 Not Found, etc.)
    char reason_phrase[256];// HTTP status reason phrase (OK, Not Found, etc.)

    // HTTP headers
    char headers[1024];     // HTTP headers (generic field for headers)

    // Message body (payload)
    char body[4096];        // Message body (generic field for body)
};

// Structure of the FTP header
struct ftp_header {
    // FTP command
    char command[10];       // FTP command (USER, PASS, LIST, RETR, etc.)

    // FTP command argument
    char argument[256];     // FTP command argument

    // Additional FTP parameters
    char params[512];       // Additional FTP parameters

    // FTP response
    uint16_t code;          // FTP response code (e.g., 200, 404, etc.)
    char response[256];      // FTP response message
};

// Structure of the SMTP header
struct smtp_header {
    // SMTP command
    char command[10];       // SMTP command (EHLO, HELO, MAIL, RCPT, etc.)

    // SMTP command argument
    char argument[256];     // SMTP command argument

    // Additional SMTP parameters
    char params[512];       // Additional SMTP parameters

    // SMTP response
    uint16_t code;          // SMTP response code (e.g., 220, 500, etc.)
    char response[256];      // SMTP response message
};

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


#endif
