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

// Structure of the BOOTP header
struct bootp_header {
    uint8_t op;          // Operation type (1 for request, 2 for reply)
    uint8_t htype;       // Hardware type (1 for Ethernet)
    uint8_t hlen;        // Hardware address length (6 for Ethernet MAC address)
    uint8_t hops;        // Number of intermediate relays
    uint32_t xid;        // Exchange identifier
    uint16_t secs;       // Time since the start of the operation
    uint16_t flags;      // Special flags
    uint8_t ciaddr[4];   // Client IP address
    uint8_t yiaddr[4];   // Assigned IP address
    uint8_t siaddr[4];   // IP address of the boot server
    uint8_t giaddr[4];   // IP address of the relay agent
    uint8_t chaddr[16];  // Client hardware address (MAC)
    uint8_t sname[64];   // Boot server name
    uint8_t file[128];   // Boot file name
    uint32_t magic;      // Magic signature (0x63825363)
    uint8_t options[64]; // BOOTP/DHCP specific options
};

// Structure of the DHCP header
struct dhcp_header {
    uint8_t op;          // Operation type (1 for request, 2 for reply)
    uint8_t htype;       // Hardware type (1 for Ethernet)
    uint8_t hlen;        // Hardware address length (6 for Ethernet MAC address)
    uint8_t hops;        // Number of intermediate relays
    uint32_t xid;        // Exchange identifier
    uint16_t secs;       // Time since the start of the operation
    uint16_t flags;      // Special flags
    uint8_t ciaddr[4];   // Client IP address
    uint8_t yiaddr[4];   // Assigned IP address
    uint8_t siaddr[4];   // IP address of the boot server
    uint8_t giaddr[4];   // IP address of the relay agent
    uint8_t chaddr[16];  // Client hardware address (MAC)
    uint8_t sname[64];   // Boot server name
    uint8_t file[128];   // Boot file name
    uint32_t magic;      // Magic signature (0x63825363)
    uint8_t options[64]; // BOOTP/DHCP specific options
};

// Structure of the DNS header
struct dns_header {
    uint16_t id;          // Query identifier
    uint16_t flags;       // Flags (QR, Opcode, AA, TC, RD, RA, Z, RCODE)
    uint16_t qdcount;     // Number of questions in the Question section
    uint16_t ancount;     // Number of entries in the Answer section
    uint16_t nscount;     // Number of entries in the Authority section
    uint16_t arcount;
};

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

#endif
