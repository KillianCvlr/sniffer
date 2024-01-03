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

#endif
