#ifndef DNS_PROTOCOL_H
#define DNS_PROTOCOL_H

#include "headers.h"

/**
 * @file dns_protocol.h
 * @brief DNS Protocol Parsing Functions
 */

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

/**
 * @brief Parse the DNS protocol header
 *
 * This function parses the DNS protocol header and prints relevant information.
 *
 * @param packet The packet data
 * @param verbose Verbosity level
 * @param prof Profundity level
 * @param size Size of the DNS packet
 */
void parse_dns(const u_char *packet, int verbose, int prof, int size);

#endif /* DNS_PROTOCOL_H */
