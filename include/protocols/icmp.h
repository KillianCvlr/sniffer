#ifndef ICMP_PROTOCOL_H
#define ICMP_PROTOCOL_H

#include "headers.h"

/**
 * @file icmp_protocol.h
 * @brief ICMP Protocol Parsing Functions
 */

/**
 * @brief Parse the ICMP and ICMPv6 protocol header
 *
 * This function parses the ICMP protocol header and prints relevant information.
 *
 * @param packet The packet data
 * @param verbose Verbosity level
 * @param prof Profundity level
 */
void parse_icmp(const u_char *packet, int verbose, int prof);


//ICMPv6 FLAGS
#define ICMP6_DESTINATION_UNREACHABLE 1
#define ICMP6_PACKET_TOO_BIG 2
#define ICMP6_TIME_EXCEEDED 3
#define ICMP6_PARAMETER_PROBLEM 4
#define ICMP6_ECHO_REQUEST 128
#define ICMP6_ECHO_REPLY 129
#define ICMP6_ROUTER_SOLICITATION 133
#define ICMP6_ROUTER_ADVERTISEMENT 134
#define ICMP6_NEIGHBOR_SOLICITATION 135
#define ICMP6_NEIGHBOR_ADVERTISEMENT 136
#define ICMP6_REDIRECT_MESSAGE 137
// To be continued...

// Structure of the ICMPv6 header
struct icmpv6_header {
    uint8_t type;          // ICMPv6 type
    uint8_t code;          // ICMPv6 code
    uint16_t checksum;     // ICMPv6 checksum
};

/**
 * @brief Parse the ICMP protocol header
 *
 * This function parses the ICMP protocol header and prints relevant information.
 *
 * @param packet The packet data
 * @param verbose Verbosity level
 * @param prof Profundity level
 */
void parse_icmpv6(const u_char *packet, int verbose, int prof);

#endif /* ICMP_PROTOCOL_H */
