#ifndef BOOTP_BIS_H
#define BOOTP_BIS_H

#include "headers.h"
#include "bootp.h"

/**
 * @file bootp.h
 * @brief BOOTP Protocol Parsing Functions, including DHCP tags
 */

/**
 * @brief Parse the BOOTP protocol header
 *
 * This function parses the BOOTP protocol header and prints relevant information.
 *
 * @param packet The packet data
 * @param verbose Verbosity level
 * @param prof Profundity level
 */
void parse_bootp(const u_char *packet, int verbose, int prof);

/**
 * @brief Print DHCP argument information
 *
 * This function prints DHCP argument information.
 *
 * @param size Size of the DHCP option
 * @param i Index of the DHCP argument
 * @param bp_vend DHCP vendor-specific information
 */
void print_dhcp_arg(int size, int i, const u_int8_t *bp_vend);

/**
 * @brief Get DHCP tag from BOOTP header
 *
 * This function retrieves the DHCP tag from the BOOTP header.
 *
 * @param bootp_header Pointer to the BOOTP header
 * @return DHCP tag value
 */
int dhcp_tag(struct bootp *bootp_header);

#endif /* BOOTP_H */
