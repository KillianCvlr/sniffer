#ifndef H_TOOL
#define H_TOOL

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

/**
 * @brief Macro for printing the parsing tree
 * (same protocol, same depth)
 */
#define PRINT_TREE(prof, args...) do { \
    print_tree(prof); \
    printf(args); \
} while(0)

/**
 * @brief Macro for printing the parsing tree
 * (new protocol, new depth)
 *
 */
#define PRINT_NEW_STATE(prof, verbose, message) do { \
    print_new_state(prof, verbose); \
    printf(message); \
    if(verbose >= 2) printf("\n"); \
} while(0)

/**
 * @brief Function printing the parsing tree for readability
 * Handles indentation and formatting
 *
 */
void print_tree(int prof);

/**
 * @brief Function printing the parsing tree for readability
 * Handles transitioning to a new depth
 *
 */
void print_new_state(int prof, int verbose);

/**
 * @brief Function printing a MAC address
 *
 */
void print_mac(uint8_t *mac);

/**
 * @brief Function printing an IPv6 address
 *
 */
void print_ipv6(struct in6_addr);

/**
 * @brief Function printing an IPv4 address
 *
 */
void print_ip(struct in_addr);

/**
* @brief Function printing an ip address from a uint8_t array
*/
void print_ip_from_uint8(uint8_t *ip);

#endif
