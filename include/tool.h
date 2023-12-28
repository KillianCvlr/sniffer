#ifndef H_TOOL
#define H_TOOL

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

/**
 * @brief Macro for displaying the parsing tree
 * (same protocol, same depth)
 */
#define DISPLAY_TREE(prof, args...) do { \
    display_tree(prof); \
    printf(args); \
} while(0)

/**
 * @brief Macro for displaying the parsing tree
 * (new protocol, new depth)
 *
 */
#define DISPLAY_NEW_STATE(prof, verbose, message) do { \
    display_new_state(prof, verbose); \
    printf(message); \
    if(verbose >= 2) printf("\n"); \
} while(0)

/**
 * @brief Function displaying the parsing tree for readability
 * Handles indentation and formatting
 *
 */
void display_tree(int prof);

/**
 * @brief Function displaying the parsing tree for readability
 * Handles transitioning to a new depth
 *
 */
void display_new_state(int prof, int verbose);

/**
 * @brief Function displaying a MAC address
 *
 */
void display_mac(uint8_t *mac);

/**
 * @brief Function displaying an IPv6 address
 *
 */
void display_ipv6(struct in6_addr);

#endif
