#ifndef H_TOOL
#define H_TOOL

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

/**
 * @brief Fonction affichant l'arbre du parsage pour la lisibilité
 * S'occupe de faire les tab et la mise en page
 *
 */

void print_tree(int prof);

/**
 * @brief Fonction affichant l'arbre du parsage pour la lisibilité
 * S'occupe de faire le passage à une nouvelle profondeur
 *
 */

void print_new_state(int prof);

/**
 * @brief Fonction affichant une adresse MAC
 *
 */
void print_mac(uint8_t *mac);

/**
 * @brief  Fonction affichant l'adresse IPv6
 *
 */

void print_ipv6(struct in6_addr);

#endif