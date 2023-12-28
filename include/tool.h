#ifndef H_TOOL
#define H_TOOL

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>


/**
 * @brief Macro pour l'affichage de l'arbre du parsage
 * (même protocole donc même profondeur)
 */
#define PRINT_TREE(prof, args...) do { \
    print_tree(prof); \
    printf(args); \
} while(0)

/**
 * @brief Macro pour l'affichage de l'arbre du parsage
 * (nouveau protocole donc nouvelle profondeur)
 *
 */
#define PRINT_NEW_STATE(prof, args...) do { \
    print_new_state(prof); \
    printf(args); \
} while(0)

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