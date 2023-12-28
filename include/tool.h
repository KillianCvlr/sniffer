#ifndef H_TOOL
#define H_TOOL

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

#endif