#ifndef ARGS_H
#define ARGS_H

#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/errno.h>
#include <unistd.h>
#include <pcap.h>
#include <sys/types.h>

extern char errbuf[PCAP_ERRBUF_SIZE];

typedef enum input_t {
    INPUT_UNKNOWN,
    INPUT_LIVE,
    INPUT_FILE,
    INPUT_DEVICE,
    INPUT_DEFAULT,
} input_t;

/**
 * @brief Structure stockant les différentes options données en entrée par
 * l'utilisateur
 *
 */

typedef struct options_t {
    input_t input;
    int verbose;
    uint64_t filter;
    char *bpf;
    char *inputFilename;
    FILE *inputFile;
    char *device;
    char *protocol;
    int nb_packet;
} options_t;

/**
 * @brief Affichage des otpions disponbles pour l'utilisateur
 *
 */

void printUsage(void);

/**
 * @brief Initialisation de la structure Options qui sauvegarde les 
 * arguments de l'utilisateur
 *
 */

void initOption(options_t *options);

/**
 * @brief Parsage des arguments
 *
 */

void parseArgs(int argc, char **argv, options_t *options);

/**
 * @brief Affichage de toutes les interfaces de l'ordinateur
 *
 */

void print_all_devs();

/**
 * @brief Vérification des arguments dans option
 *
 */

void checkOption(options_t *options);


/**
 * @brief Fermeture des fichiers dans Options
 *
 */

void closeOption(options_t *options);

#endif