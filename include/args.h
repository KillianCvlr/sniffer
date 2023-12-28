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

typedef enum {
    INPUT_UNKNOWN,
    INPUT_LIVE,
    INPUT_FILE,
    INPUT_DEVICE,
    INPUT_DEFAULT,
} input_type;

/**
 * @brief Displays available options for the user
 *
 */
void showUsage(void);

/**
 * @brief Initializes the Options structure to store user input
 *
 */
void initializeOptions(options_t *options);

/**
 * @brief Parses the arguments
 *
 */
void parseArguments(int argc, char **argv, options_t *options);

/**
 * @brief Displays all computer interfaces
 *
 */
void displayAllDevices();

/**
 * @brief Verifies the arguments in the options
 *
 */
void validateOptions(options_t *options);

/**
 * @brief Closes files in the Options structure
 *
 */
void closeOptions(options_t *options);

#endif
