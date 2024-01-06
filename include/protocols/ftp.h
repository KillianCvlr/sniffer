#ifndef FTP_PROTOCOL_H
#define FTP_PROTOCOL_H

#include "headers.h"

/**
 * @file ftp_protocol.h
 * @brief FTP Protocol Parsing Functions
 */

// Structure of the FTP header
struct ftp_header {
    // FTP command
    char command[10];       // FTP command (USER, PASS, LIST, RETR, etc.)

    // FTP command argument
    char argument[256];     // FTP command argument

    // Additional FTP parameters
    char params[512];       // Additional FTP parameters

    // FTP response
    uint16_t code;          // FTP response code (e.g., 200, 404, etc.)
    char response[256];      // FTP response message
};


/**
 * @brief Parse the FTP protocol header
 *
 * This function parses the FTP protocol header and prints relevant information.
 *
 * @param packet The packet data
 * @param verbose Verbosity level
 * @param prof Profundity level
 * @param size Size of the FTP packet
 */
void parse_ftp(const u_char *packet, int verbose, int prof, int size);

#endif /* FTP_PROTOCOL_H */
