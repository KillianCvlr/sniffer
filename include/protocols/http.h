#ifndef HTTP_PROTOCOL_H
#define HTTP_PROTOCOL_H

#include "headers.h"

/**
 * @file http_protocol.h
 * @brief HTTP Protocol Parsing Functions
 */


// Structure of the HTTP header
struct http_header {
    // HTTP request line
    char method[10];       // HTTP method (GET, POST, etc.)
    char uri[256];         // URI of the requested resource
    char version[10];      // HTTP version (HTTP/1.0, HTTP/1.1, etc.)

    // HTTP response line
    uint16_t status_code;  // HTTP status code (200 OK, 404 Not Found, etc.)
    char reason_phrase[256];// HTTP status reason phrase (OK, Not Found, etc.)

    // HTTP headers
    char headers[1024];     // HTTP headers (generic field for headers)

    // Message body (payload)
    char body[4096];        // Message body (generic field for body)
};

/**
 * @brief Parse the HTTP protocol header
 *
 * This function parses the HTTP protocol header and prints relevant information.
 *
 * @param packet The packet data
 * @param verbose Verbosity level
 * @param prof Profundity level
 * @param size Size of the HTTP packet
 */
void parse_http(const u_char *packet, int verbose, int prof, int size);

#endif /* HTTP_PROTOCOL_H */
