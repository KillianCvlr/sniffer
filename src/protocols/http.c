#include "protocols/http.h"

void parse_http(const u_char *packet, int verbose, int prof, int size) {
    switch (verbose) {
    case 1:
    case 2:
    case 3:        
        const char* packet_char  = (const char*)(packet); 
        if (strstr(packet_char, "GET") != NULL) {
            PRINT_NEW_STATE(prof, verbose, BGRN "HTTP" GRN " (GET)");
        } else if (strstr(packet_char, "HEAD") != NULL) {
            PRINT_NEW_STATE(prof, verbose, BGRN "HTTP" GRN " (HEAD)");
        } else if (strstr(packet_char, "POST") != NULL) {
            PRINT_NEW_STATE(prof, verbose, BGRN "HTTP" GRN " (POST)");
        } else if (strstr(packet_char, "PUT") != NULL) {
            PRINT_NEW_STATE(prof, verbose, BGRN "HTTP" GRN " (PUT)");
        } else if (strstr(packet_char, "DELETE") != NULL) {
            PRINT_NEW_STATE(prof, verbose, BGRN "HTTP" GRN " (DELETE)");
        } else if (strstr(packet_char, "CONNECT") != NULL) {
            PRINT_NEW_STATE(prof, verbose, BGRN "HTTP" GRN " (CONNECT)");
        } else if (strstr(packet_char, "OPTIONS") != NULL) {
            PRINT_NEW_STATE(prof, verbose, BGRN "HTTP" GRN " (OPTIONS)");
        } else if (strstr(packet_char, "TRACE") != NULL) {
            PRINT_NEW_STATE(prof, verbose, BGRN "HTTP" GRN " (TRACE)");
        } else if (strstr(packet_char, "PATCH") != NULL) {
            PRINT_NEW_STATE(prof, verbose, BGRN "HTTP" GRN " (PATCH)");
        } else if (strstr(packet_char, "OK") != NULL){
            PRINT_NEW_STATE(prof, verbose, BGRN "HTTP" GRN " (OK)");
        } else {
            PRINT_NEW_STATE(prof, verbose, BGRN "HTTP" GRN " ()");
        }

        if(verbose == 1) break ; // No need to print the rest of the header

        if(verbose == 2) break ; // No need to print the rest of the header

        print_content(prof, verbose, size, packet);

        break;
    }
}

