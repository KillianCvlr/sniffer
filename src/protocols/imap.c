#include "protocols/imap.h"

void parse_imap(const u_char *packet, int verbose, int prof, int size) {
    char buff[11];
    memset(buff, 0, 11);
    options_imap(packet, buff);
    switch (verbose) {
    case 1:
    case 2:
        PRINT_NEW_STATE(prof, verbose, BGRN "IMAP" GRN " %s", buff);
        break;
    case 3:     
        PRINT_NEW_STATE(prof, verbose, BGRN "IMAP" GRN );  
        print_content(prof, verbose, size, packet);
        break;
    }
}

void options_imap(const u_char *packet_arg, char * buff){
    const char * packet =(const char*)(packet_arg);
      if (strstr(packet, "OK LOGIN") != NULL) {
        strcpy(buff, "OK LOGIN");
    } else if (strstr(packet, "LOGIN") != NULL) {
        strcpy(buff, "LOGIN");
    } else if (strstr(packet, "SELECT") != NULL) {
        strcpy(buff, "SELECT");
    } else if (strstr(packet, "NO") != NULL) {
        strcpy(buff, "NO");
    } else if (strstr(packet, "BYE LOGOUT") != NULL) {
        strcpy(buff, "BYE LOGOUT");
    } else if (strstr(packet, "LOGOUT") != NULL) {
        strcpy(buff, "LOGOUT");
    } else if (strstr(packet, "NOOP") != NULL) {
        strcpy(buff, "NOOP");
    } else if (strstr(packet, "LIST") != NULL) {
        strcpy(buff, "LIST");
    } else if (strstr(packet, "CREATE") != NULL) {
        strcpy(buff, "CREATE");
    } else if (strstr(packet, "DELETE") != NULL) {
        strcpy(buff, "DELETE");
    } else if (strstr(packet, "RENAME") != NULL) {
        strcpy(buff, "RENAME");
    } else if (strstr(packet, "SEARCH ALL") != NULL) {
        strcpy(buff, "SEARCH ALL");
    } else if (strstr(packet, "OK") != NULL) {
        strcpy(buff, "OK");
    } else {
        strcpy(buff, "UNKNOWN");
    }
}