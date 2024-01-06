#include "protocols/ftp.h"

void parse_ftp(const u_char *packet, int verbose, int prof, int size) {
    switch (verbose) {
    case 1:
    case 2:
        PRINT_NEW_STATE(prof, verbose, BGRN "FTP" GRN);
        break;
    case 3:
        PRINT_NEW_STATE(prof, verbose, BGRN "FTP" GRN);
        print_content(prof, verbose, size, packet);
    }
}