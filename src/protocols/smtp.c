#include "protocols/smtp.h"

void parse_smtp(const u_char *packet, int verbose, int prof, int size) {
    switch (verbose) {
    case 1:
    case 2:
    case 3:
        PRINT_NEW_STATE(prof, verbose, BGRN "SMTP" GRN);

        if(verbose == 1) break ; // No need to print the rest of the header
        
        print_content(prof, verbose, size, packet);
    }
}