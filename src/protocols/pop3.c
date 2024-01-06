#include "protocols/pop3.h"

void parse_pop3(const u_char *packet, int verbose, int prof, int size){
    switch (verbose) {
    case 1:
    case 2:
    case 3:
        PRINT_NEW_STATE(prof, verbose, BGRN "POP" GRN);

        if(verbose == 1) break ; // No need to print the rest of the header
        
        print_content(prof, verbose, size, packet);
    }
    return;
}   