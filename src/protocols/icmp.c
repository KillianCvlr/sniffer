#include "protocols/icmp.h"

void parse_icmp(const u_char *packet, int verbose, int prof) {
    struct icmp *icmp = (struct icmp *)(packet);
    switch (verbose) {
    case 1:
    case 2:
    case 3:
        switch (icmp->icmp_type) {
        case ICMP_ECHOREPLY:
            PRINT_NEW_STATE(prof, verbose, BCYN "ICMP" CYN " (Echo Reply)");
            break;
        case ICMP_DEST_UNREACH:
            PRINT_NEW_STATE(prof, verbose, BCYN "ICMP" CYN " (Destination Unreachable)");
            break;
        case ICMP_SOURCE_QUENCH:
            PRINT_NEW_STATE(prof, verbose, BCYN "ICMP" CYN " (Source Quench)");
            break;
        case ICMP_REDIRECT:
            PRINT_NEW_STATE(prof, verbose, BCYN "ICMP" CYN " (Redirect (change route))");
            break;
        case ICMP_ECHO:
            PRINT_NEW_STATE(prof, verbose, BCYN "ICMP" CYN " (Echo Request)");
            break;
        case ICMP_TIME_EXCEEDED:
            PRINT_NEW_STATE(prof, verbose, BCYN "ICMP" CYN " (Time Exceeded)");
            break;
        case ICMP_PARAMETERPROB:
            PRINT_NEW_STATE(prof, verbose, BCYN "ICMP" CYN " (Parameter Problem)");
            break;  
        default:
            PRINT_NEW_STATE(prof, verbose, BCYN "ICMP" CYN " (Unknown)");
            break;
        }

       if(verbose == 1) break ; // No need to print the rest of the header

        PRINT_TREE(prof, BCYN "Type : " CYN " %i\n", icmp->icmp_type);

       if(verbose == 2) break ; // No need to print the rest of the header

        PRINT_TREE(prof, BCYN "Code : " CYN " %i\n", icmp->icmp_code);
        //TAG for the user's lisibility
        
        PRINT_TREE(prof, BCYN "Checksum : " CYN "0x%x\n", ntohs(icmp->icmp_cksum));
        break;
    }
}