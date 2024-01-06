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


void parse_icmpv6(const u_char *packet, int verbose, int prof) {
    struct icmpv6_header *icmp6 = (struct icmpv6_header *)(packet);
    switch (verbose) {
    case 1:
    case 2:
    case 3:
        switch (icmp6->type) {
        case ICMP6_DESTINATION_UNREACHABLE:
            PRINT_NEW_STATE(prof, verbose, BCYN "ICMPv6" CYN " (Destination Unreachable)");
            break;
        case ICMP6_PACKET_TOO_BIG:
            PRINT_NEW_STATE(prof, verbose, BCYN "ICMPv6" CYN " (Packet Too Big)");
            break;
        case ICMP6_TIME_EXCEEDED:
            PRINT_NEW_STATE(prof, verbose, BCYN "ICMPv6" CYN " (Time Exceeded)");
            break;
        case ICMP6_PARAMETER_PROBLEM:
            PRINT_NEW_STATE(prof, verbose, BCYN "ICMPv6" CYN " (Parameter Problem)");
            break;
        case ICMP6_ECHO_REQUEST:
            PRINT_NEW_STATE(prof, verbose, BCYN "ICMPv6" CYN " (Echo Request)");
            break;
        case ICMP6_ECHO_REPLY:
            PRINT_NEW_STATE(prof, verbose, BCYN "ICMPv6" CYN " (Echo Reply)");
            break;
        case ICMP6_ROUTER_SOLICITATION:
            PRINT_NEW_STATE(prof, verbose, BCYN "ICMPv6" CYN " (Router Solicitation)");
            break;
        case ICMP6_ROUTER_ADVERTISEMENT:
            PRINT_NEW_STATE(prof, verbose, BCYN "ICMPv6" CYN " (Router Advertisement)");
            break;
        case ICMP6_NEIGHBOR_SOLICITATION:
            PRINT_NEW_STATE(prof, verbose, BCYN "ICMPv6" CYN " (Neighbor Solicitation)");
            break;
        case ICMP6_NEIGHBOR_ADVERTISEMENT:
            PRINT_NEW_STATE(prof, verbose, BCYN "ICMPv6" CYN " (Neighbor Advertisement)");
            break;
        case ICMP6_REDIRECT_MESSAGE:
            PRINT_NEW_STATE(prof, verbose, BCYN "ICMPv6" CYN " (Redirect)");
            break;
        default:
            PRINT_NEW_STATE(prof, verbose, BCYN "ICMPv6" CYN " (Unknown)");
            break;
        }

         if(verbose == 1) break ; // No need to print the rest of the header

        PRINT_TREE(prof, BCYN "Type : " CYN " %i\n", icmp6->type);
            
        if(verbose == 2) break ; // No need to print the rest of the header

        PRINT_TREE(prof, BCYN "Code : " CYN " %i\n", icmp6->code);
    }
}