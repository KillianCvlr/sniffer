#include "protocols/udp.h"

void parse_udp(const u_char *packet, int verbose, int prof, int size) {
    struct udphdr *udp = (struct udphdr *)(packet);
    switch (verbose) {
    case 1:
    case 2:
    case 3:
        PRINT_NEW_STATE(prof, verbose, BCYN "UDP" CYN);

       if(verbose == 1) break ; // No need to print the ports

        PRINT_TREE(prof, BCYN "Port Source: " CYN " %d\n", ntohs(udp->uh_sport));
        PRINT_TREE(prof, BCYN "Port Destination: " CYN " %d\n", ntohs(udp->uh_dport));

       if(verbose == 2) break ; // No need to print the rest of the header

        PRINT_TREE(prof, BCYN "Length : " CYN " %i\n", ntohs(udp->uh_ulen));
        PRINT_TREE(prof, BCYN "Checksum : " CYN " 0x%x\n", ntohs(udp->uh_sum));
        break;
    }

    // Rest of the packet (protocol under UDP)
    printf(GRN);
    int size2 = size - sizeof(struct udphdr);
    switch (ntohs(udp->uh_sport)) {
    case 0x43:
    case 0x44:
        parse_bootp(packet + sizeof(struct udphdr), verbose, prof +1);
        break;
    case 0x35:
        parse_dns(packet + sizeof(struct udphdr), verbose, prof +1, size2);
        break;
    default:
        switch (ntohs(udp->uh_dport)) {
        case 0x43:
        case 0x44:
            parse_bootp(packet + sizeof(struct udphdr), verbose, prof +1);
            break;
        case 0x35:
            parse_dns(packet + sizeof(struct udphdr), verbose, prof +1, size2);
            break;
        default:
            PRINT_NEW_STATE(prof +1, verbose, BGRN "DATA" GRN " (%d - %d)", ntohs(udp->uh_sport), ntohs(udp->uh_dport));
            if (verbose == 3) print_content(prof, verbose, size2, packet + sizeof(struct udphdr));
            break;
        }
        break;
    }
}
