#include "protocols/dns.h"

void parse_dns(const u_char *packet, int verbose, int prof, int size) {
    int rest = size - sizeof(struct dns_header);
    struct dns_header *dns_header = (struct dns_header *)packet;
    switch (verbose) {
    case 1:
    case 2:
    case 3:
        PRINT_NEW_STATE(prof, verbose, BGRN "DNS" GRN);
        if(verbose == 1){
            if (ntohs(dns_header->flags) & DNS_QR) printf(" QR");
            if (ntohs(dns_header->flags) & DNS_OPCODE) printf(" OPCODE");
            if (ntohs(dns_header->flags) & DNS_AA) printf(" AA");
            if (ntohs(dns_header->flags) & DNS_TC) printf(" TC");
            if (ntohs(dns_header->flags) & DNS_RD) printf(" RD");
            if (ntohs(dns_header->flags) & DNS_RA) printf(" RA");
            if (ntohs(dns_header->flags) & DNS_Z) printf(" Z");
            if (ntohs(dns_header->flags) & DNS_RCODE) printf(" RCODE");
        }

       if(verbose == 1) break ; // No need to print the rest of the header

        PRINT_TREE(prof, "Transaction ID : 0x%.2x\n", ntohs(dns_header->id));
        PRINT_TREE(prof, "Flags : 0x%.2x ", ntohs(dns_header->flags));
        //TAG for the user's lisibility
        if (ntohs(dns_header->flags) & DNS_QR) printf("QR ");
        if (ntohs(dns_header->flags) & DNS_OPCODE) printf("OPCODE ");
        if (ntohs(dns_header->flags) & DNS_AA) printf("AA ");
        if (ntohs(dns_header->flags) & DNS_TC) printf("TC ");
        if (ntohs(dns_header->flags) & DNS_RD) printf("RD ");
        if (ntohs(dns_header->flags) & DNS_RA) printf("RA ");
        if (ntohs(dns_header->flags) & DNS_Z) printf("Z ");
        if (ntohs(dns_header->flags) & DNS_RCODE) printf("RCODE ");
        printf("\n");

       if(verbose == 2) break ; // No need to print the rest of the header

        PRINT_TREE(prof, "Questions : %i\n", ntohs(dns_header->qdcount));
        PRINT_TREE(prof, "Answer RRs : %i\n", ntohs(dns_header->ancount));
        PRINT_TREE(prof, "Authority RRs : %i\n", ntohs(dns_header->nscount));
        PRINT_TREE(prof, "Additional RRs : %i\n", ntohs(dns_header->arcount));
        break;

        //TO DO : parse the rest of the packet ie questions, answers, authority, additional
        print_content(prof, verbose, rest, packet + sizeof(struct dns_header));
    }
}
