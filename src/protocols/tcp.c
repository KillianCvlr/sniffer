#include "protocols/tcp.h"

void parse_tcp(const u_char *packet, int verbose, int prof, int size){
    struct tcphdr *tcp = (struct tcphdr *)(packet);
    switch (verbose) {
    case 1:
    case 2:
    case 3:
        PRINT_NEW_STATE(prof, verbose, BCYN "TCP " CYN);
            if(verbose == 1){
            if (tcp->th_flags & TH_FIN) printf("FIN ");
            if (tcp->th_flags & TH_SYN) printf("SYN ");
            if (tcp->th_flags & TH_RST) printf("RST ");
            if (tcp->th_flags & TH_PUSH) printf("PUSH ");
            if (tcp->th_flags & TH_ACK) printf("ACK ");
            if (tcp->th_flags & TH_URG) printf("URG ");
        }

       if(verbose == 1) break ; // No need to print the ports

        PRINT_TREE(prof, BCYN "Port Source: " CYN " %d\n", ntohs(tcp->th_sport));
        PRINT_TREE(prof, BCYN "Port Destination: " CYN " %d\n", ntohs(tcp->th_dport));
        PRINT_TREE(prof, BCYN "Flags : " CYN " 0x%.2x ", tcp->th_flags);

        //TAGS for the user's lisibility
        if (tcp->th_flags & TH_FIN) printf("FIN ");
        if (tcp->th_flags & TH_SYN) printf("SYN ");
        if (tcp->th_flags & TH_RST) printf("RST ");
        if (tcp->th_flags & TH_PUSH) printf("PUSH ");
        if (tcp->th_flags & TH_ACK) printf("ACK ");
        if (tcp->th_flags & TH_URG) printf("URG ");
        printf("\n");

       if(verbose == 2) break ; // No need to print the rest of the header

        PRINT_TREE(prof, BCYN "Sequence number : " CYN " 0x%.2x (%u)\n", tcp->th_seq,
               ntohl(tcp->th_seq));
        PRINT_TREE(prof, BCYN "Acknowledgement number : " CYN " 0x%.2x (%u)\n", tcp->th_ack,
               ntohl(tcp->th_ack));
        PRINT_TREE(prof, BCYN "Data offset : " CYN " %i (%i bytes)\n", tcp->th_off, tcp->th_off * 4);
        

        PRINT_TREE(prof, BCYN "Window : " CYN " %u\n", ntohs(tcp->th_win));
        PRINT_TREE(prof, BCYN "Checksum : " CYN " 0x%x\n", ntohs(tcp->th_sum));
        PRINT_TREE(prof, BCYN "Urgent Pointer : " CYN " %.2x\n", tcp->th_urp);
        break;
    }
    // check if only used in order to flag the TCP protocol 
    //or used in an other protocol (flag PSH present)
    printf(GRN);
    size -= 4*tcp->th_off;
    if(size) {
        // Rest of the packet (protocol under TCP)
        switch (ntohs(tcp->th_sport)) {
        case 0x50:
            parse_http(packet + 4*tcp->th_off, verbose, prof +1, size );
            break;
        case 0x15:  
            parse_ftp(packet + 4*tcp->th_off, verbose, prof +1,  size);
            break;
        case 0x19:
        case 0x1D1:
        case 0x24B:
            parse_smtp(packet + 4*tcp->th_off, verbose, prof +1,  size);
            break;
        case 0x17:
            parse_telnet(packet + 4*tcp->th_off, verbose, prof +1, size);
            break;
        case 0x43:
        case 0x44:
            parse_bootp(packet + 4*tcp->th_off, verbose, prof +1);
            break;
        case 0x35:
            parse_dns(packet + 4*tcp->th_off, verbose, prof +1, size);
            break;
        case 0x8F:
            parse_imap(packet + 4*tcp->th_off, verbose, prof +1, size);
            break;
        case 0x6E:
            parse_pop3(packet + 4*tcp->th_off, verbose, prof +1, size);
            break;
        default:
            switch (ntohs(tcp->th_dport)) {
            case 0x50:
                parse_http(packet + 4*tcp->th_off, verbose, prof +1, size );
                break;
            case 0x15:  
                parse_ftp(packet + 4*tcp->th_off, verbose, prof +1,  size);
                break;
            case 0x19:
            case 0x1D1:
            case 0x24B:
                parse_smtp(packet + 4*tcp->th_off, verbose, prof +1,  size);
                break;
            case 0x17:
                parse_telnet(packet + 4*tcp->th_off, verbose, prof +1, size);
                break;
            case 0x43:
            case 0x44:
                parse_bootp(packet + 4*tcp->th_off, verbose, prof +1);
                break;
            case 0x35:
                parse_dns(packet + 4*tcp->th_off, verbose, prof +1, size);
                break;
            case 0x8F:
                parse_imap(packet + 4*tcp->th_off, verbose, prof +1, size);
                break;
            case 0x6E:
                parse_pop3(packet + 4*tcp->th_off, verbose, prof +1, size);
                break;
            default :
                PRINT_NEW_STATE(prof +1, verbose, "DATA");
                print_content(prof +1, verbose, size, packet + 4*tcp->th_off);
            }
        }
    }
}