#include "application_layer.h"

void parse_icmp(const u_char *packet, int verbose, int prof) {
    struct icmp *icmp = (struct icmp *)(packet);
    switch (verbose) {
    case 1:
    case 2:
    case 3:
        PRINT_NEW_STATE(prof, verbose, BGRN "ICMP" GRN);

       if(verbose == 1) break ; // No need to print the rest of the header

        PRINT_TREE(prof, BGRN "Type : " GRN " %i\n", icmp->icmp_type);

       if(verbose == 2) break ; // No need to print the rest of the header

        PRINT_TREE(prof, BGRN "Code : " GRN " %i", icmp->icmp_code);
        //TAG for the user's lisibility
        switch (icmp->icmp_code) {
        case ICMP_ECHOREPLY:
            printf(" (Echo Reply)\n");
            break;
        case ICMP_DEST_UNREACH:
            printf(" (Destination Unreachable)\n");
            break;
        case ICMP_SOURCE_QUENCH:
            printf(" (Source Quench)\n");
            break;
        case ICMP_REDIRECT:
            printf(" (Redirect (change route))\n");
            break;
        case ICMP_ECHO:
            printf(" (Echo Request)\n");
            break;
        case ICMP_TIME_EXCEEDED:
            printf(" (Time Exceeded)\n");
            break;
        case ICMP_PARAMETERPROB:
            printf(" (Parameter Problem)\n");
            break;  

        default:
            printf(" (Unknown)\n");
            break;
        }
        PRINT_TREE(prof, BGRN "Checksum : " GRN "0x%x\n", ntohs(icmp->icmp_cksum));
        break;
    }
}

void parse_bootp(const u_char *packet, int verbose, int prof) {
    struct bootp *bootp_header = (struct bootp *)(packet);

    switch (verbose) {
    case 1:
    case 2:
    case 3:
        switch (dhcp_tag(bootp_header))
        {
        case DHCPDISCOVER:
            PRINT_NEW_STATE(prof, verbose, BGRN "DHCP" GRN " (DISCOVER)");
            break;

        case DHCPOFFER:
            PRINT_NEW_STATE(prof, verbose, BGRN "DHCP" GRN " (OFFER)");
            break;

        case DHCPREQUEST:
            PRINT_NEW_STATE(prof, verbose, BGRN "DHCP" GRN " (REQUEST)");
            break;
        
        case DHCPDECLINE:
            PRINT_NEW_STATE(prof, verbose, BGRN "DHCP" GRN " (DECLINE)");
            break;

        case DHCPACK:
            PRINT_NEW_STATE(prof, verbose, BGRN "DHCP" GRN " (ACK)");
            break;

        case DHCPNAK:
            PRINT_NEW_STATE(prof, verbose, BGRN "DHCP" GRN " (NAK)");
            break;

        case DHCPRELEASE:
            PRINT_NEW_STATE(prof, verbose, BGRN "DHCP" GRN " (RELEASE)");
            break;

        case DHCPINFORM:
            PRINT_NEW_STATE(prof, verbose, BGRN "DHCP" GRN " (INFORM)");
            break;

        default:
            PRINT_NEW_STATE(prof, verbose, BGRN "BOOTP" GRN "");
            break;
        } 

       if(verbose == 1) break ; // No need to print the rest of the header

        PRINT_TREE(prof, BGRN "Operation : " GRN " %i", bootp_header->bp_op);
        //TAG for the user's lisibility
        switch (bootp_header->bp_op) {
        case BOOTREQUEST:
            printf(" (Request)\n");
            break;
        case BOOTREPLY:
            printf(" (Reply)\n");
            break;
        default:
            printf(" (Unknown)\n");
            break;
        }

         if(verbose == 2) break ; // No need to print the rest of the header    

        PRINT_TREE(prof, BGRN "Hardware type : " GRN " %i\n", bootp_header->bp_htype);
        PRINT_TREE(prof, BGRN "Hardware address length : " GRN " %i\n", bootp_header->bp_hlen);
        PRINT_TREE(prof, BGRN "Hops : " GRN " %i\n", bootp_header->bp_hops);
        PRINT_TREE(prof, BGRN "Transaction ID : " GRN " 0x%.2x\n", bootp_header->bp_xid);
        PRINT_TREE(prof, BGRN "Seconds : " GRN " %i\n", bootp_header->bp_secs);
        PRINT_TREE(prof, BGRN "Flags : " GRN " 0x%.2x\n", bootp_header->bp_flags);
        PRINT_TREE(prof, BGRN "Client IP : " GRN " ");

        print_ip(bootp_header->bp_ciaddr); printf("\n");
        PRINT_TREE(prof, BGRN "Your IP : " GRN " ");
        print_ip(bootp_header->bp_yiaddr); printf("\n");
        PRINT_TREE(prof, BGRN "Server IP : " GRN " ");
        print_ip(bootp_header->bp_siaddr); printf("\n");
        PRINT_TREE(prof, BGRN "Gateway IP : " GRN " ");
        print_ip(bootp_header->bp_giaddr); printf("\n");
        PRINT_TREE(prof, BGRN "Client hardware address : " GRN " ");
        print_mac(bootp_header->bp_chaddr); printf("\n");

        PRINT_TREE(prof, BGRN "Server host name : " GRN " %s\n", bootp_header->bp_sname);
        PRINT_TREE(prof, BGRN "Boot file name : " GRN " %s\n", bootp_header->bp_file);
        PRINT_TREE(prof, BGRN "Magic cookie : " GRN " 0x%.2x\n", bootp_header->bp_vend);

        //Option parsing
        int i = 4 ;
        while (i < 64) {
            switch (bootp_header->bp_vend[i]) {
            case TAG_PAD:
                i++;
                break;
            case TAG_SUBNET_MASK:
                PRINT_TREE(prof, "Subnet mask : ");
                print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                printf("\n");
                i += bootp_header->bp_vend[i + 1] + 2;
                break;
            case TAG_TIME_OFFSET:
                PRINT_TREE(prof, "Time offset : %i\n", bootp_header->bp_vend[i + 2]);
                i += bootp_header->bp_vend[i + 1] + 2;
                break;
            case TAG_GATEWAY:
                PRINT_TREE(prof, "Gateway : ");
                print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                printf("\n");
                i += bootp_header->bp_vend[i + 1] + 2;
                break;
            case TAG_TIME_SERVER:
                PRINT_TREE(prof, "Time server : ");
                print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                printf("\n");
                i += bootp_header->bp_vend[i + 1] + 2;
                break;
            case TAG_NAME_SERVER:
                PRINT_TREE(prof, "Name server : ");
                print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                printf("\n");
                i += bootp_header->bp_vend[i + 1] + 2;
                break;
            case TAG_DOMAIN_SERVER:
                PRINT_TREE(prof, "Domain server : ");
                print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                printf("\n");
                i += bootp_header->bp_vend[i + 1] + 2;
                break;
            case TAG_LOG_SERVER:
                PRINT_TREE(prof, "Log server : ");
                print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                printf("\n");
                i += bootp_header->bp_vend[i + 1] + 2;
                break;
            case TAG_COOKIE_SERVER:
                PRINT_TREE(prof, "Cookie server : ");
                print_ip_from_uint8(bootp_header);
                printf("\n");
                i += bootp_header->bp_vend[i + 1] + 2;
            
            case TAG_LPR_SERVER:
                PRINT_TREE(prof, "LPR server : ");
                print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                printf("\n");
                i += bootp_header->bp_vend[i + 1] + 2;
            
            case TAG_IMPRESS_SERVER:
                PRINT_TREE(prof, "Impress server : ");
                print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                printf("\n");
                i += bootp_header->bp_vend[i + 1] + 2;

            case TAG_RLP_SERVER:
                PRINT_TREE(prof, "RLP server : ");
                print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                printf("\n");
                i += bootp_header->bp_vend[i + 1] + 2;

            case TAG_HOSTNAME:
                PRINT_TREE(prof, "Hostname : %s\n", bootp_header->bp_vend + i + 2);
                i += bootp_header->bp_vend[i + 1] + 2;
                break;
            
            case TAG_BOOTSIZE:
                PRINT_TREE(prof, "Bootsize : %i\n", bootp_header->bp_vend[i + 2]);
                i += bootp_header->bp_vend[i + 1] + 2;
                break;
            
            case  TAG_REQUESTED_IP:
                PRINT_TREE(prof, "Requested IP : ");
                print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                printf("\n");
                i += bootp_header->bp_vend[i + 1] + 2;
                break;
            
            case TAG_IP_LEASE:
                PRINT_TREE(prof, "Lease time : %i\n", bootp_header->bp_vend[i + 2]);
                i += bootp_header->bp_vend[i + 1] + 2;
                break;
            
            case TAG_OPT_OVERLOAD:
                PRINT_TREE(prof, "Overload : %i\n", bootp_header->bp_vend[i + 2]);
                i += bootp_header->bp_vend[i + 1] + 2;
                break;

            case TAG_DHCP_MESSAGE:
                PRINT_TREE(prof, "DHCP message : %i", bootp_header->bp_vend[i + 2]);
                //TAG for the user's lisibility
                switch (bootp_header->bp_vend[i + 2]) {
                case DHCPDISCOVER:
                    printf(" (Discover)\n");
                    break;
                case DHCPOFFER:
                    printf(" (Offer)\n");
                    break;
                case DHCPREQUEST:
                    printf(" (Request)\n");
                    break;
                case DHCPDECLINE:   
                    printf(" (Decline)\n");
                    break;
                case DHCPACK:
                    printf(" (ACK)\n");
                    break;
                case DHCPNAK:
                    printf(" (NAK)\n");
                    break;
                case DHCPRELEASE:
                    printf(" (Release)\n");
                    break;
                case DHCPINFORM:
                    printf(" (Inform)\n");
                    break;
                default:
                    printf(" (Unknown)\n");
                    break;
                }
                
                i += bootp_header->bp_vend[i + 1] + 2;
                break;

            case TAG_SERVER_ID:
                PRINT_TREE(prof, "DHCP server : ");
                print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                printf("\n");
                i += bootp_header->bp_vend[i + 1] + 2;
                break;
            
            case TAG_PARM_REQUEST:
                PRINT_TREE(prof, "Parameter request : ");
                for (int j = 0; j < bootp_header->bp_vend[i + 1]; j++) {
                    printf("%i ", bootp_header->bp_vend[i + 2 + j]);
                }
                printf("\n");
                i += bootp_header->bp_vend[i + 1] + 2;
                break;
            
            case TAG_MESSAGE:
                PRINT_TREE(prof, "Message : %s\n", bootp_header->bp_vend + i + 2);
                i += bootp_header->bp_vend[i + 1] + 2;
                break;

            case TAG_MAX_MSG_SIZE:
                PRINT_TREE(prof, "Max size : %i\n", bootp_header->bp_vend[i + 2]);
                i += bootp_header->bp_vend[i + 1] + 2;
                break;
            
            case TAG_RENEWAL_TIME:
                PRINT_TREE(prof, "Renewal time : %i\n", bootp_header->bp_vend[i + 2]);
                i += bootp_header->bp_vend[i + 1] + 2;
                break;
            
            case TAG_REBIND_TIME:
                PRINT_TREE(prof, "Rebind time : %i\n", bootp_header->bp_vend[i + 2]);
                i += bootp_header->bp_vend[i + 1] + 2;
                break;

            case TAG_VENDOR_CLASS:
                PRINT_TREE(prof, "Vendor class : %s\n", bootp_header->bp_vend + i + 2);
                i += bootp_header->bp_vend[i + 1] + 2;
                break;
            
            case TAG_CLIENT_ID:
                PRINT_TREE(prof, "Client ID : %i\n", bootp_header->bp_vend[i + 2]);
                i += bootp_header->bp_vend[i + 1] + 2;
                break;

            case TAG_END:
                i = 64;
                break;
            
            default:
                i += bootp_header->bp_vend[i + 1] + 2;
                break;
            }
        }
        break;
    }  
}

int dhcp_tag(struct bootp* bootp_header){
    int i = 4;
    while (i < 64) {
        switch (bootp_header->bp_vend[i]) {
        case TAG_DHCP_MESSAGE:
            return bootp_header->bp_vend[i + 2];
            break;
        default:
            i += bootp_header->bp_vend[i + 1] + 2;
            break;
        }
    }
    return 0;
}

void parse_dns(const u_char *packet, int verbose, int prof) {
    struct dns_header *dns_header = (struct dns_header *)(packet);
    switch (verbose) {
    case 1:
    case 2:
    case 3:
        PRINT_NEW_STATE(prof, verbose, "DNS");

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
    }
}

void parse_http(const u_char *packet, int verbose, int prof, int size) {
    switch (verbose) {
    case 1:
    case 2:
    case 3:            
        if (strstr(packet, "GET") != NULL) {
            PRINT_NEW_STATE(prof, verbose, BGRN "HTTP" GRN " (GET)");
        } else if (strstr(packet, "HEAD") != NULL) {
            PRINT_NEW_STATE(prof, verbose, BGRN "HTTP" GRN " (HEAD)");
        } else if (strstr(packet, "POST") != NULL) {
            PRINT_NEW_STATE(prof, verbose, BGRN "HTTP" GRN " (POST)");
        } else if (strstr(packet, "PUT") != NULL) {
            PRINT_NEW_STATE(prof, verbose, BGRN "HTTP" GRN " (PUT)");
        } else if (strstr(packet, "DELETE") != NULL) {
            PRINT_NEW_STATE(prof, verbose, BGRN "HTTP" GRN " (DELETE)");
        } else if (strstr(packet, "CONNECT") != NULL) {
            PRINT_NEW_STATE(prof, verbose, BGRN "HTTP" GRN " (CONNECT)");
        } else if (strstr(packet, "OPTIONS") != NULL) {
            PRINT_NEW_STATE(prof, verbose, BGRN "HTTP" GRN " (OPTIONS)");
        } else if (strstr(packet, "TRACE") != NULL) {
            PRINT_NEW_STATE(prof, verbose, BGRN "HTTP" GRN " (TRACE)");
        } else if (strstr(packet, "PATCH") != NULL) {
            PRINT_NEW_STATE(prof, verbose, BGRN "HTTP" GRN " (PATCH)");
        } else if (strstr(packet, "OK") != NULL){
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

void parse_ftp(const u_char *packet, int verbose, int prof, int size) {
    switch (verbose) {
    case 1:
    case 2:
    case 3:
        PRINT_NEW_STATE(prof, verbose, BGRN "FTP" GRN);

        if(verbose == 1) break ; // No need to print the rest of the header

        print_content(prof, verbose, size, packet);
    }

}

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

void parse_imap(const u_char *packet, int verbose, int prof, int size) {
    switch (verbose) {
    case 1:
    case 2:
    case 3:
        PRINT_NEW_STATE(prof, verbose, BGRN "IMAP" GRN);

        if(verbose == 1) break ; // No need to print the rest of the header
        
        print_content(prof, verbose, size, packet);
    }
}
void parse_telnet(const u_char *packet, int verbose, int prof, int size) {
    switch (verbose) {
    case 1:
    case 2:
    case 3:
        PRINT_NEW_STATE(prof, verbose, BGRN "TELNET" GRN);

        if(verbose == 1) break ; // No need to print the rest of the header
        
        if(size){
            if (packet[0] == TELNET_IAC) {
                PRINT_TREE(prof, "IAC \n");
                switch (packet[1]) {
                case TELNET_WILL:
                    PRINT_TREE(prof, "WILL \n");
                    break;
                case TELNET_WONT:
                    PRINT_TREE(prof, "WONT \n");
                    break;
                case TELNET_DO:
                    PRINT_TREE(prof, "DO \n");
                    break;
                case TELNET_DONT:
                    PRINT_TREE(prof, "DONT \n");
                    break;
                case TELNET_SB:
                    PRINT_TREE(prof, "SB \n");
                    break;
                case TELNET_GA:
                    PRINT_TREE(prof, "GA \n");
                    break;
                case TELNET_EL:
                    PRINT_TREE(prof, "EL \n");
                    break;
                case TELNET_EC:
                    PRINT_TREE(prof, "EC \n");
                    break;
                case TELNET_AYT:
                    PRINT_TREE(prof, "AYT \n");
                    break;
                case TELNET_AO:
                    PRINT_TREE(prof, "AO \n");
                    break;
                case TELNET_IP:
                    PRINT_TREE(prof, "IP \n");
                    break;
                case TELNET_BREAK:
                    PRINT_TREE(prof, "BREAK \n");
                    break;
                case TELNET_DM:
                    PRINT_TREE(prof, "DM \n");
                    break;
                case TELNET_NOP:
                    PRINT_TREE(prof, "NOP \n");
                    break;
                case TELNET_SE:
                    PRINT_TREE(prof, "SE \n");
                    break;
                default:
                    PRINT_TREE(prof, "UNKNOWN \n");
                    break;
                }
                switch (packet[2]) {
                case TELNET_BINARY:
                    PRINT_TREE(prof, "BINARY \n");
                    break;
                case TELNET_ECHO:
                    PRINT_TREE(prof, "ECHO \n");
                    break;
                case TELNET_RECONNECTION:
                    PRINT_TREE(prof, "RECONNECTION \n");
                    break;
                case TELNET_SUPPRESS_GO_AHEAD:
                    PRINT_TREE(prof, "SUPPRESS GO AHEAD \n");
                    break;
                case TELNET_APPROX_MESSAGE_SIZE_NEGOTIATION:
                    PRINT_TREE(prof, "APPROX MESSAGE SIZE NEGOTIATION \n");
                    break;
                case TELNET_STATUS:
                    PRINT_TREE(prof, "STATUS \n");
                    break;
                case TELNET_TIMING_MARK:
                    PRINT_TREE(prof, "TIMING MARK \n");
                    break;
                case TELNET_RCTE:
                    PRINT_TREE(prof, "REMOTE CONTROLLED TRANSMISSION AND ECHOING \n");
                    break;
                case TELNET_OLW:
                    PRINT_TREE(prof, "OUTPUT LINE WIDTH \n");
                    break;
                case TELNET_OPS:
                    PRINT_TREE(prof, "OUTPUT PAGE SIZE \n");
                    break;
                case TELNET_OCRD:
                    PRINT_TREE(prof, "OUTPUT CARRIAGE RETURN DISPOSITION \n");
                    break;
                case TELNET_OHTS:
                    PRINT_TREE(prof, "OUTPUT HORIZONTAL TAB STOPS \n");
                    break;
                case TELNET_OHTD:
                    PRINT_TREE(prof, "OUTPUT HORIZONTAL TAB DISPOSITION \n");
                    break;
                case TELNET_OFD:
                    PRINT_TREE(prof, "OUTPUT FORMFEED DISPOSITION \n");
                    break;
                case TELNET_OVT:
                    PRINT_TREE(prof, "OUTPUT VERTICAL TABSTOPS \n");
                    break;
                case TELNET_OVTD:
                    PRINT_TREE(prof, "OUTPUT VERTICAL TAB DISPOSITION \n");
                    break;
                case TELNET_OLFD:
                    PRINT_TREE(prof, "OUTPUT LINEFEED DISPOSITION \n");
                    break;
                case TELNET_EXTEND_ASCII:
                    PRINT_TREE(prof, "EXTENDED ASCII \n");
                    break;
                case TELNET_LOGOUT:
                    PRINT_TREE(prof, "LOGOUT \n");
                    break;
                case TELNET_BYTE_MACRO:
                    PRINT_TREE(prof, "BYTE MACRO \n");
                    break;
                case TELNET_DATA_ENTRY_TERMINAL:
                    PRINT_TREE(prof, "DATA ENTRY TERMINAL \n");
                    break;  
                case TELNET_SUPDUP:
                    PRINT_TREE(prof, "SUPDUP \n");
                    break;
                case TELNET_SUPDUP_OUTPUT:
                    PRINT_TREE(prof, "SUPDUP OUTPUT \n");
                    break;
                case TELNET_SEND_LOCATION:
                    PRINT_TREE(prof, "SEND LOCATION \n");
                    break;
                case TELNET_TERMINAL_TYPE:
                    PRINT_TREE(prof, "TERMINAL TYPE \n");
                    break;
                case TELNET_END_OF_RECORD:
                    PRINT_TREE(prof, "END OF RECORD \n");
                    break;
                case TELNET_TUID:
                    PRINT_TREE(prof, "TUID \n");
                    break;
                case TELNET_OUTMRK:
                    PRINT_TREE(prof, "OUTPUT MARKING \n");
                    break;
                case TELNET_TTYLOC:
                    PRINT_TREE(prof, "TTYLOC \n");
                    break;
                case TELNET_3270_REGIME:
                    PRINT_TREE(prof, "3270 REGIME \n");
                    break;
                case TELNET_X3_PAD:
                    PRINT_TREE(prof, "X3 PAD \n");
                    break;
                case TELNET_NAWS:
                    PRINT_TREE(prof, "NAWS \n");
                    break;
                case TELNET_TERMINAL_SPEED:
                    PRINT_TREE(prof, "TERMINAL SPEED \n");
                    break;
                case TELNET_TOGGLE_FLOW_CONTROL:
                    PRINT_TREE(prof, "TOGGLE FLOW CONTROL \n");
                    break;
                case TELNET_LINEMODE:
                    PRINT_TREE(prof, "LINEMODE \n");
                    break;
                case TELNET_X_DISPLAY_LOCATION:
                    PRINT_TREE(prof, "X DISPLAY LOCATION \n");
                    break;
                case TELNET_OLD_ENVIRONMENT_VARIABLES:
                    PRINT_TREE(prof, "OLD ENVIRONMENT VARIABLES \n");
                    break;
                case TELNET_AUTHENTICATION:
                    PRINT_TREE(prof, "AUTHENTICATION \n");
                    break;
                case TELNET_ENCRYPTION:
                    PRINT_TREE(prof, "ENCRYPTION \n");
                    break;
                case TELNET_NEW_ENVIRONMENT_VARIABLES:
                    PRINT_TREE(prof, "NEW ENVIRONMENT VARIABLES \n");
                    break;
                case TELNET_TN3270E:
                    PRINT_TREE(prof, "TN3270E \n");
                    break;
                case TELNET_XAUTH:
                    PRINT_TREE(prof, "XAUTH \n");
                    break;
                case TELNET_CHARSET:
                    PRINT_TREE(prof, "CHARSET \n");
                    break;  
                case TELNET_REMOTE_SERIAL_PORT:
                    PRINT_TREE(prof, "REMOTE SERIAL PORT \n");
                    break;
                case TELNET_COM_PORT_CONTROL:
                    PRINT_TREE(prof, "COM PORT CONTROL \n");
                    break;
                case TELNET_SUPPRESS_LOCAL_ECHO:
                    PRINT_TREE(prof, "SUPPRESS LOCAL ECHO \n");
                    break;
                case TELNET_START_TLS:
                    PRINT_TREE(prof, "START TLS \n");
                    break;
                case TELNET_KERMIT:
                    PRINT_TREE(prof, "KERMIT \n");
                    break;
                case TELNET_SEND_URL:
                    PRINT_TREE(prof, "SEND URL \n");
                    break;
                case TELNET_FORWARD_X:
                    PRINT_TREE(prof, "FORWARD X \n");
                    break;
                case TELNET_PRAGMA_LOGON:
                    PRINT_TREE(prof, "PRAGMA LOGON \n");
                    break;
                case TELNET_SSPI_LOGON:
                    PRINT_TREE(prof, "SSPI LOGON \n");
                    break;
                case TELNET_PRAGMA_HEARTBEAT:
                    PRINT_TREE(prof, "PRAGMA HEARTBEAT \n");
                    break;
                case TELNET_EXOPL:
                    PRINT_TREE(prof, "EXOPL \n");
                    break;
                default:
                    PRINT_TREE(prof, "UNKNOWN \n");
                    break;
                }
                printf("\n");
            } else {
                print_content(prof, verbose, size, packet);
            }
        }
    }
}

void parse_pop3(const u_char *packet, int verbose, int prof, int size) {
    switch (verbose) {
    case 1:
    case 2:
    case 3:
        PRINT_NEW_STATE(prof, verbose, BGRN "POP" GRN);

        if(verbose == 1) break ; // No need to print the rest of the header
        
        print_content(prof, verbose, size, packet);
    }
}   