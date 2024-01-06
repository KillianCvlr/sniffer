#include "protocols/bootp_bis.h"

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
        if(dhcp_tag(bootp_header)){ 
            PRINT_TREE(prof, BGRN "Magic cookie : " GRN);
            printf("0x%.2x%.2x%.2x%.2x", bootp_header->bp_vend[0], 
                    bootp_header->bp_vend[1],
                    bootp_header->bp_vend[2], 
                    bootp_header->bp_vend[3] );
            printf("\n");
        }


        //Option parsing
        int i = 4 ;
        int size = 0;
        while (i < 64) {
            switch (bootp_header->bp_vend[i]) {
            case TAG_PAD:
                i++;
                break;
            case TAG_SUBNET_MASK:
                size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "Subnet mask : ");
                print_ip_from_uint8(bootp_header->bp_vend + i + 2); printf("   ");
                print_dhcp_arg(size, i, bootp_header->bp_vend);
                i += size + 2;
                break;
            case TAG_TIME_OFFSET:
                size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "Time offset : ");
                print_dhcp_arg(size, i, bootp_header->bp_vend);
                break;
            case TAG_GATEWAY:
                size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "Gateway : ");
                if (size / 4) {
                    printf("\n");
                    for(int nb = 0; nb < (size /4); nb++){
                        print_tree(prof); printf("\t");
                        print_ip_from_uint8(bootp_header->bp_vend + i + 2 + nb*4);
                        printf("   ");
                        print_dhcp_arg(4 , i + nb*4, bootp_header->bp_vend);
                    }
                } else {
                    print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                    printf("   ");
                    print_dhcp_arg(size, i, bootp_header->bp_vend);
                }
                i += size + 2;
                break;
            case TAG_TIME_SERVER:
                size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "Time server : ");
                if (size / 4) {
                    printf("\n");
                    for(int nb = 0; nb < (size /4); nb++){
                        print_tree(prof); printf("\t");
                        print_ip_from_uint8(bootp_header->bp_vend + i + 2 + nb*4);
                        printf("   ");
                        print_dhcp_arg(4 , i + nb*4, bootp_header->bp_vend);
                    }
                } else {
                    print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                    printf("   ");
                    print_dhcp_arg(size, i, bootp_header->bp_vend);
                }
                i += size + 2;
                break;
            case TAG_NAME_SERVER:
                size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "Name server : ");
                if (size / 4) {
                    printf("\n");
                    for(int nb = 0; nb < (size /4); nb++){
                        print_tree(prof); printf("\t");
                        print_ip_from_uint8(bootp_header->bp_vend + i + 2 + nb*4);
                        printf("   ");
                        print_dhcp_arg(4 , i + nb*4, bootp_header->bp_vend);
                    }
                } else {
                    print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                    printf("   ");
                    print_dhcp_arg(size, i, bootp_header->bp_vend);
                }
                i += size + 2;
                break;
            case TAG_DOMAIN_SERVER:
                size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "Domain server : ");
                if (size / 4) {
                    printf("\n");
                    for(int nb = 0; nb < (size /4); nb++){
                        print_tree(prof); printf("\t");
                        print_ip_from_uint8(bootp_header->bp_vend + i + 2 + nb*4);
                        printf("   ");
                        print_dhcp_arg(4 , i + nb*4, bootp_header->bp_vend);
                    }
                } else {
                    print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                    printf("   ");
                    print_dhcp_arg(size, i, bootp_header->bp_vend);
                }
                i += size + 2;
                break;
            case TAG_LOG_SERVER:
                size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "Log server : ");
                if (size / 4) {
                    printf("\n");
                    for(int nb = 0; nb < (size /4); nb++){
                        print_tree(prof); printf("\t");
                        print_ip_from_uint8(bootp_header->bp_vend + i + 2 + nb*4);
                        printf("   ");
                        print_dhcp_arg(4 , i + nb*4, bootp_header->bp_vend);
                    }
                } else {
                    print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                    printf("   ");
                    print_dhcp_arg(size, i, bootp_header->bp_vend);
                }
                i += size + 2;
                break;
            case TAG_COOKIE_SERVER:
                size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "Cookie server : ");
                if (size / 4) {
                    printf("\n");
                    for(int nb = 0; nb < (size /4); nb++){
                        print_tree(prof); printf("\t");
                        print_ip_from_uint8(bootp_header->bp_vend + i + 2 + nb*4);
                        printf("   ");
                        print_dhcp_arg(4 , i + nb*4, bootp_header->bp_vend);
                    }
                } else {
                    print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                    printf("   ");
                    print_dhcp_arg(size, i, bootp_header->bp_vend);
                }
                i += size + 2;
                break;
            
            case TAG_LPR_SERVER:
                size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "LPR server : ");
                if (size / 4) {
                    printf("\n");
                    for(int nb = 0; nb < (size /4); nb++){
                        print_tree(prof); printf("\t");
                        print_ip_from_uint8(bootp_header->bp_vend + i + 2 + nb*4);
                        printf("   ");
                        print_dhcp_arg(4 , i + nb*4, bootp_header->bp_vend);
                    }
                } else {
                    print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                    printf("   ");
                    print_dhcp_arg(size, i, bootp_header->bp_vend);
                }
                i += size + 2;
                break;
            
            case TAG_IMPRESS_SERVER:
                size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "Impress server : ");
                if (size / 4) {
                    printf("\n");
                    for(int nb = 0; nb < (size /4); nb++){
                        print_tree(prof); printf("\t");
                        print_ip_from_uint8(bootp_header->bp_vend + i + 2 + nb*4);
                        printf("   ");
                        print_dhcp_arg(4 , i + nb*4, bootp_header->bp_vend);
                    }
                } else {
                    print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                    printf("   ");
                    print_dhcp_arg(size, i, bootp_header->bp_vend);
                }
                i += size + 2;
                break;

            case TAG_RLP_SERVER:
                size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "RLP server : ");
                if (size / 4) {
                    printf("\n");
                    for(int nb = 0; nb < (size /4); nb++){
                        print_tree(prof); printf("\t");
                        print_ip_from_uint8(bootp_header->bp_vend + i + 2 + nb*4);
                        printf("   ");
                        print_dhcp_arg(4 , i + nb*4, bootp_header->bp_vend);
                    }
                } else {
                    print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                    printf("   ");
                    print_dhcp_arg(size, i, bootp_header->bp_vend);
                }
                i += size + 2;
                break;

            case TAG_HOSTNAME:
                size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "Hostname : ");
                for(int j = 0; j < size; j++){
                    printf("%c", bootp_header->bp_vend[i + 2 + j]);
                }
                printf(" ");
                print_dhcp_arg(size, i, bootp_header->bp_vend);
                i += size + 2;
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
                size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "Lease time : ");
                print_dhcp_arg(size, i, bootp_header->bp_vend);
                i += size + 2;
                break;
            
            case TAG_OPT_OVERLOAD:
                PRINT_TREE(prof, "Option overload : \n");
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
                size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "MESSAGE : ");
                print_dhcp_arg(size, i, bootp_header->bp_vend);
                i += size + 2;
                break;

            case TAG_MAX_MSG_SIZE:
                size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "Max message size : ");
                print_dhcp_arg(size, i, bootp_header->bp_vend);
                i += size + 2;
                break;
            
            case TAG_RENEWAL_TIME:
                int size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "Renewal time : ");
                print_dhcp_arg(size, i, bootp_header->bp_vend);
                i += size + 2;
                break;
            
            case TAG_REBIND_TIME:
                size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "Rebind time : ");
                print_dhcp_arg(size, i, bootp_header->bp_vend);
                i += size + 2;
                break;

            case TAG_VENDOR_CLASS:
                size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "Vendor class : ");
                print_dhcp_arg(size, i, bootp_header->bp_vend);
                i += size + 2;
                break;

            case TAG_CLIENT_ID:
                size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "Client ID : ");
                print_dhcp_arg(size, i, bootp_header->bp_vend);
                print_content(prof, verbose, size, bootp_header->bp_vend + i + 2);
                printf("\n");                
                print_tree(prof); printf("\n");
                i += size + 2;
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

void print_dhcp_arg(int size, int i, const u_int8_t *bp_vend){
    printf("0x");
    for(int j = 0; j < size; j++){
        printf("%.2x", bp_vend[i + 2 + j]);
    }
    printf("\n");
    return;
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