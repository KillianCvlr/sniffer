#include "tool.h"

void print_tree(int prof){
    for(int i = 0; i < prof; i++){
        printf("\t");
    }
    printf("| ");
    return;
}

void print_new_state(int prof, int verbose){
    if(prof == 0){
        printf("* ");
        return;
    }
    if(verbose == 1){
        printf(" | ");
        return;
    } else {
        print_tree(prof -1); printf("\n");
        for(int i = 0; i < prof -1; i++){
            printf("\t");
        }
        printf("*———————* ");
        return;
    }
}

void print_mac(uint8_t *mac){
    printf("%02x:%02x:%02x:%02x:%02x:%02x", 
    mac[0], 
    mac[1], 
    mac[2], 
    mac[3], 
    mac[4], 
    mac[5]);
    return;
}
void print_ipv6(struct in6_addr addr){
    printf("%x:%x:%x:%x:%x:%x:%x:%x", 
    addr.s6_addr[0], 
    addr.s6_addr[1], 
    addr.s6_addr[2], 
    addr.s6_addr[3], 
    addr.s6_addr[4], 
    addr.s6_addr[5], 
    addr.s6_addr[6], 
    addr.s6_addr[7]);
    return;
}