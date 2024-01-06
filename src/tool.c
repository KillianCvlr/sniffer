#include "tool.h"

void print_tree(int prof){
    for(int i = 0; i < prof; i++){
        printf("\t");
    }
    printf("| ");
    return;
}

void print_content(int prof, int verbose, int size, char* buff){
    if(verbose == 1) return;
    if(size != 0){
        print_tree(prof);
        for(int i = 0; i < size; i++){
            if(isprint(buff[i])){
                printf("%c", buff[i]);
            } else {
                if(buff[i] == '\n' && i != size -1){
                    printf("\n");
                    print_tree(prof);
                } else {
                    printf("·");
                }
            }
        }
    }
}

void print_new_state(int prof, int verbose){
    if(prof == 0){
        return;
    }
    if(verbose == 1){
        printf(" | ");
        return;
    } else {
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

void print_ip(struct in_addr addr){
    printf("%d.%d.%d.%d", 
    addr.s_addr & 0xFF, 
    (addr.s_addr >> 8) & 0xFF, 
    (addr.s_addr >> 16) & 0xFF, 
    (addr.s_addr >> 24) & 0xFF);
    return;
}

void print_ip_from_uint8(uint8_t *addr){
    printf("%d.%d.%d.%d", 
    addr[0], 
    addr[1], 
    addr[2], 
    addr[3]);
    return;
}

int pow(int base, int exp){
    int res = 1;
    for(int i = 0; i < exp; i++){
        res *= base;
    }
    return res;
}

int value_hex(uint8_t *buff, int size){
    int somme = 0;
    for(int i = 0; i < size; i++){
        somme += pow(16, size - i - 1) * *(buff+ i);
    }
    return somme;
}