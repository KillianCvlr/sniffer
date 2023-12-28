#include "tool.h"

void print_tree(int prof){
    for(int i = 0; i < prof; i++){
        printf("\t");
    }
    printf("| ");
    return;
}

void print_new_state(int prof){
    if(prof == 0){
        printf("* ");
        return;
    }

    for(int i = 0; i < prof -1; i++){
        printf("\t");
    }
    printf("*----*");
    return;
}