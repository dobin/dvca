#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "vulns.h"

void vuln1_test() {
        char first[128];
        char second[128];
        unsigned int len1 = 16;
        unsigned int len2 = 0;

        bzero(first, sizeof(first));
        bzero(second, sizeof(second));

        printf("Test 1: \n");
        len2 = 8;
        concat_print1(first, &len1, second, &len2);

        printf("Test 2: \n");
        len2 = 256;
        concat_print1(first, &len1, second, &len2);

        printf("Test 3: \n");
        len2 = UINT_MAX;
        concat_print1(first, &len1, second, &len2);
}

void vuln2_test() {
        char first[128];
        char second[128];
        uint8_t len1 = 16;
        uint8_t len2 = 0;

        bzero(first, sizeof(first));
        bzero(second, sizeof(second));

        printf("Test 1: \n");
        len2 = 8;
        concat_print2(first, &len1, second, &len2);

        printf("Test 2: \n");
        len2 = 128;
        concat_print2(first, &len1, second, &len2);


        len2 = UINT8_MAX;
        printf("Test 3: %hhu \n", len2);
        concat_print2(first, &len1, second, &len2);
}



void vuln3_test() {
        char first[256];
        char second[256];
        unsigned int len1 = 16;
        unsigned int len2 = 0;

        bzero(first, sizeof(first));
        bzero(second, sizeof(second));

        memset(first, 'A', 16);
        memset(second, 'B', sizeof(second) - 1);

        printf("Test 1: \n");
        len2 = 8;
        concat_print3(first, len1, "BBBB", 4);

        printf("Test 2: \n");
        len2 = 256;
        concat_print3(first, len1, "BBBBBBBB BBBBBBBB BBBBBBBB BBBBBBBB BBBBBBBB BBBBBBBB", len2);

        printf("Test 3: \n");
        len2 = UINT_MAX;
        concat_print3(first, len1, second, len2);
}


void vuln4_test() {
    unsigned int arr[16];

    printf("Test 1: \n");
    storeScores(16, arr);

    printf("Test 2: \n");
    storeScores(UINT_MAX / sizeof(int) + 1, arr);
}


void vuln5_test() {
    earnings_table *table = malloc(sizeof(earnings_table));

    table->table = malloc(16 * sizeof(unsigned int));
    table->size = 16;

    printf("Test 5\n");
    insert_in_table(1, -1);
    change_earnings(table, 123, -1);

    int a = -1;
    int b = 5;
    if (a > b) {
        printf("NONO3\n");
    }

    free(table->table);
    free(table);
}


void main(int argc, char **argv) {
        //vuln1_test();
        //vuln2_test();
        //vuln3_test();
        //vuln4_test();
        vuln5_test();

        //char *a = malloc(0);
        //printf("A: %p", a);
}
