#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "vulns.h"

#define BUF_SIZE 32


/****************** integer ***********************/

// VULN: Stack based, overwrite local buffer
// VULN: Unsigned Integer Wraparound
// VULN:   in dest buffer size comparison
/* Bad:
     ptr as arg
     Doesnt do much
   Good:
     can exploit via stack
*/
void concat_print1(
    char *first,
    unsigned int *first_len,
    char *second,
    unsigned int *second_len)
{
    int len = 0;
    char buf[BUF_SIZE];

    printf("First Len: %u  Second Len: %u   Buf len: %u\n",
            *first_len, *second_len, BUF_SIZE);

    // Check if it has space
    // VULN: Unsigned Integer Wraparound
    if (*first_len + *second_len > BUF_SIZE) {
        printf("First with size %i plus second with size %i do not have space in buf with size %i\n",
                *first_len, *second_len, BUF_SIZE);
        return;
    }

    for(unsigned int n=0; n<*first_len; n++) {
        printf("Copy 1: %i\n", n);
        buf[n] = first[n];
    }

    for(unsigned int n=0; n<*second_len; n++) {
        printf("Copy 2: %u at %u/%x   second_len: %u\n", n,
            *first_len+n,
            &buf[*first_len + n],
            *second_len);

        printf("  second_len pre : %u\n", *second_len);
        buf[*first_len + n] = second[n];
        printf("  second_len post: %u\n", *second_len);
    }

    printf("%s", buf);
}


// VULN: Stack based, overwrite local buffer
// VULN: signed Integer overflow
// VULN:   in dest buffer size comparison
/* Bad:
     ptr as arg
     uint8_t so we can really exploit it
   Good:
     can exploit via stack

    TODO: Remove ptr (not necessary)
*/
void concat_print2(
    char *first,
    uint8_t *first_len,
    char *second,
    uint8_t *second_len)
{
    uint8_t len = 0;
    char buf[BUF_SIZE];

    printf("First Len: %hhu  Second Len: %hhu   Buf len: %hhu\n",
            *first_len, *second_len, BUF_SIZE);

    // Check if it has space
    // VULN: Signed Integer Overflow
    printf("%hhu + %hhu = %hhu", *first_len, *second_len, *first_len + *second_len);
    len = *first_len + *second_len;
    if (len > BUF_SIZE) {
        printf("First with size %hhu plus second with size %hhu do not have space in buf with size %hhu\n",
                *first_len, *second_len, BUF_SIZE);
        return;
    }

    memcpy(buf, first, *first_len);
    memcpy(buf + *first_len, second, *second_len);

    printf("%s", buf);
}


// VULN: unsigned integer overflow
// VULN:   uses len of buffers to check, but strcpy() to copy for easier exploitation
void concat_print3(
    char *first,
    unsigned int first_len,
    char *second,
    unsigned int second_len)
{
    int len = 0;
    char buf[BUF_SIZE];

    printf("First Len: %u  Second Len: %u   Buf len: %u\n",
            first_len, second_len, BUF_SIZE);

    // Check if it has space
    // VULN: Unsigned Integer Wraparound
    if (first_len + second_len > BUF_SIZE) {
        printf("First with size %i plus second with size %i do not have space in buf with size %i\n",
                first_len, second_len, BUF_SIZE);
        return;
    }

    strcpy(buf, first);
    strcpy(buf + first_len, second);

    printf("%s", buf);
}



// VULN: signed comparison
// VULN:   overwrite arbitrary value below table with an int
int table[500];
int insert_in_table(int val, int pos) {
    printf("%i %i\n", pos, sizeof(table) / sizeof(int));
    if(pos > sizeof(table) / sizeof(int)) {
        printf("NONO1\n");
        return -1;
    }

    table[pos] = val;

    return 0;
}


/*****************************************************************************/



// OK
// VULN: signed comparison
// VULN:   overwrite arbitrary value below table with an int
int change_earnings(earnings_table *table, unsigned int val, int pos) {
    printf("%i %i\n", pos, table->size);
    if (pos > table->size) {
        printf("NONO2\n");
        return -1;
    }

    table->table[pos] = val;
}


// OK
// VULN: unsigned integer wraparound
unsigned int* storeScores(unsigned int score_count, unsigned int* score_array) {
    if (score_count == 0) {
        return NULL;
    }

    score_table *table = malloc(sizeof(score_table));


    printf("Store scores\n");

    unsigned int alloc_size = score_count * sizeof(int);
    printf("Alloc: %u * %u = %u\n", score_count, sizeof(int), alloc_size);
    table->table = (int *) malloc(alloc_size);
    table->size = score_count;

    for(unsigned int n=0; n<score_count; n++) {
        int score;

        score = score_array[n];
        if (score < 0) {
            break;
        }

        table->table[n] = score;
    }

    free(table->table);
    free(table);
}


/****************** overflow *******************/

// Stack Overflow
// Title

// Heap Overflow (static sized heap)
// Comment


/******************* UAF ***********************/

// Double Free
// with watchlist: add in two lists, remove in both

// Use after free
// With watchlist: add in two lists, remove in one, use in other one


// NULL ptr deref

// STR missing null byte
