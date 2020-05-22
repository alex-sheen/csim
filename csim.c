#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <assert.h>
#include <math.h>
#include <string.h>
#include "cachelab.h"

/* === DATA STRUCTURES === */
/* Forward declaration of linked list */
typedef struct list list_t;

/* Linked list */
struct list {
    unsigned val;
    list_t* next;
};

/* A cache line */
typedef struct line {
    // The valid bit
    long valid;
    // The tag bits
    long tag;
} line_t;

/* A cache set */
typedef struct set {
    // The array of cache lines
    line_t* lines;
    // The list of accessed cache lines, from least to most recently used
    list_t* accessed;
} set_t;

/* === GLOBALS AND MACROS === */
/* Hexadecimal base */
#define HEX 16
/* Address length, in bits */
#define ADLEN 64
/* Cache hit */
#define HIT 0
/* Cache miss */
#define MISS 1

/* Command-line arguments */
int hflag = 0, vflag = 0, s, E_lines, b;
char* tracefile = NULL;

/* Number of cache sets, S */
int S_sets;

/* Cache hits, misses, and evictions */
int hits = 0, misses = 0, evictions = 0;

/* === LIST FUNCTIONS === */
list_t* append(list_t* xs, unsigned val) {
    list_t* node = (list_t*)malloc(sizeof(list_t));
    assert(node != NULL);
    node->val = val;
    node->next = NULL;
    list_t* res;
    if (xs) {
        res = xs;
        while (xs->next) {
            xs = xs->next;
        }
        xs->next = node;
        return res;
    } else {
        return node;
    }
}

list_t* expend(list_t* xs, unsigned val) {
    if (xs == NULL) {
        return NULL;
    }
    list_t *res, *prev;
    if (xs->val == val) {
        res = xs->next;
        free(xs);
        return res;
    }
    res = xs;
    while (xs && xs->val != val) {
        prev = xs;
        xs = xs->next;
    }
    if (xs) {
        prev->next = xs->next;
        free(xs);
    }
    return res;
}

void list_free(list_t* xs) {
    list_t* temp;
    while (xs) {
        temp = xs->next;
        free(xs);
        xs = temp;
    }
}

/* === CACHE FUNCTIONS === */
list_t* update_accessed(list_t* accessed, unsigned line) {
    list_t* updated = expend(accessed, line);
    updated = append(updated, line);
    return updated;
}

line_t* cache_lines_init() {
    line_t* lines = (line_t*)malloc(sizeof(line_t) * E_lines);
    assert(lines != NULL);
    unsigned i;
    for (i = 0; i < E_lines; i++) {
        lines[i].valid = 0;
        lines[i].tag = 0;
    }
    return lines;
}

set_t* cache_set_init() {
    set_t* set = (set_t*)malloc(sizeof(set_t));
    assert(set != NULL);
    set->lines = cache_lines_init();
    set->accessed = NULL;
    return set;
}

void cache_set_free(set_t* set) {
    assert(set != NULL);
    free(set->lines);
    list_free(set->accessed);
    free(set);
}

set_t** cache_init() {
    set_t** cache = (set_t**)malloc(sizeof(set_t*) * S_sets);
    assert(cache != NULL);
    unsigned i;
    for (i = 0; i < S_sets; i++) {
        cache[i] = cache_set_init();
    }
    return cache;
}

void cache_free(set_t** cache) {
    assert(cache != NULL);
    unsigned i;
    for (i = 0; i < S_sets; i++) {
        cache_set_free(cache[i]);
    }
    free(cache);
}

int cache_load(set_t* set, long tbits) {
    unsigned i;
    for (i = 0; i < E_lines; i++) {
        if(set->lines[i].valid) {
            if (set->lines[i].tag == tbits) {
                set->accessed = update_accessed(set->accessed, i);
                hits++;
                if (vflag) {
                    printf("hit ");
                }
                return HIT;
            }
        }
    }
    misses++;
    if (vflag) {
        printf("miss ");
    }
    for (i = 0; i < E_lines; i++) {
        if(set->lines[i].valid == 0) {
            break;
        }
    }
    if (i >= E_lines) {
        i = set->accessed->val;
        evictions++;
        if (vflag) {
            printf("eviction ");
        }
    }
    set->lines[i].valid = 1;
    set->lines[i].tag = tbits;
    set->accessed = update_accessed(set->accessed, i);
    return MISS;
}

/* === CACHE SIMULATOR === */
long nmask(unsigned nbits) {
    assert(nbits >= 0 && nbits <= 64);
    long mask = 0;
    unsigned i;
    for (i = 0; i < nbits; i++) {
        mask = (mask << 1) | 1;
    }
    return mask;
}

void simulate() {
    set_t** cache = cache_init();
    FILE* file = fopen(tracefile, "r");
    assert(file != NULL);
    char buffer[80];
    char operation;
    char saddress[80];
    long address, tbits, sbits;
    char* fline;
    while (fgets(buffer, sizeof(buffer), file)) {
        if (buffer[0] == ' ') {
            fline = strtok(buffer, "\n");
            if (vflag) {
                printf("%s ", fline);
            }
            sscanf(buffer, " %c %s", &operation, saddress);
            address = strtol(saddress, NULL, HEX);
            tbits = address >> (s + b);
            tbits = tbits & nmask(ADLEN - s - b);
            sbits = address >> b;
            sbits = sbits & nmask(s);
            switch (operation) {
                case 'L':
                case 'S':
                    cache_load(cache[sbits], tbits);
                    break;
                case 'M':
                    cache_load(cache[sbits], tbits);
                    cache_load(cache[sbits], tbits);
                    break;
                default:
                    fprintf(stderr, "simulate: not a valid cache operation\n");
                    exit(1);
            }
            if (vflag) {
                printf("\n");
            }
        }
    }
    cache_free(cache);
    fclose(file);
}

void print_help() {
    printf("Usage: ./csim [-hv] -s <num> -E <num> -b <num> -t <file>\n");
    printf("Options:\n");
    printf("  -h         Print this help message.\n");
    printf("  -v         Optional verbose flag.\n");
    printf("  -s <num>   Number of set index bits.\n");
    printf("  -E <num>   Number of lines per set.\n");
    printf("  -b <num>   Number of block offset bits.\n");
    printf("  -t <file>  Trace file.\n");
    printf("\n");
    printf("Examples:\n");
    printf("  linux>  ./csim -s 4 -E 1 -b 4 -t traces/yi.trace\n");
    printf("  linux>  ./csim -v -s 8 -E 2 -b 4 -t traces/yi.trace\n");
}

int main(int argc, char *argv[]) {
    // Parse command-line arguments
    char c;
    while ((c = getopt(argc, argv, "hvs:E:b:t:")) != -1) {
        switch (c) {
            case 'h':
                hflag = 1;
                break;
            case 'v':
                vflag = 1;
                break;
            case 's':
                s = atoi(optarg);
                S_sets = pow(2, s);
                break;
            case 'E':
                E_lines = atoi(optarg);
                break;
            case 'b':
                b = atoi(optarg);
                break;
            case 't':
                tracefile = optarg;
                break;
            default:
                exit(1);
        }
    }
    // Print help message
    if (argc == 1 || hflag) {
        print_help();
        exit(0);
    }
    // Simulate cache memory
    simulate();
    printSummary(hits, misses, evictions);
    return 0;
}
