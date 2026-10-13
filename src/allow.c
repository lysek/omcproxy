#define _POSIX_C_SOURCE 200809L
#include "allow.h"

#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Parse a allow string and return a table. Return NULL on error.
// Trailing colon is ignored.
// Out‑of‑range octet turns that octet and all following ones into -1
// (wildcards). Empty entries (e.g., ":::") cause parsing to fail.
table_t* allow_parse(char* allow) {
    if (!allow) {
        return NULL;
    }
    int length = strlen(allow);
    if (length == 0) {
        return NULL;
    }

    // count non‑empty tokens (ignore trailing ":")
    int records = 0;
    char* tmp = strdup(allow);
    if (!tmp) {
        return NULL;
    }
    char *save, *tok = strtok_r(tmp, ":", &save);
    while (tok) {
        if (*tok != '\0') {
            records++;
        }
        tok = strtok_r(NULL, ":", &save);
    }
    free(tmp);
    if (records == 0) {
        return NULL;  // nothing to parse
    }

    // allocate table_t and its rows
    table_t* allowTable = malloc(sizeof(table_t));
    if (!allowTable) {
        return NULL;
    }

    allowTable->records_cnt = records;
    allowTable->table = malloc(records * sizeof(short*));
    if (!allowTable->table) {
        free(allowTable);
        return NULL;
    }
    for (int i = 0; i < records; i++) {
        allowTable->table[i] = calloc(4, sizeof(short));  // init to 0
        if (!allowTable->table[i]) {
            // cleanup on failure
            for (int j = 0; j < i; j++) free(allowTable->table[j]);
            free(allowTable->table);
            free(allowTable);
            return NULL;
        }
        // initialise to -1 for each octet
        for (int j = 0; j < 4; j++) {
            allowTable->table[i][j] = -1;
        }
    }

    // fill the table
    char* dup = strdup(allow);
    if (!dup) {
        // free everything
        for (int i = 0; i < records; i++) free(allowTable->table[i]);
        free(allowTable->table);
        free(allowTable);
        return NULL;
    }
    allow_table_fill(allowTable, dup);
    free(dup);

    return allowTable;
}

// Add an address to a table row. Converts out‑of‑range octet to wildcard.
void allow_table_add_address(short* array, char* address) {
    int i = 0;
    char *save, *octet_str;

    octet_str = strtok_r(address, ".", &save);
    while (octet_str != NULL && i < 4) {
        /* use strtol for proper range check */
        char* endptr;
        long val = strtol(octet_str, &endptr, 10);
        if (*endptr != '\0' || val < 0 || val > 255) {
            // out of range or non‑numeric → wildcard for this and remaining
            array[i] = -1;
            for (int j = i + 1; j < 4; j++) array[j] = -1;
            return;
        }
        array[i] = (short)val;
        octet_str = strtok_r(NULL, ".", &save);
        i++;
    }
    /* fill remaining slots with -1 (wildcard) */
    while (i < 4) {
        array[i++] = -1;
    }
}

// Fill table from a colon separated string.
void allow_table_fill(table_t* allowTable, char* argument) {
    int i = 0;
    char *save, *token = strtok_r(argument, ":", &save);
    while (token != NULL && i < allowTable->records_cnt) {
        if (*token != '\0') {
            allow_table_add_address(allowTable->table[i], token);
            i++;
        }
        token = strtok_r(NULL, ":", &save);
    }
}

// Free allocated table and its contents.
void allow_table_free(table_t* allowTable) {
    if (!allowTable) return;
    for (int i = 0; i < allowTable->records_cnt; i++) {
        free(allowTable->table[i]);
    }
    free(allowTable->table);
    free(allowTable);
}

// Helper to match IPv4 mapped address against allow table.
bool allow_match_address(const struct in6_addr* addr, table_t* allowTable) {
    bool result = false;

    for (int i = 0; i < allowTable->records_cnt; i++) {
        for (int j = 0; j < 4; j++) {
            if (allowTable->table[i][j] == -1) {
                result = true;  // wildcard matches any value at this octet
                break;
            }
            if (allowTable->table[i][j] != addr->s6_addr[j + 12]) {
                break;  // octet mismatch
            }
            if (j == 3 && allowTable->table[i][j] == addr->s6_addr[j + 12]) {
                result = true;  // all four octets matched
                break;
            }
        }
        if (result) {
            break;
        }
    }
    return result;
}
