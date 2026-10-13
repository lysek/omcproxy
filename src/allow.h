#pragma once

#include <stdbool.h>
#include <netinet/in.h>

// Table used for address allow list
// Each entry is an array of 4 shorts representing an IPv4 address octets
// -1 indicates wildcard for that octet.
typedef struct table {
    int records_cnt;
    short **table;
} table_t;

// Create table from string like "192.168.0:10.0.0"
// Parses colon-separated addresses
// Returns NULL on error.
// The caller must free with allow_table_free().
table_t *allow_parse(char *allow);

// Free allocated table and its contents.
void allow_table_free(table_t *allowTable);

// Add an address to a table row. Used internally; may be used by other code.
void allow_table_add_address(short *array, char *address);

// Fill table from argument string. Used internally.
void allow_table_fill(table_t *allowTable, char *argument);

// Helper to match IPv4 mapped address against allow table.
bool allow_match_address(const struct in6_addr *addr, table_t *allowTable);