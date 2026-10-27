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
// Parses colon-separated IPv4 prefixes with 1-4 octets each.
// Returns NULL on malformed input.
// The caller must free with allow_table_free().
table_t *allow_parse(const char *allow);

// Free allocated table and its contents.
void allow_table_free(table_t *allowTable);

// Add an address to a table row. Returns false on malformed input.
bool allow_table_add_address(short *array, const char *address);

// Fill table from argument string. Returns false on malformed input.
bool allow_table_fill(table_t *allowTable, const char *argument);

// Helper to match IPv4 mapped address against allow table.
bool allow_match_address(const struct in6_addr *addr, const table_t *allowTable);
