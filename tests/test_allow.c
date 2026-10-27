#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include "../src/allow.h"

static int test_parse(void) {
    char *allow = "239.192.60+239.23+239.100";
    table_t *t = allow_parse(allow);
    if (!t) {
        printf("test_parse: parse returned NULL\n");
        return 1;
    }
    if (t->records_cnt != 3) {
        printf("test_parse: expected 3 records, got %d\n", t->records_cnt);
        allow_table_free(t);
        return 1;
    }
    // Verify first entry
    short *row1 = t->table[0];
    if (row1[0] != 239 || row1[1] != 192 || row1[2] != 60 || row1[3] != -1) {
        printf("test_parse: first row mismatch\n");
        allow_table_free(t);
        return 1;
    }
    // Verify second entry
    short *row2 = t->table[1];
    if (row2[0] != 239 || row2[1] != 23 || row2[2] != -1 || row2[3] != -1) {
        printf("test_parse: second row mismatch\n");
        allow_table_free(t);
        return 1;
    }
    // Verify third entry
    short *row3 = t->table[2];
    if (row3[0] != 239 || row3[1] != 100 || row3[2] != -1 || row3[3] != -1) {
        printf("test_parse: third row mismatch\n");
        allow_table_free(t);
        return 1;
    }
    allow_table_free(t);
    return 0;
}

static int test_trailing(void) {
    char *allow = "239.192.60+239.23+239.100+";
    table_t *t = allow_parse(allow);
    if (!t) {
        printf("test_trailing: parse returned NULL\n");
        return 1;
    }
    if (t->records_cnt != 3) {
        printf("test_trailing: expected 3 records, got %d\n", t->records_cnt);
        allow_table_free(t);
        return 1;
    }
    allow_table_free(t);
    return 0;
}

static int test_multiple_colon(void) {
    table_t *t = allow_parse("+");
    if (t != NULL) {
        printf("test_multiple_colon: expected no table, got %d records\n", t->records_cnt);
        allow_table_free(t);
        return 1;
    }
    t = allow_parse("+++");
    if (t != NULL) {
        printf("test_multiple_colon: expected no table, got %d records\n", t->records_cnt);
        allow_table_free(t);
        return 1;
    }
    return 0;
}

static int test_invalid(void) {
    const char *invalid[] = {
        "", "+", "+++", "239.1++239.2", "239.1+239.2++",
        "239..1", ".239.1", "239.1.", "1.2.3.4.5",
        "999", "256", "-1", "+1", "abc", "239.1.2.abc",
        "239.1.2.256", " 239.1", "239.1 ", "239,1",
    };

    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        table_t *t = allow_parse(invalid[i]);
        if (t) {
            printf("test_invalid: expected NULL for \"%s\"\n", invalid[i]);
            allow_table_free(t);
            return 1;
        }
    }
    return 0;
}

static int test_boundary(void) {
    table_t *t = allow_parse("0.0.0.0+255.255.255.255");
    if (!t) {
        printf("test_boundary: parse returned NULL\n");
        return 1;
    }
    if (t->records_cnt != 2) {
        printf("test_boundary: expected 2 records, got %d\n", t->records_cnt);
        allow_table_free(t);
        return 1;
    }
    if (t->table[0][0] != 0 || t->table[0][1] != 0 ||
        t->table[0][2] != 0 || t->table[0][3] != 0) {
        printf("test_boundary: 0.0.0.0 mismatch\n");
        allow_table_free(t);
        return 1;
    }
    if (t->table[1][0] != 255 || t->table[1][1] != 255 ||
        t->table[1][2] != 255 || t->table[1][3] != 255) {
        printf("test_boundary: 255.255.255.255 mismatch\n");
        allow_table_free(t);
        return 1;
    }
    allow_table_free(t);
    return 0;
}

static int test_match(void) {
    char *allow = "239.192.60"; // last octet wildcard
    table_t *t = allow_parse(allow);
    if (!t) { printf("test_match: parse NULL\n"); return 1; }
    struct in6_addr addr = {0};
    // IPv4-mapped address 239.192.60.5
    addr.s6_addr[12] = 239; addr.s6_addr[13] = 192; addr.s6_addr[14] = 60; addr.s6_addr[15] = 5;
    if (!allow_match_address(&addr, t)) {
        printf("test_match: expected true for 239.192.60.5\n");
        allow_table_free(t);
        return 1;
    }
    // Different address
    addr.s6_addr[14] = 61;
    if (allow_match_address(&addr, t)) {
        printf("test_match: expected false for 239.192.61.5\n");
        allow_table_free(t);
        return 1;
    }
    allow_table_free(t);
    return 0;
}

int main(void) {
    int failures = 0;
    failures += test_parse();
    failures += test_match();
    failures += test_trailing();
    failures += test_multiple_colon();
    failures += test_invalid();
    failures += test_boundary();
    if (failures)
        printf("%d test(s) failed\n", failures);
    else
        printf("All tests passed\n");
    return failures ? 1 : 0;
}
