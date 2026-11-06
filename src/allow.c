#include "allow.h"

#include <limits.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

// Parse one dot-separated IPv4 prefix. Missing octets are wildcards (-1).
static bool allow_parse_record(const char *record, size_t len, short out[4])
{
	size_t pos = 0;
	size_t octets = 0;

	while (pos < len) {
		size_t start = pos;
		unsigned value = 0;

		while (pos < len && record[pos] != '.') {
			unsigned char c = (unsigned char)record[pos];

			if (c < '0' || c > '9')
				return false;

			if (pos - start >= 3)
				return false;

			value = value * 10 + (c - '0');
			if (value > 255)
				return false;

			++pos;
		}

		if (pos == start || octets >= 4)
			return false;

		out[octets++] = (short)value;

		if (pos < len) {
			++pos;
			if (pos == len)
				return false;
		}
	}

	if (octets == 0)
		return false;

	while (octets < 4)
		out[octets++] = -1;

	return true;
}

static int allow_parse_records(const char *allow, table_t *table)
{
	size_t len = strlen(allow);
	size_t pos = 0;
	size_t records = 0;

	if (len == 0)
		return -1;

	while (pos < len) {
		size_t end = pos;
		short parsed[4];

		while (end < len && allow[end] != '+')
			++end;

		if (end == pos)
			return -1;

		if (!allow_parse_record(&allow[pos], end - pos, parsed))
			return -1;

		if (table) {
			if (records >= (size_t)table->records_cnt)
				return -1;

			memcpy(table->table[records], parsed, sizeof(parsed));
		}

		++records;

		if (end == len)
			break;

		pos = end + 1;
	}

	if (records == 0 || records > INT_MAX)
		return -1;

	return (int)records;
}

table_t *allow_parse(const char *allow)
{
	table_t *allow_table;
	int records;

	if (!allow)
		return NULL;

	records = allow_parse_records(allow, NULL);
	if (records <= 0)
		return NULL;

	allow_table = calloc(1, sizeof(*allow_table));
	if (!allow_table)
		return NULL;

	allow_table->records_cnt = records;
	allow_table->table = calloc((size_t)records, sizeof(*allow_table->table));
	if (!allow_table->table) {
		free(allow_table);
		return NULL;
	}

	for (int i = 0; i < records; ++i) {
		allow_table->table[i] = calloc(4, sizeof(*allow_table->table[i]));
		if (!allow_table->table[i]) {
			allow_table_free(allow_table);
			return NULL;
		}
	}

	if (allow_parse_records(allow, allow_table) != records) {
		allow_table_free(allow_table);
		return NULL;
	}

	return allow_table;
}

void allow_table_free(table_t *allow_table)
{
	if (!allow_table)
		return;

	for (int i = 0; i < allow_table->records_cnt; ++i)
		free(allow_table->table[i]);

	free(allow_table->table);
	free(allow_table);
}

bool allow_match_address(const struct in6_addr *addr, const table_t *allow_table)
{
	if (!allow_table)
		return false;

	for (int i = 0; i < allow_table->records_cnt; ++i) {
		const short *row = allow_table->table[i];
		bool match = true;

		for (int j = 0; j < 4; ++j) {
			if (row[j] == -1)
				return true;

			if (row[j] != addr->s6_addr[12 + j]) {
				match = false;
				break;
			}
		}

		if (match)
			return true;
	}

	return false;
}
