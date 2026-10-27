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
	table_t *allowTable;
	int records;

	if (!allow)
		return NULL;

	records = allow_parse_records(allow, NULL);
	if (records <= 0)
		return NULL;

	allowTable = calloc(1, sizeof(*allowTable));
	if (!allowTable)
		return NULL;

	allowTable->records_cnt = records;
	allowTable->table = calloc((size_t)records, sizeof(*allowTable->table));
	if (!allowTable->table) {
		free(allowTable);
		return NULL;
	}

	for (int i = 0; i < records; ++i) {
		allowTable->table[i] = calloc(4, sizeof(*allowTable->table[i]));
		if (!allowTable->table[i]) {
			allow_table_free(allowTable);
			return NULL;
		}
	}

	if (allow_parse_records(allow, allowTable) != records) {
		allow_table_free(allowTable);
		return NULL;
	}

	return allowTable;
}

void allow_table_free(table_t *allowTable)
{
	if (!allowTable)
		return;

	for (int i = 0; i < allowTable->records_cnt; ++i)
		free(allowTable->table[i]);

	free(allowTable->table);
	free(allowTable);
}

bool allow_table_add_address(short *array, const char *address)
{
	short parsed[4];

	if (!array || !address)
		return false;

	if (!allow_parse_record(address, strlen(address), parsed))
		return false;

	memcpy(array, parsed, sizeof(parsed));
	return true;
}

bool allow_table_fill(table_t *allowTable, const char *argument)
{
	int records;

	if (!allowTable || !argument)
		return false;

	records = allow_parse_records(argument, NULL);
	if (records != allowTable->records_cnt)
		return false;

	return allow_parse_records(argument, allowTable) == records;
}

bool allow_match_address(const struct in6_addr *addr, const table_t *allowTable)
{
	if (!allowTable)
		return false;

	for (int i = 0; i < allowTable->records_cnt; ++i) {
		const short *row = allowTable->table[i];
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
