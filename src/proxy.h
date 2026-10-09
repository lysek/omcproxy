/*
 * Copyright 2015 Steven Barth <steven at midlink.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

enum proxy_flags {
	// minimum scope to proxy (use only one, includes higher scopes)
	PROXY_REALMLOCAL = 3,
	PROXY_ADMINLOCAL = 4,
	PROXY_SITELOCAL = 5,
	PROXY_ORGLOCAL = 8,
	PROXY_GLOBAL = 0xe,

	// proxy may be flushed (from static config source)
	PROXY_FLUSHABLE = 1 << 4,

	// internal values
	_PROXY_UNUSED = 1 << 5,
	_PROXY_SCOPEMASK = 0xf,

	// allow table scope
	PROXY_ALLOW = 0b1000011,
};

// new struct - added allow functionality
typedef struct table {
	int records_cnt;
	short** table;
} table_t;


int proxy_set(const char *uplink, const char *downlinks[], size_t downlinks_cnt, enum proxy_flags flags, table_t* allowTable);

void proxy_reconcile_all(void);

void proxy_update(bool all);
void proxy_flush(void);

// additional functions - added allow functionality
table_t* allow_parse(char* allow);
void allow_table_fill(table_t* allowTable, char* argument);
void allow_table_free(table_t* allowTable);
void allow_table_add_address(short* array, char* address);
