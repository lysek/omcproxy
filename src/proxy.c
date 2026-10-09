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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <libubox/list.h>

#include "querier.h"
#include "client.h"
#include "mrib.h"
#include "proxy.h"

struct proxy_downlink {
	struct list_head head;
	struct querier_user_iface iface;
	struct mrib_user mrib;
	struct client client;
	char *ifname;
	int ifindex;
	enum proxy_flags flags;
	table_t* allowTable; // added allow functionality
	bool attached;
};

struct proxy {
	struct list_head head;
	struct list_head downlinks;
	char *ifname;
	int ifindex;
	struct mrib_user mrib;
	struct querier querier;
	enum proxy_flags flags;
	table_t* allowTable; // added allow functionality
	bool attached;
};

// new functions - added allow functionality
table_t* allow_parse(char* allow) {
	int length = strlen(allow);
	if (length == 0) {
		//fprintf(stderr, "Error occurred while parsing allow.\n");
		return NULL;
	}
	int counter = 0;
	table_t* allowTable = malloc(sizeof(table_t));
	if (allowTable == NULL) {
		//fprintf(stderr, "Error while allocating new struct table.\n");
		return NULL;
	}

	for(int i = 0; i < length; i++) {
		if (allow[i] == ':') {
			counter++;
		}
	}
	counter++;
	// array of short arrays
	short** table = malloc(counter * sizeof(short*));
	if (table == NULL) {
		//fprintf(stderr, "Error while allocating new table.\n");
		return NULL;
	}
	for(int i = 0; i < counter; i++) { // record for every address
		short* array = malloc(4 * sizeof(short));
		if (array == NULL) {
			free(table);
			//fprintf(stderr, "Error while allocating sub-table\n");
			return NULL;
		}
		table[i] = array;
	}

	for(int i = 0; i < counter; i++) {
		for(int j = 0; j < 4; j++) {
			table[i][j] = -1;
		}
	}

	allowTable->records_cnt = counter;
	allowTable->table = table;
	allow_table_fill(allowTable, allow);

	return allowTable;
}

void allow_table_add_address(short* array, char* address) {
	int i = 0;
	char* save;
	char* c = NULL;

	c = strtok_r(address, ".", &save);
	while(c != NULL && i < 4) {
		array[i] = (short) atoi(c);
		c = strtok_r(NULL, ".", &save);
		i++;
	}

	while (i < 4) {
		array[i] = -1;
		i++;
	}
}

void allow_table_fill(table_t* allowTable, char* argument) {
	char* c = NULL;
	int i = 0;
	c = strtok(argument, ":");
	while(c != NULL) {
		allow_table_add_address(allowTable->table[i], c);
		c = strtok(NULL, ":");
		i++;
	}
}

void allow_table_free(table_t* allowTable) {
	for(int i = 0; i < allowTable->records_cnt; i++) {
		free(allowTable->table[i]);
	}
	free(allowTable->table);
	free(allowTable);
}

static bool allow_match_address(const struct in6_addr* addr, table_t* allowTable) {
	bool result = false;

	for(int i = 0; i < allowTable->records_cnt; i++) {
		for(int j = 0; j < 4; j++) {
			if(allowTable->table[i][j] == -1) {
				result = true;
				break;
			}
			if(allowTable->table[i][j] != addr->s6_addr[j+12]) {
				break;
			}
			if(j == 3 && allowTable->table[i][j] == addr->s6_addr[j+12]) {
				result = true;
				break;
			}
		}
		if(result) {
			break;
		}
	}
	return result;
}

static struct list_head proxies = LIST_HEAD_INIT(proxies);

// Detach the runtime part of a downlink, keeping its configuration.
static void proxy_downlink_detach(struct proxy_downlink *downlink)
{
	if (!downlink->attached)
		return;

	querier_detach(&downlink->iface);
	mrib_detach_user(&downlink->mrib);
	client_deinit(&downlink->client);
	downlink->ifindex = 0;
	downlink->attached = false;
}

// Remove and cleanup a downlink configuration.
static void proxy_remove_downlink(struct proxy_downlink *downlink)
{
	proxy_downlink_detach(downlink);
	list_del(&downlink->head);
	free(downlink->ifname);
	free(downlink);
}

// Match scope of a multicast-group against proxy scope-filter
static bool proxy_match_scope(enum proxy_flags flags, const struct in6_addr *addr, table_t* allowTable) // added allowTable
{
	bool isMatching = false;
	if (flags == PROXY_ALLOW) { // added allow functionality
		if(IN6_IS_ADDR_V4MAPPED(addr)) {
			isMatching = allow_match_address(addr, allowTable);
		}
	} else {
		unsigned scope = 0;
		if (IN6_IS_ADDR_V4MAPPED(addr)) {
			if (addr->s6_addr[12] == 239 && addr->s6_addr[13] == 255)
				scope = PROXY_REALMLOCAL;
			else if (addr->s6_addr[12] == 239 && (addr->s6_addr[13] & 0xfc) == 192)
				scope = PROXY_ORGLOCAL;
			else if (addr->s6_addr[12] == 224 && addr->s6_addr[13] == 0 && addr->s6_addr[14] == 0)
				scope = 2;
			else
				scope = PROXY_GLOBAL;
		} else {
			scope = addr->s6_addr[1] & 0xf;
		}
		isMatching = scope >= (flags & _PROXY_SCOPEMASK);
	}
	return isMatching;
}

// Test and set multicast route (called by mrib on detection of new source)
static void proxy_mrib(struct mrib_user *mrib, const struct in6_addr *group,
		const struct in6_addr *source, mrib_filter *filter)
{
	struct proxy *proxy = container_of(mrib, struct proxy, mrib);
	if (!proxy_match_scope(proxy->flags, group, proxy->allowTable))
		return;

	omgp_time_t now = omgp_time();
	struct querier_user *user;
	list_for_each_entry(user, &proxy->querier.ifaces, head) {
		if (groups_includes_group(user->groups, group, source, now)) {
			struct querier_user_iface *iface = container_of(user, struct querier_user_iface, user);
			struct proxy_downlink *downlink = container_of(iface, struct proxy_downlink, iface);
			mrib_filter_add(filter, &downlink->mrib);
		}
	}
}

// Update proxy state (called from querier on change of combined group-state)
static void proxy_trigger(struct querier_user_iface *user, const struct in6_addr *group,
		bool include, const struct in6_addr *sources, size_t len)
{
	struct proxy_downlink *iface = container_of(user, struct proxy_downlink, iface);
	if (proxy_match_scope(iface->flags, group, iface->allowTable))
		client_set(&iface->client, group, include, sources, len);
}

// Return true if an interface exists and is administratively up.
static bool proxy_get_ifindex(const char *ifname, int *ifindex)
{
	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	struct ifreq ifr = {};
	int idx;

	if (fd < 0)
		return false;

	if (strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1),
		ioctl(fd, SIOCGIFFLAGS, &ifr)) {
		close(fd);
		return false;
	}

	idx = if_nametoindex(ifname);
	close(fd);

	if (!idx || !(ifr.ifr_flags & IFF_UP))
		return false;

	*ifindex = idx;
	return true;
}

static int proxy_downlink_attach(struct proxy *proxy, struct proxy_downlink *downlink)
{
	int ifindex;
	int ret;

	if (downlink->attached)
		return 0;

	if (!proxy->attached || !proxy_get_ifindex(downlink->ifname, &ifindex))
		return -ENODEV;

	if (ifindex == proxy->ifindex)
		return -EINVAL;

	ret = client_init(&downlink->client, proxy->ifindex);
	if (ret)
		return ret;

	ret = mrib_attach_user(&downlink->mrib, ifindex, NULL);
	if (ret)
		goto err_client;

	ret = querier_attach(&downlink->iface, &proxy->querier, ifindex, proxy_trigger);
	if (ret)
		goto err_mrib;

	downlink->ifindex = ifindex;
	downlink->attached = true;
	return 0;

err_mrib:
	mrib_detach_user(&downlink->mrib);
err_client:
	client_deinit(&downlink->client);
	return ret;
}

static void proxy_downlinks_detach(struct proxy *proxy)
{
	struct proxy_downlink *downlink;
	list_for_each_entry(downlink, &proxy->downlinks, head)
		proxy_downlink_detach(downlink);
}

static int proxy_attach(struct proxy *proxy)
{
	int ifindex;
	int ret;

	if (proxy->attached)
		return 0;

	if (!proxy_get_ifindex(proxy->ifname, &ifindex))
		return -ENODEV;

	ret = mrib_attach_user(&proxy->mrib, ifindex, proxy_mrib);
	if (ret)
		return ret;

	proxy->ifindex = ifindex;
	proxy->attached = true;

	struct proxy_downlink *downlink;
	list_for_each_entry(downlink, &proxy->downlinks, head)
		proxy_downlink_attach(proxy, downlink);

	L_INFO("proxy: attached uplink %s (%d)", proxy->ifname, proxy->ifindex);
	return 0;
}

static void proxy_detach(struct proxy *proxy)
{
	if (!proxy->attached)
		return;

	proxy_downlinks_detach(proxy);
	mrib_detach_user(&proxy->mrib);
	proxy->ifindex = 0;
	proxy->attached = false;

	L_INFO("proxy: detached uplink %s", proxy->ifname);
}

static void proxy_reconcile(struct proxy *proxy)
{
	int ifindex;
	bool up = proxy_get_ifindex(proxy->ifname, &ifindex);

	if (!up) {
		proxy_detach(proxy);
		return;
	}

	if (!proxy->attached || proxy->ifindex != ifindex) {
		proxy_detach(proxy);
		if (proxy_attach(proxy))
			return;
	}

	struct proxy_downlink *downlink;
	list_for_each_entry(downlink, &proxy->downlinks, head) {
		int downlink_ifindex;
		bool down = proxy_get_ifindex(downlink->ifname, &downlink_ifindex);

		if (!down) {
			proxy_downlink_detach(downlink);
			continue;
		}

		if (downlink->attached && downlink->ifindex != downlink_ifindex)
			proxy_downlink_detach(downlink);

		if (!downlink->attached)
			proxy_downlink_attach(proxy, downlink);
	}
}

// Remove proxy with given pointer. This destroys the configuration.
static int proxy_unset(struct proxy *proxyp)
{
	bool found = false;
	struct proxy *proxy, *n;
	list_for_each_entry_safe(proxy, n, &proxies, head) {
		if ((proxyp && proxy == proxyp) ||
			(!proxyp && (proxy->flags & _PROXY_UNUSED))) {
			struct proxy_downlink *downlink, *dn;
			list_for_each_entry_safe(downlink, dn, &proxy->downlinks, head)
				proxy_remove_downlink(downlink);

			proxy_detach(proxy);
			if (proxy->allowTable != NULL)
				allow_table_free(proxy->allowTable);
			querier_deinit(&proxy->querier);
			list_del(&proxy->head);
			free(proxy->ifname);
			free(proxy);
			found = true;
		}
	}
	return (found) ? 0 : -ENOENT;
}

// Add / update proxy. Interface names are kept as configuration; interfaces
// may be absent or down and will be attached later by proxy_reconcile().
int proxy_set(const char *uplink, const char *downlinks[], size_t downlinks_cnt,
		enum proxy_flags flags, table_t* allowTable)
{
	struct proxy *proxy = NULL, *p;
	int ret = 0;

	list_for_each_entry(p, &proxies, head)
		if (!strcmp(p->ifname, uplink) && p->allowTable == allowTable)
			proxy = p;

	if (proxy && (downlinks_cnt == 0 ||
			((proxy->flags & _PROXY_SCOPEMASK) != (flags & _PROXY_SCOPEMASK)))) {
		proxy_unset(proxy);
		proxy = NULL;
	}

	if (downlinks_cnt <= 0)
		return 0;

	if (!proxy) {
		if (!(proxy = calloc(1, sizeof(*proxy))))
			return -ENOMEM;

		if ((flags & _PROXY_SCOPEMASK) == 0)
			flags |= PROXY_GLOBAL;

		proxy->flags = flags;
		proxy->allowTable = allowTable;
		proxy->ifname = strdup(uplink);
		if (!proxy->ifname) {
			free(proxy);
			return -ENOMEM;
		}

		INIT_LIST_HEAD(&proxy->downlinks);
		querier_init(&proxy->querier);
		list_add(&proxy->head, &proxies);
	}

	// The desired downlink set is represented by persistent downlink objects.
	// Remove entries which are no longer present in the configuration.
	struct proxy_downlink *downlink, *dn;
	list_for_each_entry_safe(downlink, dn, &proxy->downlinks, head) {
		size_t i;
		for (i = 0; i < downlinks_cnt && strcmp(downlinks[i], downlink->ifname); ++i);
		if (i == downlinks_cnt)
			proxy_remove_downlink(downlink);
	}

	for (size_t i = 0; i < downlinks_cnt; ++i) {
		bool found = false;
		list_for_each_entry(downlink, &proxy->downlinks, head) {
			if (!strcmp(downlink->ifname, downlinks[i])) {
				found = true;
				break;
			}
		}

		if (found)
			continue;

		downlink = calloc(1, sizeof(*downlink));
		if (!downlink) {
			ret = -ENOMEM;
			goto err;
		}

		downlink->ifname = strdup(downlinks[i]);
		if (!downlink->ifname) {
			free(downlink);
			ret = -ENOMEM;
			goto err;
		}

		downlink->flags = proxy->flags;
		downlink->allowTable = proxy->allowTable;
		list_add_tail(&downlink->head, &proxy->downlinks);
	}

	proxy_reconcile(proxy);
	return 0;

err:
	proxy_unset(proxy);
	return ret ? ret : -ENOMEM;
}

// Reconcile all configured proxies after an interface topology change.
void proxy_reconcile_all(void)
{
	struct proxy *proxy;
	list_for_each_entry(proxy, &proxies, head)
		proxy_reconcile(proxy);
}

// Mark all flushable proxies as unused
void proxy_update(bool all)
{
	struct proxy *proxy;
	list_for_each_entry(proxy, &proxies, head)
		if (all || (proxy->flags & PROXY_FLUSHABLE))
			proxy->flags |= _PROXY_UNUSED;
}


// Flush all unused proxies
void proxy_flush(void)
{
	proxy_unset(NULL);
}
