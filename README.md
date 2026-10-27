# omcproxy - Embedded IGMPv3 and MLDv2 proxy

omcproxy is an IGMPv3 and MLDv2 multicast proxy for use in embedded Linux
devices like routers. It is small in size and can be compiled to <40 KB.

It is partly based on code of https://github.com/Oryon/pimbd

## Specifications and Features

1. Source-Specific Multicast Querier
	- MLDv2 querier (based on RFC 3810)
	- IGMPv3 querier (based on RFC 3376)

2. Multicast Proxying (based on RFC 4605)
	- Kernel-space multicast routing
	- Multiple instances support
	- Address-scope specific proxying

### Allow table functionality

It is possible to filter particular IP v4 address multicast by passing `allow`
instead of `scope` parameter. There can multiple addresses separated by `+` sign.
The address can be a wildcard if part of it is omitted (e.g. `allow=239.1.2` will allow
any final octet address).

## Compiling

The easiest way to compile omcproxy is by using `devel-build.sh` script within `sripts/` directory. Simply execute

```bash
./scripts/devel-build.sh
```

Note that `cmake` is required.

## Tests

Integration tests require Docker and `NET_ADMIN`:

```bash
make -C build
./tests/run-docker-test.sh
```

They cover interface lifecycle handling and IPv4 multicast data forwarding through the proxy.

Compiling and running the tests separately after running `scripts/devel-build.sh`:

```bash
make -C build
./build/test_allow
```