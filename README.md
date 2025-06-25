# anydnsdqy

small dns server supports doq(dns over quic), doh(dns over https) made with rust.
it is made with [any-dns](https://github.com/severinalexb/any-dns/) service and [dqy](https://github.com/dandyvica/dqy) backend

* this binary has not tested, please use this in test environment
* ipv6 service or connect is not supported

## Usage

use it like any dns server. it will open 53 port.
```
- Run Normal DNS Server backed with default system DNS
$ ./anydnsdqy

- Use a specific resolver
$ ./anydnsdqy @1.1.1.1

- Use DoT for a resolver supporting DNS over TLS
$ ./anydnsdqy @1.1.1.1 --tls

- Use DoH for a resolver supporting DNS over HTTPS
$ ./anydnsdqy @https://cloudflare-dns.com/dns-query --doh

- Use DoQ
$ ./anydnsdqy @quic://dns.adguard.com

- Use DNSSEC
$ ./anydnsdqy --dnssec

- Binding Dns service to 127.0.0.2:53
$ ./anydnsdqy -b 127.0.0.2:53
```

## Supported DNS Types

these dns types are supported. Unsupported dns type request will be replied with fallback server responses.

```
A
AAAA
AFSDB
CNAME
HINFO
LOC
MX
NS
PTR
SOA
SRV
TXT
SVCB
HTTPS
CAA
DNSKEY
RRSIG
DS
```

## Todo

DQY Supported But Not Implemented Types
```
NAPTR >>
EUI48 >>
EUI64 >>
CERT >>
ZONEMD >>
KX >>
IPSECKEY >>
DNAME
NSEC
DHCID >>
-----------------
ISDN >>
MINFO >>
NSAP >>
NSEC >>
RouteThrough >>
RP >>
WKS >>
-----------------
algorithm
apl
csync
hip
openpgpkey
opt
rrlist
sshfp
tlsa
type_bitmaps
uri
wallet
```

simple_dns Not Implemented Types
```
NSEC3
NSEC3PARAM
OPENPGPKEY >>
SSHFP >>
TLSA
URI >>
WALLET
```