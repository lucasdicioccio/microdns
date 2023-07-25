# microdns

A minimalist DNS-authoritative server.

## FAQ

- what problem does this package solve?

My zeroth use-case is to have some dynamic-DNS of my own so that I can track
and automate some configs.

Then another use-case is to answer [ACME DNS-01 challenges](https://datatracker.ietf.org/doc/html/rfc8555#section-8.4) from
[Let's Encrypt](https://letsencrypt.org).

You could use microdns for many cases where you want to expose something on top
of DNS.

A nice thing is that microdns uses my
[prodapi](https://github.com/lucasdicioccio/prodapi) package and will give you
some metrics, and a somewhat uniform way of building services.

- will you support DNSSEC ?

very unlikely

- will you support PunyCode ?

if some user asks politely


## Usage

To date, `microDNS` serves fixed records from a file and everything else from
memory. That is, you need to configure `microDNS` after it's started and will
lose everything if it restarts. You add DNS records by calling an HTTP(s)-API.

The HTTP(s)-API calls are validated using a shared-secret HMAC-256.  This
mechanism is not very strong, so you should probably not use `microdns` while
exposing the HTTP-configuration API on the Internet if your domain apex is a
sensitive target. For tech-savvy individuals with low-profile blogs like mine,
it's probably enough.

## Design

The implementation of `microDNS` ressembles roughly the modern HTTP server: a
server API (`MicroDNS.DAI`) much like
[WAI](https://hackage.haskell.org/package/wai) separates servers from handlers.
A single-threaded reference implementation (`MicroDNS.Server`) serving DNS over
UDP is provided. There are helpers (`MicroDNS.Handler`) to implement
applications based on lookup-functions so that you merely have to provide an
`IO [DNS.ResourceRecord]`.  Finally, a `MicoDNS.MicroZone` defines a zone-like
parser and `MicroDNS.DynamicRegistration` provides an HTTP(s)
configuration-interface.

## How to run?

Unless you have really good reasons not to do so, run microdns on UDP port 53.
You also need to listen on a TCP port of your choice for configuration
requests. We strongly recommend to use TLS to protect API-calls as the current
code is sensitive to replay attacks.

Assuming you're running some Linux.

IMHO, the best is to run chrooted with only enough privileges to do networking
and read the certificate/HMAC-files.

Say you've installed `microdns` in `/usr/local/bin`, you can grant the binary
the right to listen on port 53 even for non-root users using Linux capabilities
(`man 7 capabilities`).

```console
setcap 'cap_net_bind_service=+ep' /usr/local/bin/microdns
```

You should also consider rate-limiting incoming/outgoing UDP as UDP-DNS is
prone to abuse.

An example rate-limit is, using netfilter.

```console
nft add rule inet filter input udp dport 53 limit rate over 10/second drop
```

## Dynamic registration

There are only two available API-based registration:

Expose the client IP as A (or AAAA for IPv6 clients) `${subzone}.${apex}`
(mostly for the dynamic-DNS problem).
- `POST /register/auto/:subzone`

Expose `TXT ${subzone}.${apex} ${value}` (mostly for ACME-challenge token).
- `POST /register/txt/:subzone/:value`

### authentication

Some HMAC-256 protection using a shared-secret is here to provide a minimum of
authentication (cf. `MicroDNS.DynamicRegistration.verifyHmac`).

`x-microdns-hmac: ${base16-encode(hmac(${secret_key},${subzone}))}`

In present form, the implementation lacks nonces and only hashes the subzone.
Which means queries that can be spied-on can be modified and replayed.  As a
result, if you are using the Dynamic registration API over the Internet, TLS
should be mandatory.

## MicroZone Files

MicroDNS uses its own zone file with limited support for DNS records (e.g., all TTL are 300, no support for CHAOS class).

An example file with comments is as follows:

```
-- comments start with "--"
-- all records have fixed TTL to 300
-- there are no wildcards
-- there is no @ special syntax
-- all domain names are fqdns

-- A and AAAA records
A example.com. 1.2.3.4
AAAA example.com. ::1.2.3.4

-- TXT wants quoted strings
TXT example.com. "microdns has \"quoted\" strings with \\ (backslashes)"

-- CAA has two quoted strings
CAA example.com. "issue" "letsencrypt"

-- MX

MX example.com. 10 1.2.3.4
MX example.com. 100 spool.example.com.

-- CNAME

CNAME dir.example.com. directory.example.com

-- SRV have only priority
SRV _altweb._tcp.example.com. 10 8080 1.2.3.4
```

## TODO list

- dns-zones
  - eager, port and others parsing
  - some validation of zone values
- dynamic registration
  - support more record types
  - actual nonces
- server/handler
  - switch DNS lib to `dnsext`
  - listen on TCP socket
  - rate limiter
  - onException handler
- runtime/app
  - optionally count zones (unbounded storage required)
  - optionally expose a "self SRV record"
