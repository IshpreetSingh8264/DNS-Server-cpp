# DNS Server — C++

A UDP DNS forwarder in C++23, built for the
[CodeCrafters "Build your own DNS server" challenge](https://codecrafters.io/challenges/dns-server).

Binds `0.0.0.0:2053`, answers from a small local zone, and forwards everything else to a real upstream resolver. Handles
name-compression pointers on the way in, per-question upstream resolution for multi-question packets, and the TC bit
per RFC 2181.

> **Scope note.** UDP only, and a *forwarder* rather than a recursive resolver. It does not walk the DNS hierarchy,
> chase CNAMEs, follow referrals, or cache. See [Not implemented](#not-implemented).

## Contents

- [Quick start](#quick-start)
- [How it answers](#how-it-answers)
- [Architecture](#architecture)
- [The DNS message model](#the-dns-message-model)
- [Name compression](#name-compression)
- [Response truncation](#response-truncation)
- [Multi-question queries](#multi-question-queries)
- [Logging](#logging)
- [CLI options](#cli-options)
- [Known limitations](#known-limitations)
- [Project layout](#project-layout)

## Quick start

Requires CMake 3.13+ and a C++23 compiler. No third-party libraries — `vcpkg.json` declares none and nothing calls
`find_package`.

```bash
cmake -B build -S .
cmake --build ./build
./build/dns-server
```

Or:

```bash
./your_program.sh
```

```
DNS server listening on 0.0.0.0:2053, upstream 8.8.8.8:53
```

```bash
$ dig @127.0.0.1 -p 2053 codecrafters.io A +short
8.8.8.8
$ dig @127.0.0.1 -p 2053 example.com A +short
93.184.216.34
```

## How it answers

`handleQuery` in `src/resolver/handler.cpp` is the whole policy, in order:

```
1.  parse the packet
      undecodable ──► re-parse the header alone, reply SERVFAIL with no question
2.  opcode != QUERY ──► NOTIMP
3.  RD == 0      ──► NOERROR with an empty answer section
4.  local zone match ──► answer from the fixed table
5.  forward to the upstream
      >1 question ──► one upstream query per question, then merge
6.  bigger than the client can accept ──► NOERROR + TC, question section only
7.  nothing came back  ──► SERVFAIL
```

**It never invents an answer.** If a real answer cannot be obtained, the client gets an error. That single rule is why
there is no fallback address and no synthesised A record anywhere in the tree.

The local zone is a fixed table mapping `codecrafters.io` to `8.8.8.8` with a 300-second TTL, served regardless of what
`--resolver` is set to.

## Architecture

```
              ┌──────────────────────────────────────────┐
   recvfrom ──►│  main.cpp                                 │
              │    for (;;) { receiveDatagram; handleQuery; │
              │               sendDatagram; }              │
              └───────────────────┬──────────────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │  resolver/handler.cpp      │
                    │  the policy, above         │
                    └──┬──────────────┬──────────┘
           ┌───────────┘              └────────────┐
           ▼                                        ▼
┌──────────────────────┐              ┌────────────────────────┐
│ resolver/            │              │  resolver/upstream.cpp │
│   local_override.cpp │              │    connect + send +    │
│   the fixed zone     │              │    recv, per query     │
└──────────┬───────────┘              └────────────────────────┘
           │
           ▼
┌──────────────────────────────────────────────────────────┐
│  protocol/    reader · names · writer · responses         │
│  types/       header, question, record, packet            │
│  utils/       big-endian helpers, stderr logger           │
└──────────────────────────────────────────────────────────┘
```

`main.cpp` is 90 lines and does nothing but argument parsing, bind, and the loop. Everything else is behind
`handleQuery`.

## The DNS message model

`src/types/message.hpp` is a struct of data plus enums. `DnsPacket` holds a `DnsHeader` and four vectors —
questions, answers, authorities, additionals — with a `syncCounts()` member that derives the four count fields from the
vector sizes.

`DnsRecord::rdata` is an **opaque byte blob**. There is no typed A, AAAA, NS, or SOA representation, which means any
record type parses and re-encodes identically and the server never has to understand what it is relaying.

Names are stored as dotted strings (`"example.com"`), with the root as `""`. `Rcode` values for `FORMERR` and `REFUSED`
are declared and have `toString` cases, but are never assigned locally — malformed input becomes `SERVFAIL`, and
`REFUSED` can only reach a client by verbatim relay.

## Name compression

Decoding lives in `src/protocol/names.cpp`. `parseName` recurses when it meets a pointer:

```cpp
if ((len & 0xC0) == 0xC0) {
    if (!name.empty()) name += '.';      // the dot, before the jumped-to suffix
    return parseNameImpl(data, offset, jumps + 1);
}
```

Two details that are easy to get wrong and were both bugs here:

**The dot.** When a compressed suffix is spliced onto a name that already has labels, the separator has to be
reinserted. `def` plus a pointer into `longassdomainname.com` is `def.longassdomainname.com`, not
`deflongassdomainname.com`. An earlier version dropped the dot, and a synthetic answer hid it from `dig`.

**The loop guard.** Recursion is capped at `kMaxNamePointerJumps = 20`, so a pointer that points at itself is a
`Name compression loop detected` error rather than a hang.

**Encoding does not compress.** `writeName` emits length-prefixed labels and a single zero terminator, and never writes
a pointer. That is correct but means responses near the size limit are larger than they need to be — which is what the
TC path exists to handle.

## Response truncation

`maxResponseSize(query)` scans the additionals for an EDNS0 OPT record (type 41) and reads the advertised UDP payload
size out of its class field, which is what that field means for an OPT record. With no OPT record it returns the
classic 512 bytes. It never returns less than 512, per RFC 6891.

If the relayed reply is over that limit, the server sends `NOERROR` with the **question section only** and the TC bit
set. It never emits a partial answer section. RFC 2181 §9 is explicit that a truncated response should carry no answers
rather than half of them, and that rule is why a client retries over TCP instead of parsing something half-formed.

## Multi-question queries

A packet with more than one question is not forwarded as-is. `forwardMultiQuestion` builds one single-question query per
question, sends each in turn, and merges the answers.

Each merged reply is checked: an answer whose transaction id does not match is discarded as somebody else's traffic, and
a question that fails to parse is logged and skipped. After the loop:

- Nothing reached the upstream at all → give up, and the caller sends `SERVFAIL`.
- Some but not all questions succeeded → set TC, because the answer is partial.
- All answers empty and an upstream reported an error → pass that RCODE through.

Two costs worth knowing: the queries go out **sequentially**, so an N-question packet can take up to N × 1.5 s, and the
EDNS0 OPT record is dropped from each forwarded query, so the upstream sees a 512-byte-limited query and may set TC on
its own reply.

## Logging

Everything goes to stderr. `std::cout` appears nowhere in `src/` — stdout is reserved for the socket.

`writeLine` flushes on every line, because a debug runner would otherwise show log output late or not at all.
`logInfo` and `logError` are byte-identical: there is no level, no prefix, and no severity distinction. `logPacketSummary`
prints a one-line header summary followed by one line per question.

All logging is unconditional. `codecrafters.yml` sets `debug: false`, but there is no debug switch in the code.

## CLI options

There is exactly one flag:

| Flag | Effect |
|---|---|
| `--resolver <ip>` | Upstream as an IPv4 literal, port 53. |
| `--resolver <ip>:<port>` | Upstream with an explicit port. |

The port the server binds is **fixed at 2053** and cannot be changed. There is no `--port`, no `--help`, no config file,
and no environment variables. Unknown arguments are ignored silently.

A bad *port* is reported and ignored at startup. A bad *host* is not validated at all — it is written straight into the
upstream config and fails per-query inside `inet_pton`, which is IPv4-only. Hostnames are not accepted.

## Known limitations

The first group is architectural:

1. **UDP only.** No TCP listener, no 2-byte length prefix, no connection handling.
2. **A forwarder, not a resolver.** No iterative resolution, no root or TLD walk, no CNAME chasing, no referral
   following, no cache, no DNSSEC.
3. **Single-threaded and blocking.** One request at a time; a slow upstream stalls every client for up to 1.5 s.
4. **No name compression on output.**
5. **Locally built responses never echo an EDNS0 OPT record.** Forwarded ones do, byte for byte.
6. **`SO_REUSEPORT` is mandatory-fatal.** It lets a stale server from a previous session silently answer a share of
   queries, which is a real debugging hazard as well as a reliability one.
7. **No `SO_RCVTIMEO` and no signal handling.** A blocking `recvfrom` with no shutdown path; `SIGINT` kills the process
   mid-flight.

The second group is correctness, and is less well documented elsewhere:

8. **`RD == 0` yields an empty `NOERROR`** instead of forwarding. `dig` sets RD by default, so it is invisible in
   practice.
9. **`header.qr` is never validated**, so a response datagram fed to the server is processed as a query.
10. **Reserved label types `0x40` and `0x80` are accepted** as label lengths of 64 and 128 bytes. RFC 1035 reserves
    them.
11. **No 255-octet name limit and no 63-octet label limit** on either encode or decode. `writeName` would truncate a
    64-byte label through a narrowing cast.
12. **`tryLocalAnswer` inspects only the first question**, so the local zone is bypassed entirely in a mixed packet where
    only the second question is in the zone.
13. **`buildTruncatedReply` hardcodes `ra = true`**, claiming recursion availability the server never exercised. Every
    other local builder sets `ra = false`.
14. **The size check applies only to relayed replies**, not to the locally built zone answer.
15. **Header bits `z`, `ad`, `cd`, and the EDNS0 upper RCODE bits are dropped** on parse and re-emitted as zero.
16. **The local zone matches case-sensitively.** No 0x20 case randomisation anywhere.
17. **`syncCounts()` can throw** out of `handleQuery` uncaught if a section somehow exceeds 65535 entries.

## Project layout

```
src/
  main.cpp                    argv, bind, the receive loop
  types/message.cpp           header, question, record, packet, syncCounts
  protocol/reader.cpp         parse header, question, record, packet
  protocol/names.cpp          the compression-aware name codec
  protocol/writer.cpp         serialise
  protocol/responses.cpp      the four reply builders
  resolver/handler.cpp        the policy
  resolver/upstream.cpp       connect, send, receive
  resolver/multiquery.cpp     per-question forwarding and merging
  resolver/local_override.cpp the fixed local zone
  net/socket.cpp              bind, recvfrom, sendto
  utils/bytes.cpp             big-endian readU16 / readU32 / writeU16 / writeU32
  utils/logger.cpp            stderr logging
```

`src/` is the include root, hence role-based includes like `#include "protocol/names.hpp"`. `CMakeLists.txt` globs both
`src/*.cpp` and `src/*.hpp`, with `CONFIGURE_DEPENDS` so a new file re-triggers the build.

## Code style

Comments are written in Pinglish — Punjabi in Latin script, with an English gloss in parentheses. It is the house
style, and 83 of the roughly 89 comment blocks in `src/` use it.

```cpp
// Oye, asli naam nikaal lo, te jump count badha do,
// taaki ghum chakkar na lage
if (jumps > kMaxNamePointerJumps) throw std::runtime_error("Name compression loop detected");
```

## Licence

No licence file is present in this repository. Add one before redistributing.
