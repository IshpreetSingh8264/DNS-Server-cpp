# Copilot instructions — DNS Server (C++)

A UDP DNS forwarder built for the
[CodeCrafters DNS server course](https://app.codecrafters.io/courses/dns-server/overview).
C++23, CMake, no third-party dependencies. `codecrafters test` reports 8/8.

Read `docs/ARCHITECTURE.md` for the full module map and data flow. This file is the
short version plus the things that are easy to get wrong.

## The one thing that matters

**Never invent a DNS answer.** If a real answer cannot be obtained, return the correct
error: `SERVFAIL` when the upstream is unreachable, `NOTIMP` for an opcode we do not
implement, `TC` when the reply will not fit. Never a hardcoded IP.

```sh
# must stay at zero hits
grep -rn "buildSyntheticAnswer" src/
grep -rn "std::cout" src/
```

A fabricated answer is worse than no answer: the client cannot tell, so it caches a
lie. A previous version of this codebase returned `8.8.8.8` for every A query, both
for multi-question packets and as a fallback when the upstream was down. It made a
stage pass while concealing a real bug in compression-pointer parsing.

## Layout

| Directory | Role | May call |
|---|---|---|
| `src/main.cpp` | wiring only — argv, bind, serve loop | anything |
| `src/types/` | wire contracts, enums, zero logic | nothing |
| `src/protocol/` | encode/decode, locally built responses | `types/`, `utils/` |
| `src/resolver/` | the resolution policy and the upstream | `protocol/`, `utils/`, itself |
| `src/net/` | sockets, errno, fds | `utils/` |
| `src/utils/` | leaf helpers, no DNS knowledge | nothing |

`main.cpp` is 90 lines and must stay under 200. No file may exceed 600 lines. The
largest here is `types/message.hpp` at 89.

## Conventions

- `namespace dns` on everything. Every `.hpp` has a matching `.cpp` — no header-only
  modules, no inline definitions outside `types/message.hpp`.
- No mutable globals. Config travels as a parameter (`UpstreamConfig`).
- `DnsPacket::syncCounts()` derives the four count fields from the four section
  vectors. Do not assign them by hand; a count that disagrees with its vector is a
  corrupt packet on the wire.
- Logging goes through `utils/logger.hpp`, and that module writes to **stderr only**.
  `main.cpp` must not touch `std::cout`.
- Includes are by role path: `#include "protocol/names.hpp"`.
- Comments are Pinglish + English. Match that voice.

## Things that will bite you

**`parseName` and the dot.** A compression pointer can follow a literal label, and the
result is one name joined by a dot. `"def"` plus a pointer into `"longassdomainname.com"`
is `def.longassdomainname.com`. Omitting the dot yields `deflongassdomainname.com` — a
different hostname, not a parse error, so nothing complains. The recursion depth is
capped at `kMaxNamePointerJumps` to stop pointer loops.

**A multi-question packet is not one upstream query.** A resolver may answer only the
first question or reject the packet, which hands the client an empty answer section.
`resolver/multiquery.cpp` asks once per question and merges. If nothing gets through it
returns `nullopt` and the caller replies SERVFAIL. If *some* get through, `TC` is set on
the merged reply so the client knows it is incomplete.

**EDNS0 size is the reply limit.** `maxResponseSize()` reads the advertised payload size
out of the OPT record's *class* field (that is what the field is for), and falls back to
512 with no OPT, never below 512. An oversized reply becomes a question section with
`TC` set — never a silent cut.

**`SO_REUSEPORT` will hide your bugs.** A server left running from an earlier session
keeps answering a share of the queries on port 2053 and you will draw conclusions from
another binary's output. `ss -ulnp | grep 2053` before you believe anything.

**The local zone is data, not a fallback.** `kLocalZone[]` in
`resolver/local_override.cpp` holds names we are authoritative for. It returns
`nullopt` for anything else so the query goes upstream, and it applies no matter which
`--resolver` was passed.

## Verifying a change

```sh
cmake -B build -S . && cmake --build ./build
codecrafters test
```

`codecrafters test` is the only authoritative check. `dig` against a local server
exercises one path at a time and will happily pass while a stage is broken.

## Not on the course

The course is 8 stages. Do not add: TCP DNS, multiple A records per name, `ANY` queries,
`AAAA`/IPv6. AAAA is relayed like any other RR type; there is no IPv6-specific handling
and none is needed.
