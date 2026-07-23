# Architecture — DNS Server (C++)

UDP DNS forwarder for the [CodeCrafters DNS server course](https://app.codecrafters.io/courses/dns-server/overview).
The implementation covers all 8 stages of the course. The server answers from a small local
zone, and forwards everything else to a real upstream resolver.

## The one rule

**Never invent a DNS answer.** If a real answer cannot be obtained, return the
correct error — `SERVFAIL` for an unreachable upstream, `NOTIMP` for an opcode we
do not implement, `TC` for a reply that will not fit. A hardcoded IP is worse than
no answer, because a client has no way to tell it was invented.

This is not hypothetical. The original code had a `buildSyntheticAnswer` that
returned `8.8.8.8` for every A query, wired in as the answer to both multi-question
queries and upstream failures. It made a stage pass while hiding a real bug in
compression-pointer parsing. It is gone; `grep -rn "buildSyntheticAnswer" src/` must
stay at zero hits.

## Module map

```
src/
  main.cpp                    90 lines. argv, bind, receive -> handleQuery -> send. No DNS logic.
  types/
    message.{hpp,cpp}         DnsHeader/DnsQuestion/DnsRecord/DnsPacket, Rcode/Opcode/
                              RecordType/RecordClass, toString, DnsPacket::syncCounts
  protocol/
    names.{hpp,cpp}           splitLabels, parseName (compression + loop guard), writeName
    reader.{hpp,cpp}          parseHeader, parseQuestion, parseRecord, parsePacket
    writer.{hpp,cpp}          writeHeader, writeQuestion, writeRecord, buildPacket
    responses.{hpp,cpp}       rcodeFor, buildHeaderOnlyReply, buildServFail,
                              maxResponseSize (EDNS0), buildTruncatedReply (TC)
  resolver/
    handler.{hpp,cpp}         the decision: local zone -> upstream -> error
    local_override.{hpp,cpp}  the local zone (codecrafters.io)
    multiquery.{hpp,cpp}      fan a multi-question query out, one upstream query per question
    upstream.{hpp,cpp}        forwardToUpstream, UpstreamConfig
  net/
    socket.{hpp,cpp}          bind / receive / send. The only layer that knows about fds.
  utils/
    bytes.{hpp,cpp}           readU16, readU32, writeU16, writeU32
    logger.{hpp,cpp}          every diagnostic line, all on stderr
```

## Data flow

```
UDP datagram
   |
   v
net/socket::receiveDatagram      raw bytes + sender sockaddr
   |
   v
resolver/handler::handleQuery
   |
   +-- protocol/reader::parsePacket  --> DnsPacket          (throws -> header-only SERVFAIL)
   |
   +-- opcode != 0 or rd == 0  -> protocol/responses::buildHeaderOnlyReply   [local, no data]
   |
   +-- resolver/local_override::tryLocalAnswer  --> bytes?                   [local zone data]
   |
   +-- 1 question  -> resolver/upstream::forwardToUpstream  --> relay verbatim
   |
   +-- N questions -> resolver/multiquery::forwardMultiQuestion
   |                     -> upstream::forwardToUpstream, once per question
   |                     -> merge answers/authorities/additionals
   |
   +-- nothing came back -> protocol/responses::buildServFail                 [error, no data]
   |
   v
protocol/responses::maxResponseSize    does the reply fit what the client asked for?
   | no -> buildTruncatedReply (question section only, TC set)
   v
net/socket::sendDatagram
```

## Conventions

- **`namespace dns`.** Every symbol.
- **Every header has a real `.cpp`.** No header-only modules. Three headers carry
  `inline constexpr` data rather than declarations: `types/message.hpp`
  (`kHeaderSize`, `kMaxNamePointerJumps`), `net/socket.hpp` (`kMaxDatagramSize`),
  and `resolver/local_override.hpp` (`kLocalZoneAddress`, `kLocalZoneTtl`).
- **`std::runtime_error` is the error mechanism**, thrown from eight places: the
  big-endian readers, the name codec's loop and bounds checks, the header and
  record parsers, and `syncCounts`. Every parse function throws; none of them
  returns an error code.
- **Constants are `constexpr` and owned by the layer that uses them.** `kMaxDatagramSize`
  in `net/socket.hpp`, `kLocalZoneAddress` in `resolver/local_override.hpp`, and so on.
  There are no mutable globals. `UpstreamConfig` is a parameter, not a file-scope
  variable.
- **Counts are derived, never assigned.** Call `DnsPacket::syncCounts()` instead of
  writing `anCount` by hand. A hand-set count that disagrees with its vector produces a
  corrupt packet.
- **Logging is `utils/logger.hpp` and it is stderr only.** `grep -rn "std::cout" src/`
  must return zero hits. stdout is process data; diagnostics never go there.
- **Include by role path** (`#include "protocol/names.hpp"`). `src/` is the include
  root via `target_include_directories`.
- **Comments are Pinglish + English.** That is this project's voice; keep it.

## Integration points

| What | Where |
|---|---|
| Upstream resolver address | `--resolver <ip>` or `--resolver <ip>:<port>`, parsed in `main.cpp`, carried as `UpstreamConfig` |
| Local zone data | `kLocalZone[]` in `resolver/local_override.cpp` |
| Listen port | `kDnsPort` in `main.cpp` |
| Datagram size limit | `kMaxDatagramSize` in `net/socket.hpp` |
| UDP reply size policy | `maxResponseSize()` in `protocol/responses.cpp` |

## How to add a local zone entry

`resolver/local_override.cpp` is the only place that needs editing.

1. Add a row to `kLocalZone[]`:
   ```cpp
   constexpr LocalZoneEntry kLocalZone[] = {
       {"codecrafters.io", kLocalZoneAddress, kLocalZoneTtl},
       {"example.org", "203.0.113.5", 300},
   };
   ```
2. Rebuild and check it is served, not forwarded:
   ```sh
   ./your_program.sh &
   dig @127.0.0.1 -p 2053 example.org A +short
   ```

`syncCounts()` handles the count fields, and a non-`A`/non-`IN` question for the same
name falls through to the upstream rather than being answered from the zone. That is
intended: the zone is a data table, not a catch-all.

## How to add a new response type

1. Declare the builder in `protocol/responses.hpp`; implement it in
   `protocol/responses.cpp`. Build a `DnsPacket`, copy the question section from the
   query, call `syncCounts()`, return `buildPacket()`.
2. Choose it in `resolver/handler.cpp` in the order you want it tried, above the
   upstream forwarding. Never below it — if upstream can answer, upstream answers.

## How to change how a query is resolved

`resolver/handler.cpp::handleQuery` is the whole policy, in one function, in order:
local zone, then upstream. Adding a caching layer, a second upstream, or a blocklist
means editing that one function and adding a sibling module under `resolver/`. Do not
put resolution logic in `main.cpp`.

## Testing

```sh
./your_program.sh                        # build and run
codecrafters test                        # all 8 stages
```

`codecrafters test` is authoritative. A `dig` against a locally-run server checks one
path at a time and will not catch a stage regression — it caught none of the
compression bug. Note that `SO_REUSEPORT` is set, so a server left over from an earlier
run keeps answering half your queries. Check before trusting a result:

```sh
ss -ulnp | grep 2053
```

## Not on the course — do not add

The course is 8 stages and none of these are on it, so adding them is scope
creep: TCP DNS (the 2-byte length prefix and the connection), multiple A records
for one name, `ANY` queries, `AAAA`/IPv6 records. AAAA records are parsed and relayed
like any other RR type, but there is no IPv6-specific handling and none is required.

## Known limitations

- Locally built responses (`SERVFAIL`, header-only, `TC`) do not carry an EDNS0 OPT
  record even when the client sent one. Forwarded replies do, because they are relayed
  verbatim. `dig` tolerates the absence.
- `writeName` never compresses. Fine for well-known names; a response near the size
  limit is larger than it needs to be.
- One request is served at a time, synchronously. A slow upstream blocks every other
  client for up to 1.5 s.
