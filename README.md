[![progress-banner](https://backend.codecrafters.io/progress/dns-server/128adc62-216f-4b72-be5f-1114381281d9)](https://app.codecrafters.io/users/codecrafters-bot?r=2qF)

Welcome to the **Pinglish-powered DNS server** built for the
["Build Your Own DNS server" Challenge](https://app.codecrafters.io/courses/dns-server/overview).
All 8 stages pass (`codecrafters test` → 8/8).

## What it does

A UDP DNS forwarder on `0.0.0.0:2053`. A query is answered from a small local zone if we
are authoritative for the name; otherwise it goes to a real upstream resolver
(`8.8.8.8:53` by default, `--resolver <ip>[:<port>]` to change it) and the reply is
relayed back.

**It never invents an answer.** If the upstream cannot be reached the client gets
`SERVFAIL`, not a made-up IP. That rule is the reason the code is split the way it is —
see `docs/ARCHITECTURE.md`.

## Repository setup

- `cmake`, `g++` with C++23, and a POSIX socket stack. No third-party libraries.
- `./your_program.sh` builds and runs the server.
- `codecrafters test` runs the graded stages.

## How the code is organised

Not one file — see `docs/ARCHITECTURE.md` for the module map and data flow, and
`.github/copilot-instructions.md` for the conventions and the traps.

```
src/main.cpp        argv, bind, receive -> handleQuery -> send. Nothing else.
src/types/          DnsHeader, DnsQuestion, DnsRecord, DnsPacket, enums
src/protocol/       name codec, packet reader, packet writer, local responses
src/resolver/       handler, local zone, multi-question fan-out, upstream
src/net/            bind / receive / send
src/utils/          byte helpers, logger (stderr)
```

Everything is in `namespace dns`, and every header has a real `.cpp`.

## What each course stage is implemented by

| Stage | Where |
|---|---|
| Parse header | `protocol/reader.cpp` → `parseHeader` |
| Parse question | `protocol/reader.cpp` → `parseQuestion`, `protocol/names.cpp` → `parseName` |
| Setup UDP server | `net/socket.cpp` → `bindServerSocket` |
| Write header | `protocol/writer.cpp` → `writeHeader` |
| Write question | `protocol/writer.cpp` → `writeQuestion` |
| Write answer | `protocol/writer.cpp` → `writeRecord` |
| Parse compressed packet | `protocol/names.cpp` → `parseName` (compression pointers, 20-jump loop guard) |
| Forwarding server | `resolver/handler.cpp`, `resolver/upstream.cpp` |

## Local zone

`resolver/local_override.cpp` holds a `kLocalZone[]` table. It currently maps
`codecrafters.io` → `8.8.8.8` with a 300 s TTL, which is the A record the course's
A-record stage requires. This is zone data we chose, not a fallback: the table returns
`nullopt` for every other name, so those queries reach the upstream. It is served no
matter which `--resolver` is configured.

## Not implemented, and not on the course

The course was trimmed to 8 stages. There is **no** TCP DNS, **no** multiple A records
for one name, **no** `ANY` query handling and **no** IPv6-specific handling. AAAA
records are parsed and relayed like any other record type. These are absent on purpose.

## Known limitations

- Locally built responses (`SERVFAIL`, header-only, `TC`) do not echo an EDNS0 OPT
  record. Forwarded replies do, because they are relayed byte for byte.
- `writeName` does not compress outgoing names, so a response near the size limit is
  larger than it needs to be.
- Requests are served one at a time, synchronously; a slow upstream blocks other
  clients for up to 1.5 s.

## Running locally

```sh
./your_program.sh
# from another shell:
dig @127.0.0.1 -p 2053 example.com A +short
dig @127.0.0.1 -p 2053 codecrafters.io A +short
```

`SO_REUSEPORT` is set so restarts are smooth, which also means a server left over from
an earlier session keeps answering. Check with `ss -ulnp | grep 2053` before trusting a
result.

All logging goes to **stderr**; stdout is never written to. Comments are Pinglish with
an English translation, which is this project's voice.
