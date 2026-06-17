[![progress-banner](https://backend.codecrafters.io/progress/dns-server/128adc62-216f-4b72-be5f-1114381281d9)](https://app.codecrafters.io/users/codecrafters-bot?r=2qF)

Welcome to the **Pinglish-powered DNS server** built for the
["Build Your Own DNS server" Challenge](https://app.codecrafters.io/courses/dns-server/overview).

## Introduction
- A full UDP DNS forwarder with local override for `codecrafters.io`, compression parsing, and SERVFAIL fallback.
- All logic lives in [src/main.cpp](src/main.cpp); comments are Pinglish plus playful English translations.

## Repository Setup
- Requirements: `cmake`, `g++` (C++17), and a Linux-y socket stack.
- Run `./your_program.sh` to build and start the server on UDP `2053`.

## Setup UDP Server
- The server binds `0.0.0.0:2053` with `SO_REUSEPORT` so restarts stay smooth.
- Main loop receives packets, parses, and replies immediately.

## Write header/question/answer sections
- `DnsHeader`, `DnsQuestion`, and `DnsRecord` structs capture every field.
- Encode/decode helpers read/write network byte order, ensuring flags and counts stay correct.

## Parse header/question/compressed packet
- `parsePacket()` walks header, questions, answers, authority, and additional sections.
- `parseName()` understands compressed labels (pointer handling with loop protection).

## Forwarding Server
- Queries try local override first (`codecrafters.io` → `8.8.8.8`).
- Otherwise packets forward to upstream resolver `8.8.8.8:53` with a 1.5s timeout; failures fall back to SERVFAIL.

## Running locally
```sh
./your_program.sh
# Then, from another shell:
dig @127.0.0.1 -p 2053 codecrafters.io A
```

## Notes
- Packet size capped at 512 bytes (classic DNS over UDP limit).
- Output is auto-flushed to keep logs visible in Codecrafters runner.
