#include "resolver/local_override.hpp"

#include <arpa/inet.h>

#include "protocol/responses.hpp"
#include "protocol/writer.hpp"
#include "types/message.hpp"

namespace dns {
namespace {

// Oye apna zone: naam te us da ek A address. (Our zone: a name and one A address for it.)
struct LocalZoneEntry {
    const char* name;
    const char* address;
    std::uint32_t ttl;
};

constexpr LocalZoneEntry kLocalZone[] = {
    {"codecrafters.io", kLocalZoneAddress, kLocalZoneTtl},
};

}  // namespace

// Oye local zone da jawab. (This is our zone's answer, not a guess.) It applies no
// matter which --resolver was passed: choosing an upstream resolver configures where
// *unknown* names go, it does not unpublish the names we are authoritative for.
std::optional<std::vector<std::uint8_t>> tryLocalAnswer(const DnsPacket& query) {
    if (query.questions.empty()) {
        return std::nullopt;
    }
    const DnsQuestion& question = query.questions.front();
    if (question.qtype != static_cast<std::uint16_t>(RecordType::kA) ||
        question.qclass != static_cast<std::uint16_t>(RecordClass::kIn)) {
        return std::nullopt;
    }

    for (const LocalZoneEntry& entry : kLocalZone) {
        if (question.qname != entry.name) {
            continue;
        }

        DnsRecord answer;
        answer.name = question.qname;
        answer.type = static_cast<std::uint16_t>(RecordType::kA);
        answer.rclass = static_cast<std::uint16_t>(RecordClass::kIn);
        answer.ttl = entry.ttl;
        answer.rdata.resize(4);
        if (inet_pton(AF_INET, entry.address, answer.rdata.data()) != 1) {
            return std::nullopt;
        }

        DnsPacket response;
        response.header = query.header;
        response.header.qr = true;
        response.header.aa = false;
        response.header.ra = false;
        response.header.rcode = rcodeFor(query.header.opcode, Rcode::kNoError);
        response.questions = query.questions;
        response.answers.push_back(answer);
        response.syncCounts();
        return buildPacket(response);
    }

    return std::nullopt;
}

}  // namespace dns
