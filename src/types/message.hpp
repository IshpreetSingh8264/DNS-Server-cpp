#pragma once

// Wire-format contracts. Oye shehron da interface, koi logic nahi. (The interface
// of all the wire towns. No logic here, promise.)

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace dns {

// Oye fixed sizes, har packet chann di jind. (Fixed sizes, every packet's spine.)
inline constexpr std::size_t kHeaderSize = 12;
inline constexpr int kMaxNamePointerJumps = 20;  // compression loop guard

// Oye response codes di list, sirf oh hi jo assi de sakde haan. (The response code
// list, only the ones we can actually produce.)
enum class Rcode : std::uint8_t {
    kNoError = 0,
    kFormatError = 1,
    kServerFailure = 2,
    kNameError = 3,
    kNotImplemented = 4,
    kRefused = 5,
};

// Sirf QUERY (0) supported hai, baqi sab nu NOTIMP. (Only QUERY (0) is supported, the rest get NOTIMP.)
enum class Opcode : std::uint8_t {
    kQuery = 0,
};

enum class RecordType : std::uint16_t {
    kA = 1,
    kOpt = 41,  // EDNS0 pseudo-record, sirf additional section vich. (only in the additional section)
};

enum class RecordClass : std::uint16_t {
    kIn = 1,
};

std::string_view toString(Rcode rcode);
std::string_view toString(Opcode opcode);
std::string_view toString(RecordType type);
std::string_view toString(RecordClass rclass);

struct DnsHeader {
    std::uint16_t id{};
    bool qr{};
    std::uint8_t opcode{};
    bool aa{};
    bool tc{};
    bool rd{};
    bool ra{};
    std::uint8_t rcode{};
    std::uint16_t qdCount{};
    std::uint16_t anCount{};
    std::uint16_t nsCount{};
    std::uint16_t arCount{};
};

struct DnsQuestion {
    std::string qname;
    std::uint16_t qtype{};
    std::uint16_t qclass{};
};

struct DnsRecord {
    std::string name;
    std::uint16_t type{};
    std::uint16_t rclass{};
    std::uint32_t ttl{};
    std::vector<std::uint8_t> rdata;
};

struct DnsPacket {
    DnsHeader header;
    std::vector<DnsQuestion> questions;
    std::vector<DnsRecord> answers;
    std::vector<DnsRecord> authorities;
    std::vector<DnsRecord> additionals;

    // Oye counts apne aap derive hundi haan, haath nahi lagda. (Counts derive themselves;
    // a hand-set count can never desync the wire format.)
    void syncCounts();
};

}  // namespace dns
