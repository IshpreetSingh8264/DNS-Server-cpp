#include "types/message.hpp"

#include <stdexcept>

namespace dns {

// Oye enum de text badalna, bilkul lookup hai, DNS dyanu nahi chahida. (Turning enums
// into text: a plain lookup, knows nothing about DNS.)
std::string_view toString(Rcode rcode) {
    switch (rcode) {
        case Rcode::kNoError:
            return "NOERROR";
        case Rcode::kFormatError:
            return "FORMERR";
        case Rcode::kServerFailure:
            return "SERVFAIL";
        case Rcode::kNameError:
            return "NXDOMAIN";
        case Rcode::kNotImplemented:
            return "NOTIMP";
        case Rcode::kRefused:
            return "REFUSED";
    }
    return "RCODE?";
}

std::string_view toString(Opcode opcode) {
    switch (opcode) {
        case Opcode::kQuery:
            return "QUERY";
    }
    return "OPCODE?";
}

std::string_view toString(RecordType type) {
    switch (static_cast<RecordType>(type)) {
        case RecordType::kA:
            return "A";
        case RecordType::kOpt:
            return "OPT";
    }
    return "TYPE?";
}

std::string_view toString(RecordClass rclass) {
    switch (static_cast<RecordClass>(rclass)) {
        case RecordClass::kIn:
            return "IN";
    }
    return "CLASS?";
}

void DnsPacket::syncCounts() {
    if (questions.size() > 0xFFFF || answers.size() > 0xFFFF ||
        authorities.size() > 0xFFFF || additionals.size() > 0xFFFF) {
        throw std::runtime_error("DNS section exceeds 65535 entries");
    }
    header.qdCount = static_cast<std::uint16_t>(questions.size());
    header.anCount = static_cast<std::uint16_t>(answers.size());
    header.nsCount = static_cast<std::uint16_t>(authorities.size());
    header.arCount = static_cast<std::uint16_t>(additionals.size());
}

}  // namespace dns
