#include "protocol/names.hpp"

#include <sstream>
#include <stdexcept>

#include "types/message.hpp"

namespace dns {
namespace {

// Oye recursion wala kunda, `jumps` de naal lohar pakadta hai. (The recursive worker;
// `jumps` is what catches a pointer loop.)
std::string parseNameImpl(const std::vector<std::uint8_t>& data, std::size_t& offset, int jumps) {
    if (jumps > kMaxNamePointerJumps) {
        throw std::runtime_error("Name compression loop detected");
    }
    std::string name;
    while (offset < data.size()) {
        const std::uint8_t len = data[offset];
        if ((len & 0xC0) == 0xC0) {
            if (offset + 1 >= data.size()) {
                throw std::runtime_error("Incomplete compression pointer");
            }
            const std::uint16_t ptr =
                static_cast<std::uint16_t>((static_cast<std::uint16_t>(len & 0x3F) << 8) | data[offset + 1]);
            offset += 2;
            std::size_t jumpTarget = ptr;
            // Oye dot zaroori hai. A pointer can follow a literal label - "def" followed
            // by a jump into "longassdomainname.com" is one name, "def.longassdomainname.com",
            // not two names glued together. Joining them without the dot turns one
            // hostname into a different, wrong one that will never resolve.
            // (The dot matters. A pointer may follow a literal label, and the two halves
            // are one name. Skipping the dot yields a different, nonexistent hostname
            // that can never resolve - a silent wrong answer, not a parse error.)
            if (!name.empty()) {
                name.push_back('.');
            }
            name += parseNameImpl(data, jumpTarget, jumps + 1);
            return name;
        }
        if (len == 0) {
            offset += 1;
            break;
        }
        offset += 1;
        if (offset + len > data.size()) {
            throw std::runtime_error("Label exceeds packet bounds");
        }
        if (!name.empty()) {
            name.push_back('.');
        }
        name.append(reinterpret_cast<const char*>(&data[offset]), len);
        offset += len;
    }
    return name;
}

}  // namespace

// Oye label splitter, dots nu tod ke jalebi bana rahe haan. (Splitting dotted names like jalebi spirals.)
std::vector<std::string> splitLabels(const std::string& name) {
    std::vector<std::string> labels;
    std::stringstream ss(name);
    std::string part;
    while (std::getline(ss, part, '.')) {
        if (!part.empty()) {
            labels.push_back(part);
        }
    }
    return labels;
}

// Oye DNS naam parse kar rahe, compression de nakhre vi sambhal rahe. (Parsing DNS names while babysitting compression drama.)
std::string parseName(const std::vector<std::uint8_t>& data, std::size_t& offset) {
    return parseNameImpl(data, offset, 0);
}

// Oye DNS naam likh rahe, compression to bina simple gaddi. (Writing DNS names plain, no fancy compression joyride.)
void writeName(std::vector<std::uint8_t>& out, const std::string& name) {
    for (const std::string& label : splitLabels(name)) {
        out.push_back(static_cast<std::uint8_t>(label.size()));
        out.insert(out.end(), label.begin(), label.end());
    }
    out.push_back(0);
}

}  // namespace dns
