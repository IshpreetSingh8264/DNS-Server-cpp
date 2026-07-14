#include "resolver/handler.hpp"

#include <cstddef>
#include <exception>
#include <string>

#include "protocol/reader.hpp"
#include "protocol/responses.hpp"
#include "resolver/local_override.hpp"
#include "resolver/multiquery.hpp"
#include "resolver/upstream.hpp"
#include "types/message.hpp"
#include "utils/logger.hpp"

namespace dns {
namespace {

// Parsefail te sirf header hi bachda hai: questions nu padh sakde hi nahi, ta
// chhadke. (After a parse failure only the header is trustworthy, so echo just the
// header. Reporting a SERVFAIL for a malformed datagram rather than dropping it is
// better than leaving the client waiting.)
std::vector<std::uint8_t> replyToUndecodableRequest(const std::vector<std::uint8_t>& request) {
    DnsPacket headerOnly;
    std::size_t offset = 0;
    headerOnly.header = parseHeader(request, offset);
    return buildServFail(headerOnly);
}

}  // namespace

// Oye poora safar: pehlan apna zone, phir upstream, phir (sirf error da option).
// (The whole trip: our own zone, then upstream, and only then an error.)
std::optional<std::vector<std::uint8_t>> handleQuery(const std::vector<std::uint8_t>& request,
                                                     const UpstreamConfig& upstream) {
    DnsPacket query;
    try {
        query = parsePacket(request);
    } catch (const std::exception& ex) {
        logError(std::string{"Could not decode request: "} + ex.what());
        try {
            return replyToUndecodableRequest(request);
        } catch (const std::exception& inner) {
            logError(std::string{"Could not even build an error response: "} + inner.what());
            return std::nullopt;
        }
    }

    logPacketSummary(query);

    // Oye opcode ya recursion nu apni taqdeer de raha hai, islye khud jawab dein. (We are
    // being asked for something this server does not do, so answer it ourselves
    // instead of troubling the upstream.)
    if (query.header.opcode != 0) {
        return buildHeaderOnlyReply(query);
    }
    if (query.header.rd == 0) {
        return buildHeaderOnlyReply(query);
    }

    if (auto local = tryLocalAnswer(query)) {
        return local;
    }

    // Oye baaki sagla packet, chahe ik ya sau questions ho, seedha upstream. (Everything
    // else - one question or a hundred - is answered by the upstream, never by us. We
    // relay what it says, or what merging its per-question replies says; we do not
    // second-guess it and we do not invent a better-looking answer.)
    std::optional<std::vector<std::uint8_t>> relayed =
        query.questions.size() > 1
            ? forwardMultiQuestion(query, upstream)
            : forwardToUpstream(upstream, request.data(), request.size());
    if (relayed) {
        // Oye jawaab 512 (ya EDNS0 limit) to ohdar hai, te aam tor te assi nu kaate
        // dena padega. Kadhe 1 te ghaad de ke nahi bhejna - TC bit laga ke bhejo, ta
        // client nu pata lage ki kuch reh gaya hai. (The reply is over the UDP limit and
        // may have to be cut. Never cut it silently: set TC so the client knows records
        // are missing.)
        if (relayed->size() > maxResponseSize(query)) {
            logInfo("Upstream reply is " + std::to_string(relayed->size()) +
                    " bytes, over the " + std::to_string(maxResponseSize(query)) +
                    "-byte limit for this client; replying with TC set");
            return buildTruncatedReply(query);
        }
        return relayed;
    }

    // Oye upstream nahi mila, ta error dilange. Jawab nahi banayenge - koi galat IP ya
    // koi invented record iss nu galat samajh ke koi ohda le lavan ge. (The upstream is
    // gone, so we return an error. We do not answer instead: a made-up IP or a made-up
    // record is worse than no answer, because a client will believe it.)
    logError("Upstream " + upstream.host + ":" + std::to_string(upstream.port) +
             " unreachable; replying SERVFAIL");
    return buildServFail(query);
}

}  // namespace dns
