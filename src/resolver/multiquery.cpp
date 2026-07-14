#include "resolver/multiquery.hpp"

#include <string>

#include "protocol/reader.hpp"
#include "protocol/writer.hpp"
#include "resolver/upstream.hpp"
#include "types/message.hpp"
#include "utils/logger.hpp"

namespace dns {
namespace {

// Oye ik question di alag query packet. (One question, as a standalone query packet.)
std::vector<std::uint8_t> buildSingleQuestionQuery(const DnsPacket& query, const DnsQuestion& question) {
    DnsPacket single;
    single.header = query.header;
    single.header.qr = false;
    single.header.anCount = 0;
    single.header.nsCount = 0;
    single.header.arCount = 0;
    single.questions = {question};
    single.syncCounts();
    return buildPacket(single);
}

}  // namespace

// Oye ik ik question poochh ke, phir jawaab mila ke. (Ask one question at a time, then
// join up the answers.)
std::optional<std::vector<std::uint8_t>> forwardMultiQuestion(const DnsPacket& query,
                                                              const UpstreamConfig& upstream) {
    DnsPacket merged;
    merged.header = query.header;
    merged.header.qr = true;
    merged.header.aa = false;
    merged.header.ra = false;
    merged.questions = query.questions;

    int reachedUpstream = 0;
    bool sawErrorRcode = false;
    Rcode errorRcode = Rcode::kServerFailure;

    for (const DnsQuestion& question : query.questions) {
        const std::vector<std::uint8_t> wire = buildSingleQuestionQuery(query, question);
        const std::optional<std::vector<std::uint8_t>> reply =
            forwardToUpstream(upstream, wire.data(), wire.size());
        if (!reply) {
            continue;
        }

        DnsPacket answer;
        try {
            answer = parsePacket(*reply);
        } catch (const std::exception& ex) {
            logError("Upstream reply did not decode: " + std::string{ex.what()});
            continue;
        }
        if (answer.header.id != query.header.id) {
            // A different transaction. Not ours to merge in.
            logError("Upstream reply id " + std::to_string(answer.header.id) + " does not match query id " +
                     std::to_string(query.header.id) + "; dropping it");
            continue;
        }

        ++reachedUpstream;
        merged.header.ra = merged.header.ra || answer.header.ra;
        if (answer.header.rcode != 0 && !sawErrorRcode) {
            sawErrorRcode = true;
            errorRcode = static_cast<Rcode>(answer.header.rcode);
        }
        merged.answers.insert(merged.answers.end(), answer.answers.begin(), answer.answers.end());
        merged.authorities.insert(merged.authorities.end(), answer.authorities.begin(),
                                   answer.authorities.end());
        merged.additionals.insert(merged.additionals.end(), answer.additionals.begin(),
                                  answer.additionals.end());
    }

    if (reachedUpstream == 0) {
        // Not one question got through. Let the caller answer SERVFAIL: it knows how.
        return std::nullopt;
    }

    // Oye kuch question miss ho gaye, ta TC bit lagao ta client nu pata lage ki poora
    // jawaab nahi mila. Chhupauna galat hoga. (Some questions never got answered, so set
    // TC: the client deserves to know the reply is incomplete.)
    merged.header.tc = reachedUpstream < static_cast<int>(query.questions.size());

    // Jawab hai te NOERROR, waarna pehla error jo upstream da. (With answers, NOERROR;
    // otherwise the first error the upstream reported.)
    merged.header.rcode = static_cast<std::uint8_t>(
        merged.answers.empty() && sawErrorRcode ? errorRcode : Rcode::kNoError);
    merged.syncCounts();
    return buildPacket(merged);
}

}  // namespace dns
