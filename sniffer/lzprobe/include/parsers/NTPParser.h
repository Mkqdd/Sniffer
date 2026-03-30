#ifndef NTP_PARSER_H
#define NTP_PARSER_H

#include "BaseParser.h"
#include "PacketMetadata.h"
#include <pcapplusplus/Packet.h>

class NTPParser : public BaseParser {
public:
    static bool parse(pcpp::Packet& packet, PacketMetadata& metadata);

private:
    // Helper methods for parsing NTP fields
    static void parseNTPHeader(const uint8_t* data, PacketMetadata& metadata);
    static uint64_t ntpTimestampToUint64(const uint8_t* data);
    static std::string ntpTimestampToString(uint64_t timestamp);
    static std::string leapIndicatorToString(uint8_t li);
    static std::string versionToString(uint8_t vn);
    static std::string modeToString(uint8_t mode);
    static std::string stratumToString(uint8_t stratum);
    static std::string referenceIdToString(uint32_t refId);
    static void calculateTimeMetrics(PacketMetadata& metadata);
};

#endif // NTP_PARSER_H
