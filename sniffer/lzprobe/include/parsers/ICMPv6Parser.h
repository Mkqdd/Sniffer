#ifndef ICMPV6_PARSER_H
#define ICMPV6_PARSER_H

#include "BaseParser.h"
#include "PacketMetadata.h"
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/IcmpV6Layer.h>

class ICMPv6Parser : public BaseParser {
public:
    /**
     * @brief Parse ICMPv6 packet and fill metadata
     * @param packet The packet to parse
     * @param metadata The metadata structure to fill
     * @return true if parsing was successful
     */
    static bool parse(pcpp::Packet& packet, PacketMetadata& metadata);
    
private:
    /**
     * @brief Parse ICMPv6 echo request/reply messages
     * @param icmpv6Layer The ICMPv6 layer to parse
     * @param metadata The metadata structure to fill
     */
    static void parseEchoMessage(pcpp::IcmpV6Layer* icmpv6Layer, PacketMetadata& metadata);
    
    /**
     * @brief Parse ICMPv6 destination unreachable messages
     * @param icmpv6Layer The ICMPv6 layer to parse
     * @param metadata The metadata structure to fill
     */
    static void parseDestinationUnreachable(pcpp::IcmpV6Layer* icmpv6Layer, PacketMetadata& metadata);
    
    /**
     * @brief Parse ICMPv6 packet too big messages
     * @param icmpv6Layer The ICMPv6 layer to parse
     * @param metadata The metadata structure to fill
     */
    static void parsePacketTooBig(pcpp::IcmpV6Layer* icmpv6Layer, PacketMetadata& metadata);
    
    /**
     * @brief Parse ICMPv6 time exceeded messages
     * @param icmpv6Layer The ICMPv6 layer to parse
     * @param metadata The metadata structure to fill
     */
    static void parseTimeExceeded(pcpp::IcmpV6Layer* icmpv6Layer, PacketMetadata& metadata);
    
    /**
     * @brief Parse ICMPv6 parameter problem messages
     * @param icmpv6Layer The ICMPv6 layer to parse
     * @param metadata The metadata structure to fill
     */
    static void parseParameterProblem(pcpp::IcmpV6Layer* icmpv6Layer, PacketMetadata& metadata);
    
    /**
     * @brief Parse ICMPv6 neighbor discovery messages
     * @param icmpv6Layer The ICMPv6 layer to parse
     * @param metadata The metadata structure to fill
     */
    static void parseNeighborDiscovery(pcpp::IcmpV6Layer* icmpv6Layer, PacketMetadata& metadata);
    
    /**
     * @brief Parse ICMPv6 router discovery messages
     * @param icmpv6Layer The ICMPv6 layer to parse
     * @param metadata The metadata structure to fill
     */
    static void parseRouterDiscovery(pcpp::IcmpV6Layer* icmpv6Layer, PacketMetadata& metadata);
    
    /**
     * @brief Get human-readable description for ICMPv6 type
     * @param type ICMPv6 message type
     * @return Description string
     */
    static std::string getTypeDescription(uint8_t type);
    
    /**
     * @brief Get human-readable description for ICMPv6 code
     * @param type ICMPv6 message type
     * @param code ICMPv6 message code
     * @return Description string
     */
    static std::string getCodeDescription(uint8_t type, uint8_t code);
    
    /**
     * @brief Validate ICMPv6 checksum
     * @param icmpv6Layer The ICMPv6 layer to validate
     * @return true if checksum is valid, false otherwise
     */
    static bool validateChecksum(pcpp::IcmpV6Layer* icmpv6Layer);
};

#endif // ICMPV6_PARSER_H

