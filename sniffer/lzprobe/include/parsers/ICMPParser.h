#ifndef ICMP_PARSER_H
#define ICMP_PARSER_H

#include "BaseParser.h"
#include "PacketMetadata.h"
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/IcmpLayer.h>

class ICMPParser : public BaseParser {
public:
    /**
     * @brief Parse ICMP packet and fill metadata
     * @param packet The packet to parse
     * @param metadata The metadata structure to fill
     * @return true if parsing was successful
     */
    static bool parse(pcpp::Packet& packet, PacketMetadata& metadata);
    
private:
    /**
     * @brief Parse ICMP echo request/reply messages
     * @param icmpLayer The ICMP layer to parse
     * @param metadata The metadata structure to fill
     */
    static void parseEchoMessage(pcpp::IcmpLayer* icmpLayer, PacketMetadata& metadata);
    
    /**
     * @brief Parse ICMP destination unreachable messages
     * @param icmpLayer The ICMP layer to parse
     * @param metadata The metadata structure to fill
     */
    static void parseDestinationUnreachable(pcpp::IcmpLayer* icmpLayer, PacketMetadata& metadata);
    
    /**
     * @brief Parse ICMP redirect messages
     * @param icmpLayer The ICMP layer to parse
     * @param metadata The metadata structure to fill
     */
    static void parseRedirect(pcpp::IcmpLayer* icmpLayer, PacketMetadata& metadata);
    
    /**
     * @brief Parse ICMP time exceeded messages
     * @param icmpLayer The ICMP layer to parse
     * @param metadata The metadata structure to fill
     */
    static void parseTimeExceeded(pcpp::IcmpLayer* icmpLayer, PacketMetadata& metadata);
    
    /**
     * @brief Parse ICMP parameter problem messages
     * @param icmpLayer The ICMP layer to parse
     * @param metadata The metadata structure to fill
     */
    static void parseParameterProblem(pcpp::IcmpLayer* icmpLayer, PacketMetadata& metadata);
    
    /**
     * @brief Get human-readable description for ICMP type
     * @param type ICMP message type
     * @return Description string
     */
    static std::string getTypeDescription(uint8_t type);
    
    /**
     * @brief Get human-readable description for ICMP code
     * @param type ICMP message type
     * @param code ICMP message code
     * @return Description string
     */
    static std::string getCodeDescription(uint8_t type, uint8_t code);
    
    /**
     * @brief Validate ICMP checksum
     * @param icmpLayer The ICMP layer to validate
     * @return true if checksum is valid, false otherwise
     */
    static bool validateChecksum(pcpp::IcmpLayer* icmpLayer);
};

#endif // ICMP_PARSER_H 