#ifndef IGMP_PARSER_H
#define IGMP_PARSER_H

#include "BaseParser.h"
#include "PacketMetadata.h"
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/IgmpLayer.h>

class IgmpParser : public BaseParser {
public:
    /**
     * @brief Parse IGMP packet and fill metadata
     * @param packet The packet to parse
     * @param metadata The metadata structure to fill
     * @return true if parsing was successful
     */
    static bool parse(pcpp::Packet& packet, PacketMetadata& metadata);
    
    /**
     * @brief Parse IGMP header manually if PcapPlusPlus layer is not available
     * @param packet The packet to parse
     * @param metadata The metadata structure to fill
     * @return true if parsing was successful
     */
    static bool parseManually(pcpp::Packet& packet, PacketMetadata& metadata);
    
    /**
     * @brief Get human-readable description for IGMP type
     * @param type IGMP message type
     * @param version IGMP version
     * @return Description string
     */
    static std::string getTypeDescription(uint8_t type, uint8_t version);

public:
    /**
     * @brief Format IGMP group address to string
     * @param igmp_meta The IGMP metadata to format
     * @return Formatted group address string
     */
    static std::string getGroupAddressString(const IGMPMetadata& igmp_meta);

    /**
     * @brief Format IGMP source address to string
     * @param addr Source address to format
     * @return Formatted source address string
     */
    static std::string getSourceAddressString(uint32_t addr);
    
private:
    /**
     * @brief Parse IGMPv1 Membership Query message
     * @param igmpLayer The IGMP layer to parse
     * @param metadata The metadata structure to fill
     */
    static void parseV1MembershipQuery(pcpp::IgmpLayer* igmpLayer, PacketMetadata& metadata);
    
    /**
     * @brief Parse IGMPv1 Membership Report message
     * @param igmpLayer The IGMP layer to parse
     * @param metadata The metadata structure to fill
     */
    static void parseV1MembershipReport(pcpp::IgmpLayer* igmpLayer, PacketMetadata& metadata);
    
    /**
     * @brief Parse IGMPv2 Membership Query message
     * @param igmpLayer The IGMP layer to parse
     * @param metadata The metadata structure to fill
     */
    static void parseV2MembershipQuery(pcpp::IgmpLayer* igmpLayer, PacketMetadata& metadata);
    
    /**
     * @brief Parse IGMPv2 Membership Report message
     * @param igmpLayer The IGMP layer to parse
     * @param metadata The metadata structure to fill
     */
    static void parseV2MembershipReport(pcpp::IgmpLayer* igmpLayer, PacketMetadata& metadata);
    
    /**
     * @brief Parse IGMPv2 Leave Group message
     * @param igmpLayer The IGMP layer to parse
     * @param metadata The metadata structure to fill
     */
    static void parseV2LeaveGroup(pcpp::IgmpLayer* igmpLayer, PacketMetadata& metadata);
    
    /**
     * @brief Parse IGMPv3 Membership Query message
     * @param igmpLayer The IGMP layer to parse
     * @param metadata The metadata structure to fill
     */
    static void parseV3MembershipQuery(pcpp::IgmpLayer* igmpLayer, PacketMetadata& metadata);
    
    /**
     * @brief Parse IGMPv3 Membership Report message
     * @param igmpLayer The IGMP layer to parse
     * @param metadata The metadata structure to fill
     */
    static void parseV3MembershipReport(pcpp::IgmpLayer* igmpLayer, PacketMetadata& metadata);
    
    /**
     * @brief Determine IGMP version based on message type and content
     * @param igmpLayer The IGMP layer to analyze
     * @return IGMP version (1, 2, or 3)
     */
    static uint8_t determineIgmpVersion(pcpp::IgmpLayer* igmpLayer);
    
    /**
     * @brief Validate IGMP checksum
     * @param igmpLayer The IGMP layer to validate
     * @return true if checksum is valid, false otherwise
     */
    static bool validateChecksum(pcpp::IgmpLayer* igmpLayer);
    
    /**
     * @brief Get IPv4 layer from packet for manual parsing
     * @param packet The packet to get IPv4 layer from
     * @return Pointer to IPv4 layer or nullptr if not found
     */
    static void* getIPv4Layer(pcpp::Packet& packet);
};

#endif // IGMP_PARSER_H
