#ifndef VXLAN_PARSER_H
#define VXLAN_PARSER_H

#include "BaseParser.h"
#include "PacketMetadata.h"
#include <pcapplusplus/Packet.h>

class VXLANParser : public BaseParser {
public:
    /**
     * @brief Parse VXLAN packet and fill metadata
     * @param packet The packet to parse
     * @param metadata The metadata structure to fill
     * @return true if parsing was successful
     */
    static bool parse(pcpp::Packet& packet, PacketMetadata& metadata);
    
    /**
     * @brief Check if a packet contains VXLAN (UDP port 4789)
     * @param packet The packet to check
     * @return true if packet contains VXLAN
     */
    static bool isVXLANPacket(pcpp::Packet& packet);
    
    /**
     * @brief Parse encapsulated Ethernet frame from VXLAN payload
     * @param packet The packet containing VXLAN
     * @param metadata The metadata structure to fill
     * @return true if parsing was successful
     */
    static bool parseEncapsulatedEthernet(pcpp::Packet& packet, PacketMetadata& metadata);

private:
    static const uint16_t VXLAN_PORT = 4789;  // Standard VXLAN port
    static const size_t VXLAN_HEADER_SIZE = 8; // VXLAN header size in bytes
    
    /**
     * @brief Parse VXLAN header manually when PcapPlusPlus doesn't support it
     * @param packet The packet to parse
     * @param metadata The metadata structure to fill
     * @return true if parsing was successful
     */
    static bool parseManualVXLAN(pcpp::Packet& packet, PacketMetadata& metadata);
    
    /**
     * @brief Parse VXLAN header using PcapPlusPlus VxlanLayer
     * @param packet The packet to parse
     * @param metadata The metadata structure to fill
     * @return true if parsing was successful
     */
    static bool parsePcapPlusPlusVXLAN(pcpp::Packet& packet, PacketMetadata& metadata);
};

#endif // VXLAN_PARSER_H 