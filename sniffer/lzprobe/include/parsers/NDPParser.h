#ifndef NDP_PARSER_H
#define NDP_PARSER_H

#include "BaseParser.h"
#include "PacketMetadata.h"
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/IcmpV6Layer.h>

/**
 * NDPParser - Neighbor Discovery Protocol Parser
 * 
 * NDP (Neighbor Discovery Protocol) is a core component of IPv6, responsible for:
 * - Address Resolution (Address Resolution)
 * - Neighbor Unreachability Detection (Neighbor Unreachability Detection, NUD)
 * - Duplicate Address Detection (Duplicate Address Detection, DAD)
 * - Router Discovery (Router Discovery)
 * - Redirect (Redirect)
 * 
 * Supported ICMPv6 message types:
 * - 133: Router Solicitation (RS)
 * - 134: Router Advertisement (RA)
 * - 135: Neighbor Solicitation (NS)
 * - 136: Neighbor Advertisement (NA)
 * - 137: Redirect
 */
class NDPParser : public BaseParser {
public:
    /**
     * @brief Parse NDP packet and fill metadata
     * @param packet Packet to parse
     * @param metadata Metadata structure to fill
     * @return Returns true if parsing successful
     */
    static bool parse(pcpp::Packet& packet, PacketMetadata& metadata);
    
private:
    /**
     * @brief Parse Router Solicitation (Type=133)
     * @param icmpv6Layer ICMPv6 layer pointer
     * @param metadata Metadata structure
     */
    static void parseRouterSolicitation(pcpp::IcmpV6Layer* icmpv6Layer, PacketMetadata& metadata);
    
    /**
     * @brief Parse Router Advertisement (Type=134)
     * @param icmpv6Layer ICMPv6 layer pointer
     * @param metadata Metadata structure
     */
    static void parseRouterAdvertisement(pcpp::IcmpV6Layer* icmpv6Layer, PacketMetadata& metadata);
    
    /**
     * @brief Parse Neighbor Solicitation (Type=135)
     * @param icmpv6Layer ICMPv6 layer pointer
     * @param metadata Metadata structure
     */
    static void parseNeighborSolicitation(pcpp::IcmpV6Layer* icmpv6Layer, PacketMetadata& metadata);
    
    /**
     * @brief Parse Neighbor Advertisement (Type=136)
     * @param icmpv6Layer ICMPv6 layer pointer
     * @param metadata Metadata structure
     */
    static void parseNeighborAdvertisement(pcpp::IcmpV6Layer* icmpv6Layer, PacketMetadata& metadata);
    
    /**
     * @brief Parse Redirect message (Type=137)
     * @param icmpv6Layer ICMPv6 layer pointer
     * @param metadata Metadata structure
     */
    static void parseRedirect(pcpp::IcmpV6Layer* icmpv6Layer, PacketMetadata& metadata);
    
    /**
     * @brief Parse NDP options
     * @param optionsData Options data pointer
     * @param optionsLen Options data length
     * @param metadata Metadata structure
     */
    static void parseNDPOptions(const uint8_t* optionsData, size_t optionsLen, PacketMetadata& metadata);
    
    /**
     * @brief Parse Source Link-Layer Address option (Type=1)
     * @param optionData Option data pointer
     * @param optionLen Option length
     * @param metadata Metadata structure
     */
    static void parseSourceLinkLayerOption(const uint8_t* optionData, uint8_t optionLen, PacketMetadata& metadata);
    
    /**
     * @brief Parse Target Link-Layer Address option (Type=2)
     * @param optionData Option data pointer
     * @param optionLen Option length
     * @param metadata Metadata structure
     */
    static void parseTargetLinkLayerOption(const uint8_t* optionData, uint8_t optionLen, PacketMetadata& metadata);
    
    /**
     * @brief Parse Prefix Information option (Type=3)
     * @param optionData Option data pointer
     * @param optionLen Option length
     * @param metadata Metadata structure
     */
    static void parsePrefixInformationOption(const uint8_t* optionData, uint8_t optionLen, PacketMetadata& metadata);
    
    /**
     * @brief Parse Redirected Header option (Type=4)
     * @param optionData Option data pointer
     * @param optionLen Option length
     * @param metadata Metadata structure
     */
    static void parseRedirectedHeaderOption(const uint8_t* optionData, uint8_t optionLen, PacketMetadata& metadata);
    
    /**
     * @brief Parse MTU option (Type=5)
     * @param optionData Option data pointer
     * @param optionLen Option length
     * @param metadata Metadata structure
     */
    static void parseMTUOption(const uint8_t* optionData, uint8_t optionLen, PacketMetadata& metadata);
    
public:
    /**
     * @brief Verify if IPv6 address is a solicited-node multicast address
     * @param address IPv6 address (network byte order)
     * @return Whether it is a solicited-node multicast address
     */
    static bool isSolicitedNodeMulticast(const uint8_t* address);
    
    /**
     * @brief Generate solicited-node multicast address from IPv6 address
     * @param unicastAddr Unicast address (network byte order)
     * @param multicastAddr Generated multicast address (network byte order)
     */
    static void generateSolicitedNodeMulticast(const uint8_t* unicastAddr, uint8_t* multicastAddr);
    
    /**
     * @brief Convert IPv6 address to string
     * @param address IPv6 address (network byte order)
     * @return IPv6 address string
     */
    static std::string ipv6ToString(const uint8_t* address);
    
    /**
     * @brief Convert MAC address to string
     * @param macAddr MAC address (network byte order)
     * @return MAC address string
     */
    static std::string macToString(const uint8_t* macAddr);
    
    /**
     * @brief Get NDP option type description
     * @param optionType Option type
     * @return Option type description string
     */
    static std::string getNDPOptionDescription(uint8_t optionType);
    
private:
};

#endif // NDP_PARSER_H
