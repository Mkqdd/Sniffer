#ifndef BGP_PARSER_H
#define BGP_PARSER_H

#include "PacketMetadata.h"
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/BgpLayer.h>

// Forward declarations for PcapPlusplus BGP classes
namespace pcpp {
    class BgpOpenMessageLayer;
    class BgpUpdateMessageLayer;
    class BgpNotificationMessageLayer;
    class BgpRouteRefreshMessageLayer;
}

class BGPParser {
public:
    /**
     * @brief Parse BGP packet and extract metadata
     * @param packet PcapPlusPlus packet object
     * @param metadata Packet metadata structure to populate
     * @return true if packet was successfully parsed as BGP, false otherwise
     */
    static bool parse(pcpp::Packet& packet, PacketMetadata& metadata);
    
    /**
     * @brief Check if packet is a potential BGP packet
     * @param packet PcapPlusPlus packet object
     * @return true if packet appears to be BGP, false otherwise
     */
    static bool isBGPPacket(const pcpp::Packet& packet);
    
    /**
     * @brief Format BGP metadata for console output
     * @param bgp BGP metadata structure
     * @return Formatted string for console display
     */
    static std::string formatForConsole(const BGPMetadata& bgp);

private:
    /**
     * @brief Parse BGP OPEN message
     * @param bgpLayer Pointer to BGP layer
     * @param metadata Packet metadata structure to populate
     */
    static void parseOpenMessage(const pcpp::BgpLayer* bgpLayer, BGPMetadata& metadata);
    
    /**
     * @brief Parse BGP UPDATE message
     * @param bgpLayer Pointer to BGP layer
     * @param metadata Packet metadata structure to populate
     */
    static void parseUpdateMessage(const pcpp::BgpLayer* bgpLayer, BGPMetadata& metadata);
    
    /**
     * @brief Parse BGP NOTIFICATION message
     * @param bgpLayer Pointer to BGP layer
     * @param metadata Packet metadata structure to populate
     */
    static void parseNotificationMessage(const pcpp::BgpLayer* bgpLayer, BGPMetadata& metadata);
    
    /**
     * @brief Parse BGP ROUTE-REFRESH message
     * @param bgpLayer Pointer to BGP layer
     * @param metadata Packet metadata structure to populate
     */
    static void parseRouteRefreshMessage(const pcpp::BgpLayer* bgpLayer, BGPMetadata& metadata);
    
    /**
     * @brief Parse BGP path attributes
     * @param pathAttributes Vector of path attributes
     * @param metadata Packet metadata structure to populate
     */
    static void parsePathAttributes(const std::vector<pcpp::BgpOpenMessageLayer::optional_parameter>& pathAttributes, BGPMetadata& metadata);
    
    /**
     * @brief Parse BGP NLRI (Network Layer Reachability Information)
     * @param nlri Vector of NLRI data
     * @param metadata Packet metadata structure to populate
     */
    static void parseNLRI(const std::vector<std::string>& nlri, BGPMetadata& metadata);
    
    /**
     * @brief Convert bytes to hex string
     * @param data Pointer to data
     * @param length Length of data
     * @return Hex string representation
     */
    static std::string bytesToHexString(const uint8_t* data, size_t length);
    
    /**
     * @brief Convert IP address bytes to string
     * @param data Pointer to IP address bytes
     * @param length Length of IP address (4 for IPv4, 16 for IPv6)
     * @return IP address string
     */
    static std::string ipBytesToString(const uint8_t* data, size_t length);
};

#endif // BGP_PARSER_H

