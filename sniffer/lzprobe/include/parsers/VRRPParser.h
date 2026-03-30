#ifndef VRRP_PARSER_H
#define VRRP_PARSER_H

#include "BaseParser.h"
#include "PacketMetadata.h"
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/VrrpLayer.h>

class VRRPParser : public BaseParser {
public:
    /**
     * Parse VRRP packet and extract metadata
     * @param packet The packet to parse
     * @param metadata Output metadata structure
     * @return true if parsing was successful, false otherwise
     */
    static bool parse(pcpp::Packet& packet, PacketMetadata& metadata);

private:
    /**
     * Parse VRRP v2 packet
     * @param vrrpLayer VRRP v2 layer pointer
     * @param metadata Output metadata structure
     * @return true if parsing was successful, false otherwise
     */
    static bool parseVRRPv2(pcpp::VrrpV2Layer* vrrpLayer, PacketMetadata& metadata);
    
    /**
     * Parse VRRP v3 packet
     * @param vrrpLayer VRRP v3 layer pointer
     * @param metadata Output metadata structure
     * @return true if parsing was successful, false otherwise
     */
    static bool parseVRRPv3(pcpp::VrrpV3Layer* vrrpLayer, PacketMetadata& metadata);
    
    /**
     * Validate VRRP checksum
     * @param vrrpLayer VRRP layer pointer
     * @return true if checksum is valid, false otherwise
     */
    static bool validateChecksum(pcpp::VrrpLayer* vrrpLayer);
    
    /**
     * Validate VRRP checksum manually
     * @param payload VRRP payload data
     * @param payloadSize Size of payload
     * @return true if checksum is valid, false otherwise
     */
    static bool validateChecksumManual(const uint8_t* payload, size_t payloadSize);
    
    /**
     * Extract virtual IP addresses from VRRP packet
     * @param vrrpLayer VRRP layer pointer
     * @param metadata Output metadata structure
     */
    static void extractVirtualIPs(pcpp::VrrpLayer* vrrpLayer, PacketMetadata& metadata);
    
    /**
     * Get VRRP packet type description
     * @param type VRRP packet type
     * @return Human-readable description
     */
    static std::string getTypeDescription(uint8_t type);
    
    /**
     * Get VRRP authentication type description
     * @param authType Authentication type
     * @return Human-readable description
     */
    static std::string getAuthTypeDescription(uint8_t authType);
};

#endif // VRRP_PARSER_H
