#ifndef IPSEC_PARSER_H
#define IPSEC_PARSER_H

#include "PacketMetadata.h"
#include <pcapplusplus/IPSecLayer.h>
#include <pcapplusplus/Packet.h>

/**
 * @class IPSecParser
 * @brief Parser for IPSec ESP and AH protocols using PcapPlusPlus IPSecLayer API
 * 
 * This parser handles both ESP (Encapsulating Security Payload) and AH (Authentication Header)
 * protocols as defined in RFC 4303 and RFC 4302 respectively.
 * 
 * ESP (Protocol 50):
 * - Provides encryption, authentication, and anti-replay protection
 * - Header: SPI (4 bytes) + Sequence Number (4 bytes) = 8 bytes
 * - Payload is encrypted
 * - Trailer contains padding, pad length, and next header
 * 
 * AH (Protocol 51):
 * - Provides authentication and anti-replay protection (no encryption)
 * - Header: Next Header (1) + Payload Len (1) + Reserved (2) + SPI (4) + Seq Num (4) = 12 bytes
 * - Variable length ICV (Integrity Check Value) based on authentication algorithm
 * - Payload is not encrypted
 */
class IPSecParser {
public:
    /**
     * @brief Parse IPSec ESP packet
     * @param packet PcapPlusPlus packet object
     * @param metadata PacketMetadata object to store parsed information
     * @return true if ESP parsing was successful, false otherwise
     */
    static bool parseESP(pcpp::Packet& packet, PacketMetadata& metadata);
    
    /**
     * @brief Parse IPSec AH packet
     * @param packet PcapPlusPlus packet object
     * @param metadata PacketMetadata object to store parsed information
     * @return true if AH parsing was successful, false otherwise
     */
    static bool parseAH(pcpp::Packet& packet, PacketMetadata& metadata);
    
    /**
     * @brief Parse IPSec packet (ESP or AH) based on protocol type
     * @param packet PcapPlusPlus packet object
     * @param metadata PacketMetadata object to store parsed information
     * @param protocol Protocol number (50 for ESP, 51 for AH)
     * @return true if parsing was successful, false otherwise
     */
    static bool parse(pcpp::Packet& packet, PacketMetadata& metadata, uint8_t protocol);
    
    /**
     * @brief Check if packet contains ESP layer
     * @param packet PcapPlusPlus packet object
     * @return true if packet contains ESP layer, false otherwise
     */
    static bool hasESPLayer(pcpp::Packet& packet);
    
    /**
     * @brief Check if packet contains AH layer
     * @param packet PcapPlusPlus packet object
     * @return true if packet contains AH layer, false otherwise
     */
    static bool hasAHLayer(pcpp::Packet& packet);
    
    /**
     * @brief Get ESP information as string
     * @param metadata PacketMetadata object containing ESP information
     * @return formatted string with ESP information
     */
    static std::string getESPInfoString(const PacketMetadata& metadata);
    
    /**
     * @brief Get AH information as string
     * @param metadata PacketMetadata object containing AH information
     * @return formatted string with AH information
     */
    static std::string getAHInfoString(const PacketMetadata& metadata);
    
    /**
     * @brief Convert protocol number to string
     * @param protocol Protocol number
     * @return protocol name as string
     */
    static std::string protocolToString(uint8_t protocol);

private:
    /**
     * @brief Parse ESP layer using PcapPlusPlus ESPLayer
     * @param espLayer PcapPlusPlus ESPLayer object
     * @param metadata PacketMetadata object to store parsed information
     * @return true if parsing was successful, false otherwise
     */
    static bool parseESPLayer(pcpp::ESPLayer* espLayer, PacketMetadata& metadata);
    
    /**
     * @brief Parse AH layer using PcapPlusPlus AuthenticationHeaderLayer
     * @param ahLayer PcapPlusPlus AuthenticationHeaderLayer object
     * @param metadata PacketMetadata object to store parsed information
     * @return true if parsing was successful, false otherwise
     */
    static bool parseAHLayer(pcpp::AuthenticationHeaderLayer* ahLayer, PacketMetadata& metadata, pcpp::Packet& packet);
    
    /**
     * @brief Convert bytes to hex string
     * @param data Pointer to data bytes
     * @param length Number of bytes to convert
     * @return hex string representation
     */
    static std::string bytesToHexString(const uint8_t* data, size_t length);
};

#endif // IPSEC_PARSER_H

