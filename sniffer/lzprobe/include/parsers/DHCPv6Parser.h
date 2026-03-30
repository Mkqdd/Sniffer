#ifndef DHCPV6_PARSER_H
#define DHCPV6_PARSER_H

#include "BaseParser.h"
#include <functional>

/**
 * @brief Parser for DHCPv6 (Dynamic Host Configuration Protocol for IPv6) packets
 * 
 * This parser handles DHCPv6 protocol analysis according to RFC 3315.
 * DHCPv6 operates over UDP with well-known ports:
 * - Port 546: DHCPv6 client (client -> server and server -> client)
 * - Port 547: DHCPv6 server (server -> client and client -> server)
 * 
 * DHCPv6 packet identification:
 * 1. Ethernet layer: EtherType = 0x86DD (IPv6)
 * 2. Network layer: IPv6 next header = 17 (UDP)
 * 3. Transport layer: UDP port 546 (client) or 547 (server)
 * 4. Application layer: DHCPv6 message type field
 */
class DHCPv6Parser : public BaseParser {
public:
    /**
     * @brief Parse DHCPv6 packet and extract metadata
     * @param packet The packet to parse
     * @param metadata The metadata structure to fill
     * @return true if parsing was successful, false otherwise
     */
    static bool parse(pcpp::Packet& packet, PacketMetadata& metadata);

private:
    /**
     * @brief Check if packet is a DHCPv6 packet based on UDP ports
     * @param packet The packet to check
     * @return true if packet uses DHCPv6 ports (546/547)
     */
    static bool isDHCPv6Packet(pcpp::Packet& packet);
    
    /**
     * @brief Validate DHCPv6 packet structure
     * @param data Pointer to DHCPv6 data
     * @param length Length of DHCPv6 data
     * @return true if packet has valid DHCPv6 structure
     */
    static bool validateDHCPv6Packet(const uint8_t* data, size_t length);
    
    /**
     * @brief Parse DHCPv6 header fields
     * @param data Pointer to DHCPv6 data
     * @param metadata The metadata structure to fill
     * @return true if header parsing was successful
     */
    static bool parseHeader(const uint8_t* data, PacketMetadata& metadata);
    
    /**
     * @brief Parse DHCPv6 options (TLV format)
     * @param data Pointer to options data
     * @param length Length of options data
     * @param metadata The metadata structure to fill
     * @return true if options parsing was successful
     */
    static bool parseOptions(const uint8_t* data, size_t length, PacketMetadata& metadata);
    
    /**
     * @brief Convert IPv6 address from uint8_t array to string
     * @param ipv6 Pointer to IPv6 address bytes
     * @return IPv6 address as string
     */
    static std::string ipv6ToString(const uint8_t* ipv6);
    
    /**
     * @brief Convert DUID (DHCP Unique Identifier) to string format
     * @param duid Pointer to DUID bytes
     * @param length Length of DUID
     * @return DUID as string
     */
    static std::string duidToString(const uint8_t* duid, uint16_t length);
    
    /**
     * @brief Get DHCPv6 message type string description
     * @param type DHCPv6 message type code
     * @return Human-readable message type string
     */
    static std::string getMessageTypeString(uint8_t type);

public:
    /**
     * @brief Formats DHCPv6 metadata for CSV output.
     * @param dhcpv6_meta The DHCPv6 metadata to format.
     * @param line The output stream to write to.
     * @param separator The field separator to use.
     */
    static void formatForCSV(const DHCPv6Metadata& dhcpv6_meta, std::ostringstream& line, const std::string& separator);

    /**
     * @brief Formats DHCPv6 metadata for JSON output.
     * @param dhcpv6_meta The DHCPv6 metadata to format.
     * @param oss The output stream to write to.
     * @param escapeJsonString Function to escape JSON strings.
     */
    static void formatForJSON(const DHCPv6Metadata& dhcpv6_meta, std::ostringstream& oss, const std::function<std::string(const std::string&)>& escapeJsonString);

    /**
     * @brief Formats DHCPv6 metadata for console output.
     * @param dhcpv6_meta The DHCPv6 metadata to format.
     * @return Formatted string for console display.
     */
    static std::string formatForConsole(const DHCPv6Metadata& dhcpv6_meta);
};

#endif

