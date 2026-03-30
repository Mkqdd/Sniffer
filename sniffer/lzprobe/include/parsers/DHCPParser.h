#ifndef DHCP_PARSER_H
#define DHCP_PARSER_H

#include "BaseParser.h"
#include <functional>

/**
 * @brief Parser for DHCP (Dynamic Host Configuration Protocol) packets
 * 
 * This parser handles DHCP protocol analysis according to RFC 2131.
 * DHCP operates over UDP with well-known ports:
 * - Port 67: DHCP server (server -> client and client -> server)  
 * - Port 68: DHCP client (client -> server and server -> client)
 * 
 * DHCP packet identification:
 * 1. Ethernet layer: EtherType = 0x0800 (IPv4)
 * 2. Network layer: IP protocol = 17 (UDP)
 * 3. Transport layer: UDP port 67 (server) or 68 (client)
 * 4. Application layer: DHCP magic cookie (0x63825363)
 */
class DHCPParser : public BaseParser {
public:
    /**
     * @brief Parse DHCP packet and extract metadata
     * @param packet The packet to parse
     * @param metadata The metadata structure to fill
     * @return true if parsing was successful, false otherwise
     */
    static bool parse(pcpp::Packet& packet, PacketMetadata& metadata);

private:
    /**
     * @brief Check if packet is a DHCP packet based on UDP ports
     * @param packet The packet to check
     * @return true if packet uses DHCP ports (67/68)
     */
    static bool isDHCPPacket(pcpp::Packet& packet);
    
    /**
     * @brief Validate DHCP packet structure and magic cookie
     * @param data Pointer to DHCP data
     * @param length Length of DHCP data
     * @return true if packet has valid DHCP structure
     */
    static bool validateDHCPPacket(const uint8_t* data, size_t length);
    
    /**
     * @brief Parse DHCP header fields
     * @param data Pointer to DHCP data
     * @param metadata The metadata structure to fill
     * @return true if header parsing was successful
     */
    static bool parseHeader(const uint8_t* data, PacketMetadata& metadata);
    
    /**
     * @brief Parse DHCP options (TLV format)
     * @param data Pointer to options data
     * @param length Length of options data
     * @param metadata The metadata structure to fill
     * @return true if options parsing was successful
     */
    static bool parseOptions(const uint8_t* data, size_t length, PacketMetadata& metadata);
    
    /**
     * @brief Convert IP address from uint32_t to string
     * @param ip IP address in network byte order
     * @return IP address as string
     */
    static std::string ipToString(uint32_t ip);
    
    /**
     * @brief Convert MAC address to string format
     * @param mac Pointer to MAC address bytes
     * @param length Length of MAC address
     * @return MAC address as string
     */
    static std::string macToString(const uint8_t* mac, uint8_t length);
    
    /**
     * @brief Get DHCP message type string description
     * @param type DHCP message type code
     * @return Human-readable message type string
     */
    static std::string getMessageTypeString(uint8_t type);

public:
    /**
     * @brief Formats DHCP metadata for CSV output.
     * @param dhcp_meta The DHCP metadata to format.
     * @param line The output stream to write to.
     * @param separator The field separator to use.
     */
    static void formatForCSV(const DHCPMetadata& dhcp_meta, std::ostringstream& line, const std::string& separator);

    /**
     * @brief Formats DHCP metadata for JSON output.
     * @param dhcp_meta The DHCP metadata to format.
     * @param oss The output stream to write to.
     * @param escapeJsonString Function to escape JSON strings.
     */
    static void formatForJSON(const DHCPMetadata& dhcp_meta, std::ostringstream& oss, const std::function<std::string(const std::string&)>& escapeJsonString);

    /**
     * @brief Formats DHCP metadata for console output.
     * @param dhcp_meta The DHCP metadata to format.
     * @return Formatted string for console display.
     */
    static std::string formatForConsole(const DHCPMetadata& dhcp_meta);
};

#endif
