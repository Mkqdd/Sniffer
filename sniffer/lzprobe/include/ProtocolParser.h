#ifndef PROTOCOL_PARSER_H
#define PROTOCOL_PARSER_H

#include "PacketMetadata.h"
#include <pcapplusplus/Packet.h>

/**
 * ProtocolParser - Unified protocol parsing manager
 * 
 * This class implements the complete protocol parsing stack:
 * 
 * Ethernet:
 *   ├── IPv4 (0x0800)
 *   │      ├── TCP / UDP / ...
 *   │      └── GRE (protocol 47) → decapsulate → IPv4 / IPv6 / MPLS / ...
 *   ├── IPv6 (0x86DD)
 *   ├── VLAN (0x8100 / 0x88A8) → extract VLAN tag → read real EtherType
 *   └── Other protocols...
 */
class ProtocolParser {
public:
    /**
     * Parse complete packet stack starting from Ethernet layer
     * @param packet The packet to parse
     * @param metadata Output metadata structure
     * @return true if parsing was successful, false otherwise
     */
    static bool parsePacket(pcpp::Packet& packet, PacketMetadata& metadata);
    
    /**
     * Parse Ethernet layer and determine next protocol
     * @param packet The packet to parse
     * @param metadata Output metadata structure
     * @return true if parsing was successful, false otherwise
     */
    static bool parseEthernet(pcpp::Packet& packet, PacketMetadata& metadata);
    
    /**
     * Parse VLAN layer and extract inner protocol
     * @param packet The packet to parse
     * @param metadata Output metadata structure
     * @return true if parsing was successful, false otherwise
     */
    static bool parseVLAN(pcpp::Packet& packet, PacketMetadata& metadata);
    
    /**
     * Parse GRE layer and handle decapsulation
     * @param packet The packet to parse
     * @param metadata Output metadata structure
     * @return true if parsing was successful, false otherwise
     */
    static bool parseGRE(pcpp::Packet& packet, PacketMetadata& metadata);
    
    /**
     * Parse MPLS layer and label stack
     * @param packet The packet to parse
     * @param metadata Output metadata structure
     * @return true if parsing was successful, false otherwise
     */
    static bool parseMPLS(pcpp::Packet& packet, PacketMetadata& metadata);
    
    /**
     * Parse IPv4 layer and transport protocols
     * @param packet The packet to parse
     * @param metadata Output metadata structure
     * @return true if parsing was successful, false otherwise
     */
    static bool parseIPv4(pcpp::Packet& packet, PacketMetadata& metadata);
    
    /**
     * Parse IPv6 layer and transport protocols
     * @param packet The packet to parse
     * @param metadata Output metadata structure
     * @return true if parsing was successful, false otherwise
     */
    static bool parseIPv6(pcpp::Packet& packet, PacketMetadata& metadata);
    
    /**
     * Parse transport layer protocols (TCP/UDP)
     * @param packet The packet to parse
     * @param metadata Output metadata structure
     * @return true if parsing was successful, false otherwise
     */
    static bool parseTransport(pcpp::Packet& packet, PacketMetadata& metadata);

private:
    /**
     * Parse IPv4 payload from MPLS encapsulated packet
     * @param packet The packet to parse
     * @param metadata Output metadata structure
     * @return true if parsing was successful, false otherwise
     */
    static bool parseMPLSPayloadIPv4(pcpp::Packet& packet, PacketMetadata& metadata);
    
    /**
     * Parse IPv6 payload from MPLS encapsulated packet
     * @param packet The packet to parse
     * @param metadata Output metadata structure
     * @return true if parsing was successful, false otherwise
     */
    static bool parseMPLSPayloadIPv6(pcpp::Packet& packet, PacketMetadata& metadata);
    /**
     * Convert EtherType to string representation
     * @param ethertype The EtherType value
     * @return String representation of the EtherType
     */
    static std::string etherTypeToString(uint16_t ethertype);
    
    /**
     * Convert protocol number to string representation
     * @param protocol The protocol number
     * @return String representation of the protocol
     */
    static std::string protocolToString(uint8_t protocol);
};

#endif // PROTOCOL_PARSER_H 