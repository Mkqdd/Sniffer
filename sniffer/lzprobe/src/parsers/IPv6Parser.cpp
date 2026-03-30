#include "parsers/IPv6Parser.h"
#include "parsers/GREParser.h"
#include "parsers/ICMPParser.h"
#include "parsers/ICMPv6Parser.h"
#include "parsers/IPSecParser.h"
#include <pcapplusplus/IPv6Layer.h>
#include <netinet/in.h>
#include <sstream>
#include <iomanip>

bool IPv6Parser::parse(pcpp::Packet& packet, PacketMetadata& metadata) {
    auto* ipv6Layer = packet.getLayerOfType<pcpp::IPv6Layer>();
    if (!ipv6Layer) {
        return false;
    }

    // Set IPv6 presence flag and parse IPv6 addresses
    metadata.has_ipv6 = true;
    metadata.ipv6.src_ip = ipv6Layer->getSrcIPAddress().toString();
    metadata.ipv6.dst_ip = ipv6Layer->getDstIPAddress().toString();
    
    // Legacy fields for backward compatibility
    metadata.srcIP = metadata.ipv6.src_ip;
    metadata.dstIP = metadata.ipv6.dst_ip;
    metadata.protocol = "IPv6";

    // Get IPv6 header
    auto* ipv6Header = ipv6Layer->getIPv6Header();
    
    // Parse IPv6 header fields
    metadata.ipv6.next_header = ipv6Header->nextHeader;
    metadata.ipv6.hop_limit = ipv6Header->hopLimit;
    
    // Parse traffic class and flow label from the version field
    // These are stored in the first 4 bytes of the IPv6 header
    uint32_t version_traffic_flow = ntohl(*reinterpret_cast<const uint32_t*>(ipv6Header));
    metadata.ipv6.traffic_class = (version_traffic_flow >> 20) & 0xFF;
    metadata.ipv6.flow_label = version_traffic_flow & 0xFFFFF;
    
    // Parse payload length
    metadata.ipv6.payload_length = ntohs(ipv6Header->payloadLength);

    // Parse extension headers
    parseExtensionHeaders(packet, metadata);

    // Parse next header protocol
    switch (metadata.ipv6.next_header) {
        case 6:  // TCP
            metadata.protocol = "TCP";
            break;
        case 17: // UDP
            metadata.protocol = "UDP";
            break;
        case 47: // GRE
            metadata.protocol = "GRE";
            // Parse GRE layer after IPv6
            if (GREParser::parse(packet, metadata)) {
                // After GRE parsing, we might need to parse the encapsulated protocol
                // This depends on the GRE protocol field
            }
            break;
        case 58: // ICMPv6
            metadata.protocol = "ICMPv6";
            // Parse ICMPv6 layer after IPv6
            ICMPv6Parser::parse(packet, metadata);
            break;
        default:
            metadata.protocol = "Unknown";
            break;
    }

    // Set packet length information
    metadata.packet_length = packet.getRawPacket()->getRawDataLen();
    metadata.payload_length = ipv6Layer->getLayerPayloadSize();

    return true;
}

std::string IPv6Parser::ipv6ToString(const uint8_t* ipv6) {
    std::ostringstream oss;
    for (int i = 0; i < 16; i++) {
        if (i > 0) oss << ":";
        oss << std::hex << std::setw(2) << std::setfill('0') 
            << static_cast<int>(ipv6[i]);
    }
    return oss.str();
}

void IPv6Parser::parseExtensionHeaders(pcpp::Packet& packet, PacketMetadata& metadata) {
    auto* ipv6Layer = packet.getLayerOfType<pcpp::IPv6Layer>();
    if (!ipv6Layer) {
        return;
    }
    
    // Get the raw data after IPv6 header
    const uint8_t* extensionData = ipv6Layer->getLayerPayload();
    size_t extensionDataLen = ipv6Layer->getLayerPayloadSize();
    
    if (!extensionData || extensionDataLen == 0) {
        return;
    }
    
    uint8_t nextHeader = metadata.ipv6.next_header;
    size_t offset = 0;
    
    // Parse extension headers until we reach a transport layer protocol
    while (offset < extensionDataLen && isExtensionHeader(nextHeader)) {
        if (offset + 8 > extensionDataLen) {
            break; // Not enough data for extension header
        }
        
        uint8_t headerType = nextHeader;
        uint8_t headerLength = extensionData[offset + 1];
        size_t headerTotalLength = (headerLength + 1) * 8; // Length in 8-octet units
        
        if (offset + headerTotalLength > extensionDataLen) {
            break; // Not enough data for complete header
        }
        
        // Parse specific extension header based on type
        switch (headerType) {
            case 0: // Hop-by-Hop Options
                metadata.ipv6.hop_by_hop.present = true;
                metadata.ipv6.hop_by_hop.type = headerType;
                metadata.ipv6.hop_by_hop.length = headerLength;
                metadata.ipv6.hop_by_hop.description = "Hop-by-Hop Options";
                break;
                
            case 43: // Routing
                metadata.ipv6.routing.present = true;
                metadata.ipv6.routing.type = headerType;
                metadata.ipv6.routing.length = headerLength;
                metadata.ipv6.routing.description = "Routing";
                
                // Parse routing-specific fields if enough data
                if (headerTotalLength >= 8) {
                    metadata.ipv6.routing_type = extensionData[offset + 2];
                    metadata.ipv6.segments_left = extensionData[offset + 3];
                }
                break;
                
            case 44: // Fragment
                metadata.ipv6.fragment.present = true;
                metadata.ipv6.fragment.type = headerType;
                metadata.ipv6.fragment.length = headerLength;
                metadata.ipv6.fragment.description = "Fragment";
                
                // Parse fragment-specific fields if enough data
                if (headerTotalLength >= 8) {
                    uint32_t fragment_data = ntohl(*reinterpret_cast<const uint32_t*>(&extensionData[offset + 4]));
                    metadata.ipv6.fragment_offset = (fragment_data >> 3) & 0x1FFF; // 13 bits
                    metadata.ipv6.fragment_more = (fragment_data & 0x100) != 0;   // 1 bit
                    metadata.ipv6.fragment_id = fragment_data & 0xFFFF;           // 32 bits
                }
                break;
                
            case 60: // Destination Options
                metadata.ipv6.destination.present = true;
                metadata.ipv6.destination.type = headerType;
                metadata.ipv6.destination.length = headerLength;
                metadata.ipv6.destination.description = "Destination Options";
                break;
                
            case 51: // Authentication Header (AH)
                metadata.ipv6.ah.present = true;
                metadata.ipv6.ah.type = headerType;
                metadata.ipv6.ah.length = headerLength;
                metadata.ipv6.ah.description = "Authentication Header";
                // Parse AH layer
                if (IPSecParser::parseAH(packet, metadata)) {
                    metadata.protocol = "AH";
                }
                break;
                
            case 50: // Encapsulating Security Payload (ESP)
                metadata.ipv6.esp.present = true;
                metadata.ipv6.esp.type = headerType;
                metadata.ipv6.esp.length = headerLength;
                metadata.ipv6.esp.description = "Encapsulating Security Payload";
                // Parse ESP layer
                if (IPSecParser::parseESP(packet, metadata)) {
                    metadata.protocol = "ESP";
                }
                break;
        }
        
        // Move to next header
        nextHeader = extensionData[offset];
        offset += headerTotalLength;
    }
    
    // Update the final next header after processing all extension headers
    metadata.ipv6.next_header = nextHeader;
}

bool IPv6Parser::isExtensionHeader(uint8_t nextHeader) {
    // Check if the next header is an extension header
    // Extension headers have values: 0, 43, 44, 50, 51, 60, 135, 139, 140, 253, 254
    switch (nextHeader) {
        case 0:   // Hop-by-Hop Options
        case 43:  // Routing
        case 44:  // Fragment
        case 50:  // ESP
        case 51:  // AH
        case 60:  // Destination Options
        case 135: // Mobility
        case 139: // Host Identity Protocol
        case 140: // Shim6 Protocol
        case 253: // Use for experimentation and testing
        case 254: // Use for experimentation and testing
            return true;
        default:
            return false;
    }
}
