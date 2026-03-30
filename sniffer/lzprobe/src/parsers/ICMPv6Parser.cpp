#include "parsers/ICMPv6Parser.h"
#include "parsers/NDPParser.h"
#include <pcapplusplus/IcmpV6Layer.h>
#include <pcapplusplus/IPv6Layer.h>
#include <netinet/in.h>
#include <sstream>
#include <iomanip>

bool ICMPv6Parser::parse(pcpp::Packet& packet, PacketMetadata& metadata) {
    auto* icmpv6Layer = packet.getLayerOfType<pcpp::IcmpV6Layer>();
    if (!icmpv6Layer) {
        return false;
    }

    // Set ICMPv6 presence flag
    metadata.has_icmpv6 = true;
    
    // Parse basic ICMPv6 fields using public getter methods
    metadata.icmpv6.type = static_cast<uint8_t>(icmpv6Layer->getMessageType());
    metadata.icmpv6.code = icmpv6Layer->getCode();
    metadata.icmpv6.checksum = icmpv6Layer->getChecksum();
    
    // Set type and code descriptions
    metadata.icmpv6.type_description = getTypeDescription(metadata.icmpv6.type);
    metadata.icmpv6.code_description = getCodeDescription(metadata.icmpv6.type, metadata.icmpv6.code);
    
    // Validate checksum
    metadata.icmpv6.checksum_valid = validateChecksum(icmpv6Layer);
    
    // Parse specific message types
    switch (metadata.icmpv6.type) {
        case 128: // Echo Request
        case 129: // Echo Reply
            parseEchoMessage(icmpv6Layer, metadata);
            break;
            
        case 1: // Destination Unreachable
            parseDestinationUnreachable(icmpv6Layer, metadata);
            break;
            
        case 2: // Packet Too Big
            parsePacketTooBig(icmpv6Layer, metadata);
            break;
            
        case 3: // Time Exceeded
            parseTimeExceeded(icmpv6Layer, metadata);
            break;
            
        case 4: // Parameter Problem
            parseParameterProblem(icmpv6Layer, metadata);
            break;
            
        case 133: // Router Solicitation
        case 134: // Router Advertisement
            parseRouterDiscovery(icmpv6Layer, metadata);
            // Also call NDP parser for detailed parsing
            NDPParser::parse(packet, metadata);
            break;
            
        case 135: // Neighbor Solicitation
        case 136: // Neighbor Advertisement
            parseNeighborDiscovery(icmpv6Layer, metadata);
            // Also call NDP parser for detailed parsing
            NDPParser::parse(packet, metadata);
            break;
            
        case 137: // Redirect
            // For redirect messages, directly use NDP parser
            NDPParser::parse(packet, metadata);
            break;
            
        default:
            // Unknown message type, just parse basic fields
            break;
    }
    
    return true;
}

void ICMPv6Parser::parseEchoMessage(pcpp::IcmpV6Layer* icmpv6Layer, PacketMetadata& metadata) {
    // Get the raw data after ICMPv6 header
    const uint8_t* payload = icmpv6Layer->getLayerPayload();
    size_t payloadLen = icmpv6Layer->getLayerPayloadSize();
    
    if (payloadLen >= 4) {
        // Echo messages have identifier and sequence number in the first 4 bytes
        metadata.icmpv6.identifier = ntohs(*reinterpret_cast<const uint16_t*>(payload));
        metadata.icmpv6.sequence = ntohs(*reinterpret_cast<const uint16_t*>(payload + 2));
    }
}

void ICMPv6Parser::parseDestinationUnreachable(pcpp::IcmpV6Layer* icmpv6Layer, PacketMetadata& metadata) {
    // Get the raw data after ICMPv6 header
    const uint8_t* payload = icmpv6Layer->getLayerPayload();
    size_t payloadLen = icmpv6Layer->getLayerPayloadSize();
    
    if (payloadLen >= 24) { // IPv6 header (40 bytes) + transport header (8 bytes minimum)
        // The original packet's IPv6 header starts at offset 0
        // Extract the original IPv6 address (bytes 8-23 in IPv6 header)
        if (payloadLen >= 24) {
            memcpy(metadata.icmpv6.original_ipv6, payload + 8, 16);
        }
        
        // Extract the original protocol (byte 6 in IPv6 header)
        if (payloadLen >= 7) {
            metadata.icmpv6.original_protocol = payload[6];
        }
        
        // Extract the original port (if it's TCP/UDP, it's at offset 40+0 and 40+2)
        if (payloadLen >= 42 && (metadata.icmpv6.original_protocol == 6 || metadata.icmpv6.original_protocol == 17)) {
            metadata.icmpv6.original_port = ntohs(*reinterpret_cast<const uint16_t*>(payload + 40));
        }
    }
}

void ICMPv6Parser::parsePacketTooBig(pcpp::IcmpV6Layer* icmpv6Layer, PacketMetadata& metadata) {
    // Get the raw data after ICMPv6 header
    const uint8_t* payload = icmpv6Layer->getLayerPayload();
    size_t payloadLen = icmpv6Layer->getLayerPayloadSize();
    
    if (payloadLen >= 4) {
        // Packet Too Big messages have MTU in the first 4 bytes after the header
        metadata.icmpv6.mtu = ntohl(*reinterpret_cast<const uint32_t*>(payload));
    }
}

void ICMPv6Parser::parseTimeExceeded(pcpp::IcmpV6Layer* icmpv6Layer, PacketMetadata& metadata) {
    // Get the raw data after ICMPv6 header
    const uint8_t* payload = icmpv6Layer->getLayerPayload();
    size_t payloadLen = icmpv6Layer->getLayerPayloadSize();
    
    if (payloadLen >= 4) {
        // Time Exceeded messages have an unused field in the first 4 bytes
        metadata.icmpv6.unused = payload[0];
    }
}

void ICMPv6Parser::parseParameterProblem(pcpp::IcmpV6Layer* icmpv6Layer, PacketMetadata& metadata) {
    // Get the raw data after ICMPv6 header
    const uint8_t* payload = icmpv6Layer->getLayerPayload();
    size_t payloadLen = icmpv6Layer->getLayerPayloadSize();
    
    if (payloadLen >= 4) {
        // Parameter Problem messages have a pointer in the first 4 bytes
        metadata.icmpv6.pointer = payload[0];
    }
}

void ICMPv6Parser::parseNeighborDiscovery(pcpp::IcmpV6Layer* icmpv6Layer, PacketMetadata& metadata) {
    // Get the raw data after ICMPv6 header
    const uint8_t* payload = icmpv6Layer->getLayerPayload();
    size_t payloadLen = icmpv6Layer->getLayerPayloadSize();
    
    if (payloadLen >= 16) {
        // Neighbor discovery messages have target address in the first 16 bytes
        memcpy(metadata.icmpv6.target_address, payload, 16);
    }
    
    // Parse options if present
    if (payloadLen > 16) {
        size_t offset = 16;
        while (offset + 2 <= payloadLen) {
            uint8_t optionType = payload[offset];
            uint8_t optionLength = payload[offset + 1];
            
            if (optionLength == 0 || offset + optionLength * 8 > payloadLen) {
                break;
            }
            
            switch (optionType) {
                case 1: // Source Link-Layer Address
                    if (optionLength * 8 >= 8 && offset + 8 <= payloadLen) {
                        memcpy(metadata.icmpv6.source_link_layer, payload + offset + 2, 6);
                    }
                    break;
                    
                case 2: // Target Link-Layer Address
                    if (optionLength * 8 >= 8 && offset + 8 <= payloadLen) {
                        memcpy(metadata.icmpv6.target_link_layer, payload + offset + 2, 6);
                    }
                    break;
            }
            
            offset += optionLength * 8;
        }
    }
}

void ICMPv6Parser::parseRouterDiscovery(pcpp::IcmpV6Layer* icmpv6Layer, PacketMetadata& metadata) {
    // Get the raw data after ICMPv6 header
    const uint8_t* payload = icmpv6Layer->getLayerPayload();
    size_t payloadLen = icmpv6Layer->getLayerPayloadSize();
    
    if (payloadLen >= 16) {
        // Router discovery messages have various fields in the first 16 bytes
        if (metadata.icmpv6.type == 134) { // Router Advertisement
            // Router lifetime (bytes 0-1)
            metadata.icmpv6.router_lifetime = ntohs(*reinterpret_cast<const uint16_t*>(payload));
            
            // Reachable time (bytes 4-7)
            if (payloadLen >= 8) {
                metadata.icmpv6.reachable_time = ntohl(*reinterpret_cast<const uint32_t*>(payload + 4));
            }
            
            // Retransmission timer (bytes 8-11)
            if (payloadLen >= 12) {
                metadata.icmpv6.retrans_timer = ntohl(*reinterpret_cast<const uint32_t*>(payload + 8));
            }
        }
    }
}

std::string ICMPv6Parser::getTypeDescription(uint8_t type) {
    switch (type) {
        case 1: return "Destination Unreachable";
        case 2: return "Packet Too Big";
        case 3: return "Time Exceeded";
        case 4: return "Parameter Problem";
        case 128: return "Echo Request";
        case 129: return "Echo Reply";
        case 133: return "Router Solicitation";
        case 134: return "Router Advertisement";
        case 135: return "Neighbor Solicitation";
        case 136: return "Neighbor Advertisement";
        case 137: return "Redirect Message";
        case 138: return "Router Renumbering";
        case 139: return "ICMP Node Information Query";
        case 140: return "ICMP Node Information Response";
        case 141: return "Inverse Neighbor Discovery Solicitation";
        case 142: return "Inverse Neighbor Discovery Advertisement";
        case 143: return "Version 2 Multicast Listener Report";
        case 144: return "Home Agent Address Discovery Request";
        case 145: return "Home Agent Address Discovery Reply";
        case 146: return "Mobile Prefix Solicitation";
        case 147: return "Mobile Prefix Advertisement";
        case 148: return "Certification Path Solicitation";
        case 149: return "Certification Path Advertisement";
        case 151: return "Multicast Router Advertisement";
        case 152: return "Multicast Router Solicitation";
        case 153: return "Multicast Router Termination";
        case 155: return "RPL Control Message";
        default: return "Unknown(" + std::to_string(type) + ")";
    }
}

std::string ICMPv6Parser::getCodeDescription(uint8_t type, uint8_t code) {
    switch (type) {
        case 1: // Destination Unreachable
            switch (code) {
                case 0: return "No route to destination";
                case 1: return "Communication with destination administratively prohibited";
                case 2: return "Beyond scope of source address";
                case 3: return "Address unreachable";
                case 4: return "Port unreachable";
                case 5: return "Source address failed ingress/egress policy";
                case 6: return "Reject route to destination";
                case 7: return "Error in Source Routing Header";
                default: return "Unknown(" + std::to_string(code) + ")";
            }
            
        case 2: // Packet Too Big
            return "Packet too big";
            
        case 3: // Time Exceeded
            switch (code) {
                case 0: return "Hop limit exceeded in transit";
                case 1: return "Fragment reassembly time exceeded";
                default: return "Unknown(" + std::to_string(code) + ")";
            }
            
        case 4: // Parameter Problem
            switch (code) {
                case 0: return "Erroneous header field encountered";
                case 1: return "Unrecognized Next Header type encountered";
                case 2: return "Unrecognized IPv6 option encountered";
                default: return "Unknown(" + std::to_string(code) + ")";
            }
            
        case 128: // Echo Request
        case 129: // Echo Reply
            return "Echo message";
            
        case 133: // Router Solicitation
            return "Router solicitation";
            
        case 134: // Router Advertisement
            return "Router advertisement";
            
        case 135: // Neighbor Solicitation
            return "Neighbor solicitation";
            
        case 136: // Neighbor Advertisement
            return "Neighbor advertisement";
            
        default:
            return "Unknown code";
    }
}

bool ICMPv6Parser::validateChecksum(pcpp::IcmpV6Layer* icmpv6Layer) {
    // Note: ICMPv6 checksum validation requires the pseudo-header
    // This is a simplified validation - in practice, you might want to implement
    // the full ICMPv6 checksum calculation including the pseudo-header
    
    // For now, we'll just check if the checksum field is not zero
    return (icmpv6Layer->getChecksum() != 0);
}
