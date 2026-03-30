#include "parsers/ICMPParser.h"
#include "BaseParser.h"
#include <pcapplusplus/IcmpLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>
#include <netinet/in.h>
#include <cstring>
#include <iostream>

bool ICMPParser::parse(pcpp::Packet& packet, PacketMetadata& metadata) {
    auto* icmpLayer = packet.getLayerOfType<pcpp::IcmpLayer>();
    if (!icmpLayer) {
        return false;
    }

    // Mark that ICMP is present
    metadata.has_icmp = true;
    
    // Get ICMP header
    auto* icmpHeader = icmpLayer->getIcmpHeader();
    if (!icmpHeader) {
        return false;
    }
    
    // Parse basic ICMP fields
    metadata.icmp.type = icmpHeader->type;
    metadata.icmp.code = icmpHeader->code;
    metadata.icmp.checksum = ntohs(icmpHeader->checksum);
    
    // Get type and code descriptions
    metadata.icmp.type_description = getTypeDescription(metadata.icmp.type);
    metadata.icmp.code_description = getCodeDescription(metadata.icmp.type, metadata.icmp.code);
    
    // Validate checksum
    metadata.icmp.checksum_valid = validateChecksum(icmpLayer);
    
    // Parse ICMP message based on type
    switch (metadata.icmp.type) {
        case 0: // Echo Reply
        case 8: // Echo Request
            parseEchoMessage(icmpLayer, metadata);
            break;
        case 3: // Destination Unreachable
            parseDestinationUnreachable(icmpLayer, metadata);
            break;
        case 5: // Redirect
            parseRedirect(icmpLayer, metadata);
            break;
        case 11: // Time Exceeded
            parseTimeExceeded(icmpLayer, metadata);
            break;
        case 12: // Parameter Problem
            parseParameterProblem(icmpLayer, metadata);
            break;
        default:
            // For other ICMP types, we only have basic information
            break;
    }
    
    return true;
}

void ICMPParser::parseEchoMessage(pcpp::IcmpLayer* icmpLayer, PacketMetadata& metadata) {
    // For echo request/reply, the identifier and sequence are in the data section
    // The first 4 bytes after the ICMP header contain: identifier (2 bytes) + sequence (2 bytes)
    if (icmpLayer->getLayerPayloadSize() >= 4) {
        const uint8_t* payload = icmpLayer->getLayerPayload();
        metadata.icmp.identifier = ntohs(*reinterpret_cast<const uint16_t*>(payload));
        metadata.icmp.sequence = ntohs(*reinterpret_cast<const uint16_t*>(payload + 2));
    }
}

void ICMPParser::parseDestinationUnreachable(pcpp::IcmpLayer* icmpLayer, PacketMetadata& metadata) {
    // For destination unreachable, the original IP header and first 8 bytes of original datagram
    // are included in the ICMP payload
    if (icmpLayer->getLayerPayloadSize() >= 28) { // IP header (20) + 8 bytes of original data
        const uint8_t* payload = icmpLayer->getLayerPayload();
        
        // Extract original IP header information
        // The first 20 bytes contain the original IP header
        const uint8_t* originalIpHeader = payload;
        
        // Extract original IP address (bytes 12-15)
        metadata.icmp.original_ip = ntohl(*reinterpret_cast<const uint32_t*>(originalIpHeader + 12));
        
        // Extract original protocol (byte 9)
        metadata.icmp.original_protocol = originalIpHeader[9];
        
        // Extract original port if it's TCP or UDP (bytes 20-21 for source port, 22-23 for dest port)
        // For destination unreachable, we typically use the destination port
        if (metadata.icmp.original_protocol == 6 || metadata.icmp.original_protocol == 17) {
            metadata.icmp.original_port = ntohs(*reinterpret_cast<const uint16_t*>(payload + 22));
        }
    }
}

void ICMPParser::parseRedirect(pcpp::IcmpLayer* icmpLayer, PacketMetadata& metadata) {
    // For redirect messages, the gateway IP is in the data section
    // The first 4 bytes after the ICMP header contain the gateway IP
    if (icmpLayer->getLayerPayloadSize() >= 4) {
        const uint8_t* payload = icmpLayer->getLayerPayload();
        metadata.icmp.gateway_ip = ntohl(*reinterpret_cast<const uint32_t*>(payload));
    }
}

void ICMPParser::parseTimeExceeded(pcpp::IcmpLayer* icmpLayer, PacketMetadata& metadata) {
    // For time exceeded messages, there's an unused field (1 byte) after the checksum
    // This is followed by the original IP header and first 8 bytes of original datagram
    if (icmpLayer->getLayerPayloadSize() >= 1) {
        const uint8_t* payload = icmpLayer->getLayerPayload();
        metadata.icmp.unused = payload[0];
    }
}

void ICMPParser::parseParameterProblem(pcpp::IcmpLayer* icmpLayer, PacketMetadata& metadata) {
    // For parameter problem messages, there's a pointer field (1 byte) after the checksum
    // This is followed by the original IP header and first 8 bytes of original datagram
    if (icmpLayer->getLayerPayloadSize() >= 1) {
        const uint8_t* payload = icmpLayer->getLayerPayload();
        metadata.icmp.pointer = payload[0];
    }
}

std::string ICMPParser::getTypeDescription(uint8_t type) {
    switch (type) {
        case 0: return "Echo Reply";
        case 3: return "Destination Unreachable";
        case 4: return "Source Quench";
        case 5: return "Redirect";
        case 8: return "Echo Request";
        case 9: return "Router Advertisement";
        case 10: return "Router Solicitation";
        case 11: return "Time Exceeded";
        case 12: return "Parameter Problem";
        case 13: return "Timestamp";
        case 14: return "Timestamp Reply";
        case 15: return "Information Request";
        case 16: return "Information Reply";
        case 17: return "Address Mask Request";
        case 18: return "Address Mask Reply";
        default: return "Unknown Type " + std::to_string(type);
    }
}

std::string ICMPParser::getCodeDescription(uint8_t type, uint8_t code) {
    switch (type) {
        case 3: // Destination Unreachable
            switch (code) {
                case 0: return "Network Unreachable";
                case 1: return "Host Unreachable";
                case 2: return "Protocol Unreachable";
                case 3: return "Port Unreachable";
                case 4: return "Fragmentation Needed and Don't Fragment was Set";
                case 5: return "Source Route Failed";
                case 6: return "Destination Network Unknown";
                case 7: return "Destination Host Unknown";
                case 8: return "Source Host Isolated";
                case 9: return "Communication with Destination Network is Administratively Prohibited";
                case 10: return "Communication with Destination Host is Administratively Prohibited";
                case 11: return "Destination Network Unreachable for Type of Service";
                case 12: return "Destination Host Unreachable for Type of Service";
                case 13: return "Communication Administratively Prohibited";
                case 14: return "Host Precedence Violation";
                case 15: return "Precedence Cutoff in Effect";
                default: return "Unknown Code " + std::to_string(code);
            }
        case 5: // Redirect
            switch (code) {
                case 0: return "Redirect Datagram for the Network";
                case 1: return "Redirect Datagram for the Host";
                case 2: return "Redirect Datagram for the Type of Service and Network";
                case 3: return "Redirect Datagram for the Type of Service and Host";
                default: return "Unknown Code " + std::to_string(code);
            }
        case 11: // Time Exceeded
            switch (code) {
                case 0: return "Time to Live exceeded in Transit";
                case 1: return "Fragment Reassembly Time Exceeded";
                default: return "Unknown Code " + std::to_string(code);
            }
        case 12: // Parameter Problem
            switch (code) {
                case 0: return "Pointer indicates the error";
                case 1: return "Missing a Required Option";
                case 2: return "Bad Length";
                default: return "Unknown Code " + std::to_string(code);
            }
        default:
            return "No specific code meaning";
    }
}

bool ICMPParser::validateChecksum(pcpp::IcmpLayer* icmpLayer) {
    // Get the current checksum
    auto* icmpHeader = icmpLayer->getIcmpHeader();
    if (!icmpHeader) {
        return false;
    }
    
    uint16_t originalChecksum = ntohs(icmpHeader->checksum);
    
    // Temporarily set checksum to 0 for calculation
    icmpHeader->checksum = 0;
    
    // Calculate checksum
    uint32_t checksum = 0;
    const uint8_t* data = reinterpret_cast<const uint8_t*>(icmpHeader);
    size_t length = icmpLayer->getHeaderLen() + icmpLayer->getLayerPayloadSize();
    
    // Add 16-bit words
    for (size_t i = 0; i < length; i += 2) {
        if (i + 1 < length) {
            checksum += (data[i] << 8) | data[i + 1];
        } else {
            checksum += data[i] << 8;
        }
    }
    
    // Add carry bits
    while (checksum >> 16) {
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }
    
    // Take one's complement
    uint16_t calculatedChecksum = ~checksum;
    
    // Restore original checksum
    icmpHeader->checksum = htons(originalChecksum);
    
    return (calculatedChecksum == originalChecksum);
} 