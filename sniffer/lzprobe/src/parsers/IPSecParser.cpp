#include "parsers/IPSecParser.h"
#include "parsers/TCPParser.h"
#include "parsers/UDPParser.h"
#include <pcapplusplus/IPSecLayer.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>
#include <iostream>
#include <iomanip>
#include <sstream>

bool IPSecParser::parseESP(pcpp::Packet& packet, PacketMetadata& metadata) {
    auto* espLayer = packet.getLayerOfType<pcpp::ESPLayer>();
    if (!espLayer) {
        return false;
    }
    
    return parseESPLayer(espLayer, metadata);
}

bool IPSecParser::parseAH(pcpp::Packet& packet, PacketMetadata& metadata) {
    auto* ahLayer = packet.getLayerOfType<pcpp::AuthenticationHeaderLayer>();
    if (!ahLayer) {
        return false;
    }
    
    return parseAHLayer(ahLayer, metadata, packet);
}

bool IPSecParser::parse(pcpp::Packet& packet, PacketMetadata& metadata, uint8_t protocol) {
    switch (protocol) {
        case 50: // ESP
            return parseESP(packet, metadata);
        case 51: // AH
            return parseAH(packet, metadata);
        default:
            return false;
    }
}

bool IPSecParser::hasESPLayer(pcpp::Packet& packet) {
    return packet.getLayerOfType<pcpp::ESPLayer>() != nullptr;
}

bool IPSecParser::hasAHLayer(pcpp::Packet& packet) {
    return packet.getLayerOfType<pcpp::AuthenticationHeaderLayer>() != nullptr;
}

std::string IPSecParser::getESPInfoString(const PacketMetadata& metadata) {
    if (!metadata.has_esp) {
        return "No ESP";
    }
    
    std::ostringstream oss;
    oss << "ESP: " << metadata.esp.getInfoString();
    return oss.str();
}

std::string IPSecParser::getAHInfoString(const PacketMetadata& metadata) {
    if (!metadata.has_ah) {
        return "No AH";
    }
    
    std::ostringstream oss;
    oss << "AH: " << metadata.ah.getInfoString();
    return oss.str();
}

std::string IPSecParser::protocolToString(uint8_t protocol) {
    switch (protocol) {
        case 1: return "ICMP";
        case 2: return "IGMP";
        case 6: return "TCP";
        case 17: return "UDP";
        case 41: return "IPv6";
        case 47: return "GRE";
        case 50: return "ESP";
        case 51: return "AH";
        case 58: return "ICMPv6";
        case 89: return "OSPF";
        default: return "Unknown(" + std::to_string(protocol) + ")";
    }
}

bool IPSecParser::parseESPLayer(pcpp::ESPLayer* espLayer, PacketMetadata& metadata) {
    if (!espLayer) {
        return false;
    }
    
    try {
        // Set ESP presence flag
        metadata.has_esp = true;
        metadata.protocol = "ESP";
        
        // Get ESP header using PcapPlusPlus API
        auto* espHeader = espLayer->getESPHeader();
        if (!espHeader) {
            return false;
        }
        
        // Parse ESP header fields
        metadata.esp.spi = ntohl(espHeader->spi);
        metadata.esp.sequence_number = ntohl(espHeader->sequenceNumber);
        
        // Get header length (ESP header is always 8 bytes)
        metadata.esp.header_length = espLayer->getHeaderLen();
        
        // Get payload length (encrypted data)
        metadata.esp.payload_length = espLayer->getLayerPayloadSize();
        
        // ESP trailer information
        // Note: PcapPlusPlus doesn't provide direct access to ESP trailer fields
        // The trailer contains: padding + pad length + next header
        // We can estimate trailer length based on total packet size
        size_t totalLayerSize = espLayer->getDataLen();
        if (totalLayerSize > metadata.esp.header_length + metadata.esp.payload_length) {
            metadata.esp.trailer_length = totalLayerSize - metadata.esp.header_length - metadata.esp.payload_length;
        }
        
        // Try to get next header from the layer's next layer
        auto* nextLayer = espLayer->getNextLayer();
        if (nextLayer) {
            // Map PcapPlusPlus layer types to protocol numbers
            pcpp::ProtocolType protocol = nextLayer->getProtocol();
            if (protocol == pcpp::TCP) {
                metadata.esp.next_header = 6;
            } else if (protocol == pcpp::UDP) {
                metadata.esp.next_header = 17;
            } else if (protocol == pcpp::ICMP) {
                metadata.esp.next_header = 1;
            } else if (protocol == pcpp::IPv4) {
                metadata.esp.next_header = 4;
            } else if (protocol == pcpp::IPv6) {
                metadata.esp.next_header = 41;
            } else if (protocol == pcpp::ESP) {
                metadata.esp.next_header = 50;
            } else if (protocol == pcpp::AuthenticationHeader) {
                metadata.esp.next_header = 51;
            } else if (protocol == pcpp::ICMPv6) {
                metadata.esp.next_header = 58;
            } else {
                metadata.esp.next_header = 0; // Unknown
            }
        }
        
        // ESP payload is always encrypted
        metadata.esp.is_encrypted = true;
        
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "Error parsing ESP layer: " << e.what() << std::endl;
        return false;
    }
}

bool IPSecParser::parseAHLayer(pcpp::AuthenticationHeaderLayer* ahLayer, PacketMetadata& metadata, pcpp::Packet& packet) {
    if (!ahLayer) {
        return false;
    }
    
    try {
        // Set AH presence flag
        metadata.has_ah = true;
        metadata.protocol = "AH";
        
        // Get AH header using PcapPlusPlus API
        auto* ahHeader = ahLayer->getAHHeader();
        if (!ahHeader) {
            return false;
        }
        
        // Parse AH header fields
        metadata.ah.next_header = ahHeader->nextHeader;
        metadata.ah.payload_length = ahHeader->payloadLen;
        metadata.ah.reserved = ntohs(ahHeader->reserved);
        metadata.ah.spi = ntohl(ahHeader->spi);
        metadata.ah.sequence_number = ntohl(ahHeader->sequenceNumber);
        
        // Get header length (variable based on payload_length)
        metadata.ah.header_length = ahLayer->getHeaderLen();
        
        // Get ICV (Integrity Check Value) information
        metadata.ah.icv_length = ahLayer->getICVLength();
        uint8_t* icvBytes = ahLayer->getICVBytes();
        if (icvBytes && metadata.ah.icv_length > 0) {
            metadata.ah.icv_hex = bytesToHexString(icvBytes, metadata.ah.icv_length);
        }
        
        // After AH parsing, check next_header and call appropriate parser
        // AH payload is not encrypted, so we can parse the next protocol
        if (metadata.ah.next_header == 6) {  // TCP
            if (TCPParser::parse(packet, metadata)) {
                // TCP parsing successful, update protocol
                metadata.protocol = "TCP";
                metadata.application_protocol = "ah-tcp";
            }
        } else if (metadata.ah.next_header == 17) {  // UDP
            if (UDPParser::parse(packet, metadata)) {
                // UDP parsing successful, update protocol
                metadata.protocol = "UDP";
                metadata.application_protocol = "ah-udp";
            }
        }
        
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "Error parsing AH layer: " << e.what() << std::endl;
        return false;
    }
}

std::string IPSecParser::bytesToHexString(const uint8_t* data, size_t length) {
    if (!data || length == 0) {
        return "";
    }
    
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    
    for (size_t i = 0; i < length; ++i) {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    
    return oss.str();
}

