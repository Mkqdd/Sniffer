#include "parsers/IgmpParser.h"
#include "BaseParser.h"
#include <pcapplusplus/IgmpLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <netinet/in.h>
#include <cstring>

bool IgmpParser::parse(pcpp::Packet& packet, PacketMetadata& metadata) {
    // First try to use PcapPlusPlus IGMP layer
    auto* igmpLayer = packet.getLayerOfType<pcpp::IgmpLayer>();
    if (!igmpLayer) {
        // Fall back to manual parsing
        return parseManually(packet, metadata);
    }

    // Mark that IGMP is present
    metadata.has_igmp = true;
    
    // Get IGMP header
    auto* igmpHeader = igmpLayer->getIgmpHeader();
    if (!igmpHeader) {
        return false;
    }
    
    // Parse basic IGMP fields
    metadata.igmp.type = igmpHeader->type;
    metadata.igmp.max_response_time = igmpHeader->maxResponseTime;
    metadata.igmp.checksum = ntohs(igmpHeader->checksum);
    metadata.igmp.group_address = ntohl(igmpHeader->groupAddress);
    
    // Determine IGMP version
    metadata.igmp.version = determineIgmpVersion(igmpLayer);
    
    // Get type description
    metadata.igmp.type_description = getTypeDescription(metadata.igmp.type, metadata.igmp.version);
    
    // Validate checksum
    metadata.igmp.checksum_valid = validateChecksum(igmpLayer);
    
    // Parse IGMP message based on type and version
    switch (metadata.igmp.type) {
        case 0x11: // Membership Query
            switch (metadata.igmp.version) {
                case 1:
                    parseV1MembershipQuery(igmpLayer, metadata);
                    break;
                case 2:
                    parseV2MembershipQuery(igmpLayer, metadata);
                    break;
                case 3:
                    parseV3MembershipQuery(igmpLayer, metadata);
                    break;
            }
            break;
        case 0x12: // IGMPv1 Membership Report
            parseV1MembershipReport(igmpLayer, metadata);
            break;
        case 0x16: // IGMPv2 Membership Report
            parseV2MembershipReport(igmpLayer, metadata);
            break;
        case 0x17: // IGMPv2 Leave Group
            parseV2LeaveGroup(igmpLayer, metadata);
            break;
        case 0x22: // IGMPv3 Membership Report
            parseV3MembershipReport(igmpLayer, metadata);
            break;
        default:
            // For other IGMP types, we only have basic information
            break;
    }
    
    return true;
}

bool IgmpParser::parseManually(pcpp::Packet& packet, PacketMetadata& metadata) {
    // Get IPv4 layer to find IGMP payload
    auto* ipv4Layer = packet.getLayerOfType<pcpp::IPv4Layer>();
    if (!ipv4Layer) {
        return false;
    }
    
    // Check if this is an IGMP packet (protocol = 2)
    auto* ipv4Header = ipv4Layer->getIPv4Header();
    if (ipv4Header->protocol != 2) {
        return false;
    }
    
    // Get IGMP payload
    const uint8_t* igmpData = ipv4Layer->getLayerPayload();
    size_t igmpDataLen = ipv4Layer->getLayerPayloadSize();
    
    if (!igmpData || igmpDataLen < 8) {
        return false; // Minimum IGMP message size
    }
    
    // Mark that IGMP is present
    metadata.has_igmp = true;
    
    // Parse basic IGMP header (8 bytes minimum)
    metadata.igmp.type = igmpData[0];
    metadata.igmp.max_response_time = igmpData[1];
    metadata.igmp.checksum = ntohs(*reinterpret_cast<const uint16_t*>(&igmpData[2]));
    metadata.igmp.group_address = ntohl(*reinterpret_cast<const uint32_t*>(&igmpData[4]));
    
    // Determine IGMP version based on type and message structure
    if (metadata.igmp.type == 0x11) { // Membership Query
        if (igmpDataLen >= 12) {
            // Check for IGMPv3 query (has additional fields)
            uint8_t s_flag = igmpData[8] & 0x08;
            uint8_t qrv = igmpData[8] & 0x07;
            uint8_t qqic = igmpData[9];
            uint16_t num_sources = ntohs(*reinterpret_cast<const uint16_t*>(&igmpData[10]));
            
            if (num_sources > 0 || s_flag || qrv != 0 || qqic != 0) {
                metadata.igmp.version = 3;
                metadata.igmp.qrv = qrv;
                metadata.igmp.qqic = qqic;
                metadata.igmp.num_sources = num_sources;
                
                // Parse source addresses if present
                if (num_sources > 0 && igmpDataLen >= 12 + (static_cast<size_t>(num_sources) * 4)) {
                    for (uint16_t i = 0; i < num_sources; ++i) {
                        uint32_t source_addr = ntohl(*reinterpret_cast<const uint32_t*>(&igmpData[12 + i * 4]));
                        metadata.igmp.source_addresses.push_back(source_addr);
                    }
                }
            } else if (metadata.igmp.max_response_time != 0) {
                metadata.igmp.version = 2;
            } else {
                metadata.igmp.version = 1;
            }
        } else if (metadata.igmp.max_response_time != 0) {
            metadata.igmp.version = 2;
        } else {
            metadata.igmp.version = 1;
        }
    } else if (metadata.igmp.type == 0x12) {
        metadata.igmp.version = 1; // IGMPv1 Membership Report
    } else if (metadata.igmp.type == 0x16 || metadata.igmp.type == 0x17) {
        metadata.igmp.version = 2; // IGMPv2 Membership Report or Leave Group
    } else if (metadata.igmp.type == 0x22) {
        metadata.igmp.version = 3; // IGMPv3 Membership Report
        
        // Parse IGMPv3 Report structure
        if (igmpDataLen >= 8) {
            metadata.igmp.reserved = igmpData[1]; // Reserved field in IGMPv3 Report
            // Note: Full IGMPv3 Report parsing would require parsing group records
            // uint16_t num_group_records = ntohs(*reinterpret_cast<const uint16_t*>(&igmpData[6]));
        }
    } else {
        metadata.igmp.version = 2; // Default to IGMPv2 for unknown types
    }
    
    // Get type description
    metadata.igmp.type_description = getTypeDescription(metadata.igmp.type, metadata.igmp.version);
    
    // Calculate and validate checksum
    uint32_t checksum = 0;
    for (size_t i = 0; i < igmpDataLen; i += 2) {
        if (i == 2) {
            // Skip checksum field (set to 0 for calculation)
            continue;
        }
        if (i + 1 < igmpDataLen) {
            checksum += (igmpData[i] << 8) | igmpData[i + 1];
        } else {
            checksum += igmpData[i] << 8;
        }
    }
    
    // Add carry bits
    while (checksum >> 16) {
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }
    
    // Take one's complement
    uint16_t calculatedChecksum = ~checksum;
    metadata.igmp.checksum_valid = (calculatedChecksum == metadata.igmp.checksum);
    
    return true;
}

void IgmpParser::parseV1MembershipQuery(pcpp::IgmpLayer* igmpLayer, PacketMetadata& metadata) {
    // IGMPv1 Query has no additional fields beyond the basic header
    // Group address of 0 indicates general query, non-zero indicates group-specific query
}

void IgmpParser::parseV1MembershipReport(pcpp::IgmpLayer* igmpLayer, PacketMetadata& metadata) {
    // IGMPv1 Report has no additional fields beyond the basic header
    // Group address indicates the group being reported
}

void IgmpParser::parseV2MembershipQuery(pcpp::IgmpLayer* igmpLayer, PacketMetadata& metadata) {
    // IGMPv2 Query uses Max Response Time field
    // Group address of 0 indicates general query, non-zero indicates group-specific query
    // Max Response Time is used by hosts to calculate response delay
}

void IgmpParser::parseV2MembershipReport(pcpp::IgmpLayer* igmpLayer, PacketMetadata& metadata) {
    // IGMPv2 Report has no additional fields beyond the basic header
    // Group address indicates the group being reported
}

void IgmpParser::parseV2LeaveGroup(pcpp::IgmpLayer* igmpLayer, PacketMetadata& metadata) {
    // IGMPv2 Leave Group has no additional fields beyond the basic header
    // Group address indicates the group being left
}

void IgmpParser::parseV3MembershipQuery(pcpp::IgmpLayer* igmpLayer, PacketMetadata& metadata) {
    // IGMPv3 Query has additional fields
    if (igmpLayer->getLayerPayloadSize() >= 4) {
        const uint8_t* payload = igmpLayer->getLayerPayload();
        
        // Parse flags and QRV (Querier's Robustness Variable)
        uint8_t flags_qrv = payload[0];
        metadata.igmp.qrv = flags_qrv & 0x07;
        
        // Parse QQIC (Querier's Query Interval Code)
        metadata.igmp.qqic = payload[1];
        
        // Parse Number of Sources
        metadata.igmp.num_sources = ntohs(*reinterpret_cast<const uint16_t*>(&payload[2]));
        
        // Parse source addresses if present
        if (metadata.igmp.num_sources > 0 && 
            igmpLayer->getLayerPayloadSize() >= 4 + (static_cast<size_t>(metadata.igmp.num_sources) * 4)) {
            for (uint16_t i = 0; i < metadata.igmp.num_sources; ++i) {
                uint32_t source_addr = ntohl(*reinterpret_cast<const uint32_t*>(&payload[4 + i * 4]));
                metadata.igmp.source_addresses.push_back(source_addr);
            }
        }
    }
}

void IgmpParser::parseV3MembershipReport(pcpp::IgmpLayer* igmpLayer, PacketMetadata& metadata) {
    // IGMPv3 Report has a different structure
    // The reserved field is in the Max Response Time position
    auto* igmpHeader = igmpLayer->getIgmpHeader();
    if (igmpHeader) {
        metadata.igmp.reserved = igmpHeader->maxResponseTime;
    }
    
    // Parse number of group records
    if (igmpLayer->getLayerPayloadSize() >= 2) {
        const uint8_t* payload = igmpLayer->getLayerPayload();
        metadata.igmp.num_sources = ntohs(*reinterpret_cast<const uint16_t*>(payload));
        // Note: Full group record parsing would require more complex logic
    }
}

uint8_t IgmpParser::determineIgmpVersion(pcpp::IgmpLayer* igmpLayer) {
    auto* igmpHeader = igmpLayer->getIgmpHeader();
    if (!igmpHeader) {
        return 2; // Default to IGMPv2
    }
    
    switch (igmpHeader->type) {
        case 0x11: // Membership Query
            // Check payload size and content to determine version
            if (igmpLayer->getLayerPayloadSize() >= 4) {
                const uint8_t* payload = igmpLayer->getLayerPayload();
                uint16_t num_sources = ntohs(*reinterpret_cast<const uint16_t*>(&payload[2]));
                if (num_sources > 0 || payload[0] != 0 || payload[1] != 0) {
                    return 3; // IGMPv3
                }
            }
            return (igmpHeader->maxResponseTime != 0) ? 2 : 1;
            
        case 0x12: // IGMPv1 Membership Report
            return 1;
            
        case 0x16: // IGMPv2 Membership Report
        case 0x17: // IGMPv2 Leave Group
            return 2;
            
        case 0x22: // IGMPv3 Membership Report
            return 3;
            
        default:
            return 2; // Default to IGMPv2
    }
}

std::string IgmpParser::getTypeDescription(uint8_t type, uint8_t version) {
    switch (type) {
        case 0x11:
            switch (version) {
                case 1: return "IGMPv1 Membership Query";
                case 2: return "IGMPv2 Membership Query";
                case 3: return "IGMPv3 Membership Query";
                default: return "IGMP Membership Query";
            }
        case 0x12:
            return "IGMPv1 Membership Report";
        case 0x16:
            return "IGMPv2 Membership Report";
        case 0x17:
            return "IGMPv2 Leave Group";
        case 0x22:
            return "IGMPv3 Membership Report";
        default:
            return "Unknown IGMP Type " + std::to_string(type);
    }
}

bool IgmpParser::validateChecksum(pcpp::IgmpLayer* igmpLayer) {
    auto* igmpHeader = igmpLayer->getIgmpHeader();
    if (!igmpHeader) {
        return false;
    }
    
    uint16_t originalChecksum = ntohs(igmpHeader->checksum);
    
    // Calculate checksum without modifying the original data
    uint32_t checksum = 0;
    const uint8_t* data = reinterpret_cast<const uint8_t*>(igmpHeader);
    size_t length = igmpLayer->getHeaderLen() + igmpLayer->getLayerPayloadSize();
    
    // Add 16-bit words, skipping the checksum field
    for (size_t i = 0; i < length; i += 2) {
        if (i == 2) {
            // Skip checksum field (bytes 2-3) by setting it to 0 in calculation
            checksum += 0;
        } else if (i + 1 < length) {
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
    
    return (calculatedChecksum == originalChecksum);
}

void* IgmpParser::getIPv4Layer(pcpp::Packet& packet) {
    return packet.getLayerOfType<pcpp::IPv4Layer>();
}

std::string IgmpParser::getGroupAddressString(const IGMPMetadata& igmp_meta) {
    struct in_addr addr;
    addr.s_addr = htonl(igmp_meta.group_address);
    return inet_ntoa(addr);
}

std::string IgmpParser::getSourceAddressString(uint32_t addr) {
    struct in_addr in_addr_val;
    in_addr_val.s_addr = htonl(addr);
    return inet_ntoa(in_addr_val);
}
