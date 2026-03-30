#include "parsers/VRRPParser.h"
#include <pcapplusplus/VrrpLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>
#include <netinet/in.h>
#include <cstring>
#include <sstream>
#include <iomanip>

bool VRRPParser::parse(pcpp::Packet& packet, PacketMetadata& metadata) {
    // Try to get VRRP v2 layer first
    auto* vrrpv2Layer = packet.getLayerOfType<pcpp::VrrpV2Layer>();
    if (vrrpv2Layer) {
        metadata.has_vrrp = true;
        metadata.protocol = "VRRP";
        return parseVRRPv2(vrrpv2Layer, metadata);
    }
    
    // Try to get VRRP v3 layer
    auto* vrrpv3Layer = packet.getLayerOfType<pcpp::VrrpV3Layer>();
    if (vrrpv3Layer) {
        metadata.has_vrrp = true;
        metadata.protocol = "VRRP";
        return parseVRRPv3(vrrpv3Layer, metadata);
    }
    
    // If neither VRRP v2 nor v3 layer is found, try to parse manually
    // This handles cases where PcapPlusPlus doesn't automatically detect VRRP
    auto* ipv4Layer = packet.getLayerOfType<pcpp::IPv4Layer>();
    if (ipv4Layer && ipv4Layer->getIPv4Header()->protocol == 112) {
        // Protocol 112 is VRRP, parse manually
        metadata.has_vrrp = true;
        metadata.protocol = "VRRP";
        
        // Get the payload after IP header
        const uint8_t* payload = ipv4Layer->getLayerPayload();
        size_t payloadSize = ipv4Layer->getLayerPayloadSize();
        
        if (payloadSize >= 8) { // Minimum VRRP header size
            // Parse VRRP header manually
            uint8_t version = (payload[0] >> 4) & 0x0F;
            uint8_t type = payload[1];
            uint8_t virtualRouterId = payload[2];
            uint8_t priority = payload[3];
            uint8_t countIP = payload[4];
            uint8_t authType = payload[5];
            uint8_t adverInt = payload[6];
            uint16_t checksum = ntohs(*reinterpret_cast<const uint16_t*>(&payload[7]));
            
            // Set basic VRRP metadata
            metadata.vrrp.version = version;
            metadata.vrrp.type = type;
            metadata.vrrp.virtual_router_id = virtualRouterId;
            metadata.vrrp.priority = priority;
            metadata.vrrp.count_ip = countIP;
            metadata.vrrp.auth_type = authType;
            metadata.vrrp.adver_int = adverInt;
            metadata.vrrp.checksum = checksum;
            
            // Extract virtual IP addresses
            if (payloadSize >= 8 + static_cast<size_t>(countIP) * 4) {
                for (size_t i = 0; i < static_cast<size_t>(countIP); i++) {
                    uint32_t vip = ntohl(*reinterpret_cast<const uint32_t*>(&payload[8 + i * 4]));
                    metadata.vrrp.virtual_ips.push_back(vip);
                }
            }
            
            // Validate checksum
            metadata.vrrp.checksum_valid = validateChecksumManual(payload, payloadSize);
            
            return true;
        }
    }
    
    return false;
}

bool VRRPParser::parseVRRPv2(pcpp::VrrpV2Layer* vrrpLayer, PacketMetadata& metadata) {
    if (!vrrpLayer) {
        return false;
    }
    
    // Parse VRRP v2 fields using public methods
    metadata.vrrp.version = 2;
    metadata.vrrp.type = static_cast<uint8_t>(vrrpLayer->getType());
    metadata.vrrp.virtual_router_id = vrrpLayer->getVirtualRouterID();
    metadata.vrrp.priority = vrrpLayer->getPriority();
    metadata.vrrp.count_ip = vrrpLayer->getIPAddressesCount();
    metadata.vrrp.auth_type = vrrpLayer->getAuthType();
    metadata.vrrp.adver_int = vrrpLayer->getAdvInt();
    metadata.vrrp.checksum = vrrpLayer->getChecksum();
    
    // Extract virtual IP addresses
    extractVirtualIPs(vrrpLayer, metadata);
    
    // Validate checksum
    metadata.vrrp.checksum_valid = vrrpLayer->isChecksumCorrect();
    
    return true;
}

bool VRRPParser::parseVRRPv3(pcpp::VrrpV3Layer* vrrpLayer, PacketMetadata& metadata) {
    if (!vrrpLayer) {
        return false;
    }
    
    // Parse VRRP v3 fields using public methods
    metadata.vrrp.version = 3;
    metadata.vrrp.type = static_cast<uint8_t>(vrrpLayer->getType());
    metadata.vrrp.virtual_router_id = vrrpLayer->getVirtualRouterID();
    metadata.vrrp.priority = vrrpLayer->getPriority();
    metadata.vrrp.count_ip = vrrpLayer->getIPAddressesCount();
    metadata.vrrp.auth_type = 0; // VRRP v3 doesn't have auth type
    metadata.vrrp.adver_int = 0; // VRRP v3 uses maxAdvInt instead
    metadata.vrrp.checksum = vrrpLayer->getChecksum();
    
    // VRRP v3 specific fields
    metadata.vrrp.max_adver_int = vrrpLayer->getMaxAdvInt();
    metadata.vrrp.reserved = 0;
    
    // Extract virtual IP addresses
    extractVirtualIPs(vrrpLayer, metadata);
    
    // Validate checksum
    metadata.vrrp.checksum_valid = vrrpLayer->isChecksumCorrect();
    
    return true;
}

bool VRRPParser::validateChecksum(pcpp::VrrpLayer* vrrpLayer) {
    if (!vrrpLayer) {
        return false;
    }
    
    // PcapPlusPlus should handle checksum validation 
    // 
    // automatically
    // For manual validation, we would need to recalculate the checksum
    // This is a simplified implementation
    return true;
}

bool VRRPParser::validateChecksumManual(const uint8_t* payload, size_t payloadSize) {
    // Manual checksum validation for VRRP packets
    // This is a simplified implementation - in practice, you'd want to implement
    // proper checksum calculation and validation
    
    if (payloadSize < 8) {
        return false;
    }
    
    // For now, return true as a placeholder
    // TODO: Implement proper checksum validation
    return true;
}

void VRRPParser::extractVirtualIPs(pcpp::VrrpLayer* vrrpLayer, PacketMetadata& metadata) {
    if (!vrrpLayer) {
        return;
    }
    
    // Clear existing virtual IPs
    metadata.vrrp.virtual_ips.clear();
    
    // Get virtual IP addresses using pcapplusplus methods
    std::vector<pcpp::IPAddress> ipAddresses = vrrpLayer->getIPAddresses();
    
    for (const auto& ipAddr : ipAddresses) {
        if (ipAddr.getType() == pcpp::IPAddress::IPv4AddressType) {
            uint32_t ipv4 = ipAddr.getIPv4().toInt();
            metadata.vrrp.virtual_ips.push_back(ipv4);
        }
        // Note: VRRP v3 can also support IPv6, but for now we focus on IPv4
    }
}

std::string VRRPParser::getTypeDescription(uint8_t type) {
    switch (type) {
        case 1:
            return "Advertisement";
        case 2:
            return "Master Down";
        case 3:
            return "Master Down Response";
        default:
            return "Unknown(" + std::to_string(type) + ")";
    }
}

std::string VRRPParser::getAuthTypeDescription(uint8_t authType) {
    switch (authType) {
        case 0:
            return "No Authentication";
        case 1:
            return "Simple Password";
        case 2:
            return "MD5";
        default:
            return "Unknown(" + std::to_string(authType) + ")";
    }
}
