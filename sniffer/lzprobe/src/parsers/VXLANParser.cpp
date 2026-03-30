#include "parsers/VXLANParser.h"
#include <pcapplusplus/UdpLayer.h>
#include <pcapplusplus/VxlanLayer.h>
#include <pcapplusplus/EthLayer.h>
#include "LoggerManager.h"

bool VXLANParser::parse(pcpp::Packet& packet, PacketMetadata& metadata) {
    // First check if this is a VXLAN packet
    if (!isVXLANPacket(packet)) {
        return false;
    }
    
    auto* udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
    if (!udpLayer) {
        return false;
    }
    
    // Check if UDP destination port is VXLAN port (4789)
    if (udpLayer->getDstPort() != VXLAN_PORT) {
        return false;
    }
    
    // Try to get VXLAN layer
    auto* vxlanLayer = packet.getLayerOfType<pcpp::VxlanLayer>();
    if (!vxlanLayer) {
        // If PcapPlusPlus doesn't have VXLAN layer, we need to parse manually
        return parseManualVXLAN(packet, metadata);
    }
    
    // Parse VXLAN header using PcapPlusPlus
    return parsePcapPlusPlusVXLAN(packet, metadata);
}

bool VXLANParser::isVXLANPacket(pcpp::Packet& packet) {
    auto* udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
    if (!udpLayer) {
        return false;
    }
    
    // Check if destination port is VXLAN port (4789)
    return udpLayer->getDstPort() == VXLAN_PORT;
}

bool VXLANParser::parseEncapsulatedEthernet(pcpp::Packet& packet, PacketMetadata& metadata) {
    // Get UDP layer to find VXLAN payload
    auto* udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
    if (!udpLayer) {
        return false;
    }
    
    // Get VXLAN payload (UDP payload)
    uint8_t* vxlanPayload = udpLayer->getLayerPayload();
    size_t vxlanPayloadSize = udpLayer->getLayerPayloadSize();
    
    // Check if we have enough data for VXLAN header + minimal Ethernet frame
    if (vxlanPayloadSize < VXLAN_HEADER_SIZE + 14) { // 14 bytes for minimal Ethernet frame
        return false;
    }
    
    // Skip VXLAN header (8 bytes) and get encapsulated Ethernet frame
    uint8_t* ethernetFrame = vxlanPayload + VXLAN_HEADER_SIZE;
    size_t ethernetFrameSize = vxlanPayloadSize - VXLAN_HEADER_SIZE;
    
    // Manually parse the encapsulated Ethernet frame
    if (ethernetFrameSize >= 14) { // Minimum Ethernet frame size
        // Parse destination MAC (first 6 bytes)
        memcpy(metadata.ethernet.dst_mac, ethernetFrame, 6);
        
        // Parse source MAC (next 6 bytes)
        memcpy(metadata.ethernet.src_mac, ethernetFrame + 6, 6);
        
        // Parse EtherType (next 2 bytes)
        metadata.ethernet.ethertype = (ethernetFrame[12] << 8) | ethernetFrame[13];
        
        // Mark that we have Ethernet
        metadata.has_ethernet = true;
        
        // Mark that we have VXLAN
        metadata.has_vxlan = true;
        
        return true;
    }
    
    return false;
}

bool VXLANParser::parseManualVXLAN(pcpp::Packet& packet, PacketMetadata& metadata) {
    auto* udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
    if (!udpLayer) {
        return false;
    }
    
    uint8_t* vxlanPayload = udpLayer->getLayerPayload();
    size_t vxlanPayloadSize = udpLayer->getLayerPayloadSize();
    
    // Check if we have enough data for VXLAN header
    if (vxlanPayloadSize < VXLAN_HEADER_SIZE) {
        return false;
    }
    
    // Parse VXLAN header manually
    // VXLAN header structure (8 bytes):
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |R|R|R|R|I|R|R|R|           Reserved                            |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                VXLAN Network Identifier (VNI) |   Reserved    |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    
    // Parse flags (first byte)
    uint8_t flags = vxlanPayload[0];
    metadata.vxlan.flags = flags;
    metadata.vxlan.i_bit = (flags & 0x08) != 0;  // I bit is bit 3 (0x08)
    metadata.vxlan.r_bit = (flags & 0x80) != 0;  // R bit is bit 7 (0x80)
    metadata.vxlan.r_bit2 = (flags & 0x40) != 0; // R bit 2 is bit 6 (0x40)
    metadata.vxlan.r_bit3 = (flags & 0x20) != 0; // R bit 3 is bit 5 (0x20)
    metadata.vxlan.r_bit4 = (flags & 0x10) != 0; // R bit 4 is bit 4 (0x10)
    metadata.vxlan.r_bit5 = (flags & 0x04) != 0; // R bit 5 is bit 2 (0x04)
    metadata.vxlan.r_bit6 = (flags & 0x02) != 0; // R bit 6 is bit 1 (0x02)
    metadata.vxlan.r_bit7 = (flags & 0x01) != 0; // R bit 7 is bit 0 (0x01)
    
    // Parse reserved fields
    metadata.vxlan.reserved1 = vxlanPayload[1];
    metadata.vxlan.reserved2 = (vxlanPayload[2] << 8) | vxlanPayload[3];
    
    // Parse VNI (24 bits, bytes 4-6)
    metadata.vxlan.vni = (vxlanPayload[4] << 16) | (vxlanPayload[5] << 8) | vxlanPayload[6];
    
    // Parse last reserved field
    metadata.vxlan.reserved3 = vxlanPayload[7];
    
    // Mark that we have VXLAN
    metadata.has_vxlan = true;
    
    // Try to parse encapsulated Ethernet frame
    return parseEncapsulatedEthernet(packet, metadata);
}

bool VXLANParser::parsePcapPlusPlusVXLAN(pcpp::Packet& packet, PacketMetadata& metadata) {
    auto* vxlanLayer = packet.getLayerOfType<pcpp::VxlanLayer>();
    if (!vxlanLayer) {
        return false;
    }
    
    // Get VXLAN header
    auto* vxlanHeader = vxlanLayer->getVxlanHeader();
    if (!vxlanHeader) {
        return false;
    }
    
    // Parse VXLAN header fields using the correct structure
    // The flags are stored in bit fields, so we need to reconstruct them
    uint8_t flags = 0;
    
    // Set I bit (VNI present flag)
    if (vxlanHeader->vniPresentFlag) {
        flags |= 0x08;
        metadata.vxlan.i_bit = true;
    }
    
    // Set other flags based on PcapPlusPlus structure
    if (vxlanHeader->gbpFlag) {
        flags |= 0x10;
    }
    if (vxlanHeader->policyAppliedFlag) {
        flags |= 0x20;
    }
    if (vxlanHeader->dontLearnFlag) {
        flags |= 0x40;
    }
    
    metadata.vxlan.flags = flags;
    metadata.vxlan.vni = vxlanHeader->vni;
    
    // Parse individual flags for backward compatibility
    metadata.vxlan.r_bit = (flags & 0x80) != 0;
    metadata.vxlan.r_bit2 = (flags & 0x40) != 0;
    metadata.vxlan.r_bit3 = (flags & 0x20) != 0;
    metadata.vxlan.r_bit4 = (flags & 0x10) != 0;
    metadata.vxlan.r_bit5 = (flags & 0x04) != 0;
    metadata.vxlan.r_bit6 = (flags & 0x02) != 0;
    metadata.vxlan.r_bit7 = (flags & 0x01) != 0;
    
    // Mark that we have VXLAN
    metadata.has_vxlan = true;
    
    // Try to parse encapsulated Ethernet frame
    return parseEncapsulatedEthernet(packet, metadata);
} 