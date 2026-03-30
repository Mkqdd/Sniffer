#include "parsers/UDPParser.h"
#include "parsers/VXLANParser.h"
#include "parsers/DNSParser.h"
#include "parsers/DHCPParser.h"
#include "parsers/DHCPv6Parser.h"
#include "parsers/NTPParser.h"
#include <pcapplusplus/UdpLayer.h>

bool UDPParser::parse(pcpp::Packet& packet, PacketMetadata& metadata) {
    auto* udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
    if (!udpLayer) {
        return false;
    }

    // Set UDP presence flag and parse UDP information
    metadata.has_udp = true;
    
    auto* udpHeader = udpLayer->getUdpHeader();
    
    // Basic port information
    metadata.udp.src_port = udpLayer->getSrcPort();
    metadata.udp.dst_port = udpLayer->getDstPort();
    
    // Legacy fields for backward compatibility
    metadata.srcPort = metadata.udp.src_port;
    metadata.dstPort = metadata.udp.dst_port;
    metadata.protocol = "UDP";
    
    // UDP specific fields
    metadata.udp.length = ntohs(udpHeader->length);
    metadata.udp.checksum = ntohs(udpHeader->headerChecksum);
    
    // Packet size information
    metadata.packet_length = packet.getRawPacket()->getRawDataLen();
    metadata.payload_length = udpLayer->getLayerPayloadSize();
    
    // Check for specific UDP-based protocols
    
    // Check if this is a DHCP packet (ports 67/68)
    if (DHCPParser::parse(packet, metadata)) {
        // DHCP parsing successful, update protocol
        metadata.protocol = "UDP";
        metadata.application_protocol = "dhcp";
    }
    // Check if this is a DHCPv6 packet (ports 546/547)
    else if (DHCPv6Parser::parse(packet, metadata)) {
        // DHCPv6 parsing successful, update protocol
        metadata.protocol = "UDP";
        metadata.application_protocol = "dhcpv6";
    }
    // Check if this is an NTP packet (UDP port 123) - priority over DNS detection
    else if (metadata.udp.dst_port == 123 || metadata.udp.src_port == 123) {
        // Try to parse NTP
        if (NTPParser::parse(packet, metadata)) {
            // NTP parsing successful, update protocol
            metadata.protocol = "UDP";
            metadata.application_protocol = "ntp";
        }
    }
    // Check if this is a DNS packet (port 53, 5353, or 5355, or pattern-based detection)
    else if (DNSParser::parse(packet, metadata)) {
        // DNS parsing successful, update protocol
        metadata.protocol = "UDP";
        metadata.application_protocol = "dns";
    }
    // Check if this is a VXLAN packet (UDP port 4789)
    else if (metadata.udp.dst_port == 4789) {
        // Try to parse VXLAN
        if (VXLANParser::parse(packet, metadata)) {
            // VXLAN parsing successful, update protocol
            metadata.protocol = "UDP";
            metadata.application_protocol = "vxlan";
        }
    }
    
    return true;
}