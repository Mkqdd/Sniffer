#include "ProtocolParser.h"
#include "parsers/EthernetParser.h"
#include "parsers/VLANParser.h"
#include "parsers/GREParser.h"
#include "parsers/IPv4Parser.h"
#include "parsers/IPv6Parser.h"
#include "parsers/TCPParser.h"
#include "parsers/UDPParser.h"
#include "parsers/ARPParser.h"
#include "parsers/IgmpParser.h"
#include "parsers/MPLSParser.h"
#include "parsers/VRRPParser.h"
#include "parsers/HttpParser.h"
#include "parsers/DHCPv6Parser.h"
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/VlanLayer.h>
#include <pcapplusplus/GreLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sstream>
#include <iomanip>

bool ProtocolParser::parsePacket(pcpp::Packet& packet, PacketMetadata& metadata) {
    // Start parsing from Ethernet layer
    return parseEthernet(packet, metadata);
}

bool ProtocolParser::parseEthernet(pcpp::Packet& packet, PacketMetadata& metadata) {
    // Parse Ethernet layer first
    auto* ethLayer = packet.getLayerOfType<pcpp::EthLayer>();
    if (!ethLayer) {
        return false;
    }

    // Set Ethernet presence flag and extract MAC addresses
    metadata.has_ethernet = true;
    memcpy(metadata.ethernet.src_mac, ethLayer->getSourceMac().getRawData(), 6);
    memcpy(metadata.ethernet.dst_mac, ethLayer->getDestMac().getRawData(), 6);
    metadata.ethernet.ethertype = ntohs(ethLayer->getEthHeader()->etherType);

    // Parse protocol stack based on EtherType
    switch (metadata.ethernet.ethertype) {
        case 0x0800: // IPv4
            return parseIPv4(packet, metadata);

        case 0x86DD: // IPv6
            return parseIPv6(packet, metadata);

        case 0x8100: // VLAN (IEEE 802.1Q)
        case 0x88A8: // VLAN (IEEE 802.1ad)
            return parseVLAN(packet, metadata);

        case 0x0806: // ARP
            return ARPParser::parse(packet, metadata);

        case 0x8035: // RARP
            metadata.protocol = "RARP";
            break;
            
        case 0x8847: // MPLS Unicast
        case 0x8848: // MPLS Multicast
            return parseMPLS(packet, metadata);

        default:
            metadata.protocol = "Unknown(" + etherTypeToString(metadata.ethernet.ethertype) + ")";
            break;
    }

    // Set packet length information
    metadata.packet_length = packet.getRawPacket()->getRawDataLen();
    return true;
}

bool ProtocolParser::parseVLAN(pcpp::Packet& packet, PacketMetadata& metadata) {
    // Parse VLAN layer
    if (!VLANParser::parse(packet, metadata)) {
        return false;
    }

    // After VLAN parsing, check the inner EtherType
    auto* vlanLayer = packet.getLayerOfType<pcpp::VlanLayer>();
    if (vlanLayer) {
        uint16_t innerEtherType = ntohs(vlanLayer->getVlanHeader()->etherType);
        
        // Recursively parse the inner protocol
        switch (innerEtherType) {
            case 0x0800: // IPv4
                return parseIPv4(packet, metadata);
                
            case 0x86DD: // IPv6
                return parseIPv6(packet, metadata);
                
                            case 0x0806: // ARP
                return ARPParser::parse(packet, metadata);
                
            case 0x8847: // MPLS Unicast
            case 0x8848: // MPLS Multicast
                return parseMPLS(packet, metadata);
                
            default:
                metadata.protocol = "VLAN/" + etherTypeToString(innerEtherType);
                break;
        }
    }
    
    return true;
}

bool ProtocolParser::parseGRE(pcpp::Packet& packet, PacketMetadata& metadata) {
    // Parse GRE layer and handle decapsulation
    return GREParser::parse(packet, metadata);
}

bool ProtocolParser::parseMPLS(pcpp::Packet& packet, PacketMetadata& metadata) {
    // Parse MPLS layer
    if (!MPLSParser::parse(packet, metadata)) {
        return false;
    }
    
    // After MPLS parsing, attempt to parse the payload protocol
    // For MPLS encapsulated packets, we need to manually parse the payload
    // since PcapPlusPlus doesn't automatically create IPv4/IPv6 layers for MPLS payload
    switch (metadata.mpls.payload_protocol) {
        case 0x0800: // IPv4
            // Try standard IPv4 parsing first, if fails, parse manually
            if (parseIPv4(packet, metadata)) {
                return true;
            }
            return parseMPLSPayloadIPv4(packet, metadata);
            
        case 0x86DD: // IPv6
            // Try standard IPv6 parsing first, if fails, parse manually
            if (parseIPv6(packet, metadata)) {
                return true;
            }
            return parseMPLSPayloadIPv6(packet, metadata);
            
        default:
            // For other protocols or unknown payload, just return true
            // The MPLS parser has already set the appropriate protocol string
            break;
    }
    
    return true;
}

bool ProtocolParser::parseIPv4(pcpp::Packet& packet, PacketMetadata& metadata) {
    // Parse IPv4 layer
    if (!IPv4Parser::parse(packet, metadata)) {
        return false;
    }

    // Parse transport layer
    return parseTransport(packet, metadata);
}

bool ProtocolParser::parseIPv6(pcpp::Packet& packet, PacketMetadata& metadata) {
    // Parse IPv6 layer
    if (!IPv6Parser::parse(packet, metadata)) {
        return false;
    }

    // Parse transport layer
    return parseTransport(packet, metadata);
}

bool ProtocolParser::parseTransport(pcpp::Packet& packet, PacketMetadata& metadata) {
    // Parse transport layer protocols
    if (packet.isPacketOfType(pcpp::TCP)) {
        return TCPParser::parse(packet, metadata);
    } else if (packet.isPacketOfType(pcpp::UDP)) {
        return UDPParser::parse(packet, metadata);
    }
    
    return true;
}

std::string ProtocolParser::etherTypeToString(uint16_t etherType) {
    switch (etherType) {
        case 0x0800: return "IPv4";
        case 0x0806: return "ARP";
        case 0x8035: return "RARP";
        case 0x8100: return "VLAN";
        case 0x86DD: return "IPv6";
        case 0x6558: return "GRE";
        case 0x8847: return "MPLS_Unicast";
        case 0x8848: return "MPLS_Multicast";
        default: {
            std::ostringstream oss;
            oss << "0x" << std::hex << etherType;
            return oss.str();
        }
    }
}

bool ProtocolParser::parseMPLSPayloadIPv4(pcpp::Packet& packet, PacketMetadata& metadata) {
    // Extract IPv4 payload from MPLS packet manually
    const uint8_t* packetData = packet.getRawPacket()->getRawData();
    size_t packetLen = packet.getRawPacket()->getRawDataLen();
    
    // Calculate IPv4 payload offset (14 bytes Ethernet + MPLS labels)
    size_t ipv4Offset = 14; // Ethernet header
    
    // Add VLAN offset if present
    if (metadata.has_vlan) {
        ipv4Offset += 4;
    }
    
    // Add MPLS label stack size
    ipv4Offset += metadata.mpls.stack_depth * 4;
    
    // Check if we have enough data for IPv4 header
    if (ipv4Offset + 20 > packetLen) {
        return false;
    }
    
    const uint8_t* ipv4Data = packetData + ipv4Offset;
    
    // Parse IPv4 header manually
    metadata.has_ipv4 = true;
    
    // Extract version and check
    uint8_t version = (ipv4Data[0] >> 4) & 0xF;
    if (version != 4) {
        return false;
    }
    
    // Extract header length
    uint8_t headerLen = (ipv4Data[0] & 0xF) * 4;
    if (ipv4Offset + headerLen > packetLen) {
        return false;
    }
    
    // Extract IPv4 fields
    metadata.ipv4.protocol = ipv4Data[9];
    metadata.ipv4.ttl = ipv4Data[8];
    metadata.ipv4.tos = ipv4Data[1];
    metadata.ipv4.id = ntohs(*reinterpret_cast<const uint16_t*>(ipv4Data + 4));
    
    // Extract fragment flags and offset
    uint16_t fragmentFlags = ntohs(*reinterpret_cast<const uint16_t*>(ipv4Data + 6));
    metadata.ipv4.df_bit = (fragmentFlags & 0x4000) != 0;
    metadata.ipv4.mf_bit = (fragmentFlags & 0x2000) != 0;
    metadata.ipv4.fragment_offset = fragmentFlags & 0x1FFF;
    
    // Extract IP addresses
    char srcIP[INET_ADDRSTRLEN];
    char dstIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, ipv4Data + 12, srcIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, ipv4Data + 16, dstIP, INET_ADDRSTRLEN);
    
    metadata.ipv4.src_ip = srcIP;
    metadata.ipv4.dst_ip = dstIP;
    metadata.srcIP = srcIP;
    metadata.dstIP = dstIP;
    
    // Update protocol description
    metadata.protocol = metadata.mpls.unicast ? "MPLS/Unicast/IPv4" : "MPLS/Multicast/IPv4";
    
    return true;
}

bool ProtocolParser::parseMPLSPayloadIPv6(pcpp::Packet& packet, PacketMetadata& metadata) {
    // Extract IPv6 payload from MPLS packet manually
    const uint8_t* packetData = packet.getRawPacket()->getRawData();
    size_t packetLen = packet.getRawPacket()->getRawDataLen();
    
    // Calculate IPv6 payload offset (14 bytes Ethernet + MPLS labels)
    size_t ipv6Offset = 14; // Ethernet header
    
    // Add VLAN offset if present
    if (metadata.has_vlan) {
        ipv6Offset += 4;
    }
    
    // Add MPLS label stack size
    ipv6Offset += metadata.mpls.stack_depth * 4;
    
    // Check if we have enough data for IPv6 header (40 bytes)
    if (ipv6Offset + 40 > packetLen) {
        return false;
    }
    
    const uint8_t* ipv6Data = packetData + ipv6Offset;
    
    // Parse IPv6 header manually
    metadata.has_ipv6 = true;
    
    // Extract version and check
    uint8_t version = (ipv6Data[0] >> 4) & 0xF;
    if (version != 6) {
        return false;
    }
    
    // Extract IPv6 fields
    uint32_t version_traffic_flow = ntohl(*reinterpret_cast<const uint32_t*>(ipv6Data));
    metadata.ipv6.traffic_class = (version_traffic_flow >> 20) & 0xFF;
    metadata.ipv6.flow_label = version_traffic_flow & 0xFFFFF;
    
    metadata.ipv6.payload_length = ntohs(*reinterpret_cast<const uint16_t*>(ipv6Data + 4));
    metadata.ipv6.next_header = ipv6Data[6];
    metadata.ipv6.hop_limit = ipv6Data[7];
    
    // Extract IPv6 addresses
    char srcIP[INET6_ADDRSTRLEN];
    char dstIP[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, ipv6Data + 8, srcIP, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, ipv6Data + 24, dstIP, INET6_ADDRSTRLEN);
    
    metadata.ipv6.src_ip = srcIP;
    metadata.ipv6.dst_ip = dstIP;
    metadata.srcIP = srcIP;
    metadata.dstIP = dstIP;
    
    // Update protocol description
    metadata.protocol = metadata.mpls.unicast ? "MPLS/Unicast/IPv6" : "MPLS/Multicast/IPv6";
    
    return true;
} 