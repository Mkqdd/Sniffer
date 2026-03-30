#include "parsers/IPv4Parser.h"
#include "parsers/GREParser.h"
#include "parsers/ICMPParser.h"
#include "parsers/IgmpParser.h"
#include "parsers/VRRPParser.h"
#include "parsers/IPSecParser.h"
#include <pcapplusplus/IPv4Layer.h>
#include <netinet/in.h>

bool IPv4Parser::parse(pcpp::Packet& packet, PacketMetadata& metadata) {
    auto* ipv4Layer = packet.getLayerOfType<pcpp::IPv4Layer>();
    if (!ipv4Layer) {
        return false;
    }

    // Set IPv4 presence flag and parse IPv4 addresses
    metadata.has_ipv4 = true;
    metadata.ipv4.src_ip = ipv4Layer->getSrcIPAddress().toString();
    metadata.ipv4.dst_ip = ipv4Layer->getDstIPAddress().toString();
    
    // Legacy fields for backward compatibility
    metadata.srcIP = metadata.ipv4.src_ip;
    metadata.dstIP = metadata.ipv4.dst_ip;
    metadata.protocol = "IPv4";

    // Get IPv4 header information
    auto* ipv4Header = ipv4Layer->getIPv4Header();
    
    // Parse IPv4 header fields
    metadata.ipv4.protocol = ipv4Header->protocol;
    metadata.ipv4.ttl = ipv4Header->timeToLive;
    metadata.ipv4.tos = ipv4Header->typeOfService;
    metadata.ipv4.id = ntohs(ipv4Header->ipId);
    
    // Parse fragment flags and offset
    uint16_t fragmentFlags = ntohs(ipv4Header->fragmentOffset);
    metadata.ipv4.df_bit = (fragmentFlags & 0x4000) != 0;  // Don't Fragment bit
    metadata.ipv4.mf_bit = (fragmentFlags & 0x2000) != 0;  // More Fragments bit
    metadata.ipv4.fragment_offset = fragmentFlags & 0x1FFF;  // Fragment offset (13 bits)
    
    // Update protocol based on the transport layer protocol
    switch (metadata.ipv4.protocol) {
        case 6:  // TCP
            metadata.protocol = "TCP";
            break;
        case 17: // UDP
            metadata.protocol = "UDP";
            break;
        case 1:  // ICMP
            metadata.protocol = "ICMP";
            // Parse ICMP layer after IPv4
            ICMPParser::parse(packet, metadata);
            break;
        case 2:  // IGMP
            metadata.protocol = "IGMP";
            // Parse IGMP layer after IPv4
            IgmpParser::parse(packet, metadata);
            break;
        case 47: // GRE
            metadata.protocol = "GRE";
            // Parse GRE layer after IPv4
            if (GREParser::parse(packet, metadata)) {
                // After GRE parsing, we might need to parse the encapsulated protocol
                // This depends on the GRE protocol field
            }
            break;
        case 50: // ESP
            metadata.protocol = "ESP";
            // Parse ESP layer after IPv4
            if (IPSecParser::parseESP(packet, metadata)) {
                // ESP parsing successful
            }
            break;
        case 51: // AH
            metadata.protocol = "AH";
            // Parse AH layer after IPv4
            if (IPSecParser::parseAH(packet, metadata)) {
                // AH parsing successful
            }
            break;
        case 112: // VRRP
            metadata.protocol = "VRRP";
            // Parse VRRP layer after IPv4
            if (VRRPParser::parse(packet, metadata)) {
                // VRRP parsing successful
            }
            break;
        default:
            metadata.protocol = "Unknown";
            break;
    }

    // Set packet length information
    metadata.packet_length = packet.getRawPacket()->getRawDataLen();
    metadata.payload_length = ipv4Layer->getLayerPayloadSize();

    return true;
}

std::string IPv4Parser::ipToString(uint32_t ip) {
    return std::to_string((ip >> 24) & 0xFF) + "." +
           std::to_string((ip >> 16) & 0xFF) + "." +
           std::to_string((ip >> 8) & 0xFF) + "." +
           std::to_string(ip & 0xFF);
}