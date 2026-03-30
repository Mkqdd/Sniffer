#include "parsers/ARPParser.h"
#include <pcapplusplus/ArpLayer.h>
#include <netinet/in.h>
#include <iostream>
#include <sstream>
#include <iomanip>

bool ARPParser::parse(pcpp::Packet& packet, PacketMetadata& metadata) {
    auto* arpLayer = packet.getLayerOfType<pcpp::ArpLayer>();
    if (!arpLayer) {
        return false;
    }

    // Set ARP presence flag
    metadata.has_arp = true;
    metadata.protocol = "ARP";

    // Get ARP header
    auto* arpHeader = arpLayer->getArpHeader();
    
    // Parse ARP header fields
    metadata.arp.hardware_type = ntohs(arpHeader->hardwareType);
    metadata.arp.protocol_type = ntohs(arpHeader->protocolType);
    metadata.arp.hardware_size = arpHeader->hardwareSize;
    metadata.arp.protocol_size = arpHeader->protocolSize;
    metadata.arp.operation = ntohs(arpHeader->opcode);

    // Parse sender hardware address (MAC)
    if (metadata.arp.hardware_size == 6) {
        memcpy(metadata.arp.sender_mac, arpHeader->senderMacAddr, 6);
        metadata.arp.sender_mac_str = macToString(metadata.arp.sender_mac);
    }

    // Parse sender protocol address (IP)
    if (metadata.arp.protocol_size == 4) {
        memcpy(metadata.arp.sender_ip, &arpHeader->senderIpAddr, 4);
        metadata.arp.sender_ip_str = ipToString(ntohl(arpHeader->senderIpAddr));
    }

    // Parse target hardware address (MAC)
    if (metadata.arp.hardware_size == 6) {
        memcpy(metadata.arp.target_mac, arpHeader->targetMacAddr, 6);
        metadata.arp.target_mac_str = macToString(metadata.arp.target_mac);
    }

    // Parse target protocol address (IP)
    if (metadata.arp.protocol_size == 4) {
        memcpy(metadata.arp.target_ip, &arpHeader->targetIpAddr, 4);
        metadata.arp.target_ip_str = ipToString(ntohl(arpHeader->targetIpAddr));
    }

    // Set legacy fields for backward compatibility
    metadata.srcIP = metadata.arp.sender_ip_str;
    metadata.dstIP = metadata.arp.target_ip_str;

    // Set packet length information
    metadata.packet_length = packet.getRawPacket()->getRawDataLen();
    metadata.payload_length = arpLayer->getLayerPayloadSize();

    return true;
}

std::string ARPParser::arpOpToString(uint16_t op) {
    switch (op) {
        case 1: return "REQUEST";
        case 2: return "REPLY";
        case 3: return "RARP_REQUEST";
        case 4: return "RARP_REPLY";
        case 5: return "DRARP_REQUEST";
        case 6: return "DRARP_REPLY";
        case 7: return "DRARP_ERROR";
        case 8: return "INARP_REQUEST";
        case 9: return "INARP_REPLY";
        default: return "UNKNOWN(" + std::to_string(op) + ")";
    }
} 