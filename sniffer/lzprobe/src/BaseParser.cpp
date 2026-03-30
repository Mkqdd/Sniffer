#include "BaseParser.h"
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>
#include <pcapplusplus/EthLayer.h>
#include <arpa/inet.h>
#include <sstream>
#include <iomanip>
#include <map>
#include <functional>

std::string BaseParser::ipToString(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = ip;
    return std::string(inet_ntoa(addr));
}

std::string BaseParser::macToString(const uint8_t* mac) {
    std::ostringstream oss;
    for (int i = 0; i < 6; ++i) {
        if (i > 0) oss << ":";
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mac[i]);
    }
    return oss.str();
}

std::string BaseParser::portToService(uint16_t port, const std::string& protocol) {
    static std::map<uint16_t, std::string> tcpPorts = {
        {20, "ftp-data"}, {21, "ftp"}, {22, "ssh"}, {23, "telnet"},
        {25, "smtp"}, {53, "dns"}, {80, "http"}, {110, "pop3"},
        {143, "imap"}, {443, "https"}, {993, "imaps"}, {995, "pop3s"}
    };
    
    static std::map<uint16_t, std::string> udpPorts = {
        {53, "dns"}, {67, "dhcp-server"}, {68, "dhcp-client"},
        {123, "ntp"}, {161, "snmp"}, {162, "snmp-trap"}
    };
    
    if (protocol == "TCP" && tcpPorts.find(port) != tcpPorts.end()) {
        return tcpPorts[port];
    } else if (protocol == "UDP" && udpPorts.find(port) != udpPorts.end()) {
        return udpPorts[port];
    }
    
    return std::to_string(port);
}

void BaseParser::extractNetworkInfo(pcpp::Packet& packet, PacketMetadata& metadata) {
    // Extract IPv4 information
    auto* ipv4Layer = packet.getLayerOfType<pcpp::IPv4Layer>();
    if (ipv4Layer) {
        metadata.srcIP = ipv4Layer->getSrcIPAddress().toString();
        metadata.dstIP = ipv4Layer->getDstIPAddress().toString();
        return;
    }
    
    // Extract IPv6 information
    auto* ipv6Layer = packet.getLayerOfType<pcpp::IPv6Layer>();
    if (ipv6Layer) {
        metadata.srcIP = ipv6Layer->getSrcIPAddress().toString();
        metadata.dstIP = ipv6Layer->getDstIPAddress().toString();
    }
}

void BaseParser::calculateSizes(pcpp::Packet& packet, PacketMetadata& metadata) {
    metadata.packet_length = packet.getRawPacket()->getRawDataLen();
    
    // Calculate payload size based on the deepest layer
    pcpp::Layer* lastLayer = packet.getLastLayer();
    if (lastLayer) {
        metadata.payload_length = lastLayer->getLayerPayloadSize();
    }
}

bool BaseParser::validatePacket(pcpp::Packet& packet) {
    // Basic validation checks
    if (!packet.isPacketOfType(pcpp::Ethernet)) {
        return false;
    }
    
    auto rawPacket = packet.getRawPacket();
    if (!rawPacket || rawPacket->getRawDataLen() < 14) { // Minimum Ethernet frame size
        return false;
    }
    
    return true;
}

// ParserFactory implementation
std::map<std::string, std::function<std::shared_ptr<BaseParser>()>> ParserFactory::parsers_;

std::shared_ptr<BaseParser> ParserFactory::createParser(const std::string& protocolName) {
    auto it = parsers_.find(protocolName);
    if (it != parsers_.end()) {
        return it->second();
    }
    return nullptr;
}

std::string BaseParser::etherTypeToString(uint16_t ethertype) {
    switch (ethertype) {
        case 0x0800: return "IPv4";
        case 0x0806: return "ARP";
        case 0x8035: return "RARP";
        case 0x86DD: return "IPv6";
        case 0x8100: return "VLAN";
        case 0x88A8: return "VLAN_802.1ad";
        case 0x8847: return "MPLS_UNICAST";
        case 0x8848: return "MPLS_MULTICAST";
        case 0x8863: return "PPPoE_DISCOVERY";
        case 0x8864: return "PPPoE_SESSION";
        case 0x88CC: return "LLDP";
        case 0x88E5: return "MACsec";
        case 0x88F7: return "PTP";
        case 0x8906: return "FCoE";
        case 0x8914: return "FCoE_LLDP";
        case 0x8915: return "RoCE";
        case 0x8942: return "NSH";
        case 0x9000: return "LOOPBACK";
        case 0x9100: return "VLAN_OLD";
        case 0x9200: return "VLAN_OLD";
        case 0x9300: return "VLAN_OLD";
        case 0xCAFE: return "LLDP";
        case 0xFFFF: return "RESERVED";
        default: return "UNKNOWN";
    }
}