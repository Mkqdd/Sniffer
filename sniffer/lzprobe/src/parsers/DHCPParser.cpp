#include "parsers/DHCPParser.h"
#include <pcapplusplus/UdpLayer.h>
#include <pcapplusplus/DhcpLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <sstream>
#include <iomanip>

// DHCP magic cookie (RFC 2131)
static const uint32_t DHCP_MAGIC_COOKIE = 0x63825363;

// DHCP option codes (RFC 2132)
enum DHCPOptionCode {
    DHCP_OPT_SUBNET_MASK = 1,
    DHCP_OPT_ROUTER = 3,
    DHCP_OPT_DNS_SERVERS = 6,
    DHCP_OPT_DOMAIN_NAME = 15,
    DHCP_OPT_LEASE_TIME = 51,
    DHCP_OPT_MESSAGE_TYPE = 53,
    DHCP_OPT_SERVER_ID = 54,
    DHCP_OPT_END = 255
};

bool DHCPParser::parse(pcpp::Packet& packet, PacketMetadata& metadata) {
    // First check if this is a potential DHCP packet based on UDP ports
    if (!isDHCPPacket(packet)) {
        return false;
    }
    
    // Try to get DHCP layer using PcapPlusPlus
    auto* dhcpLayer = packet.getLayerOfType<pcpp::DhcpLayer>();
    if (!dhcpLayer) {
        return false;
    }
    
    // Set DHCP presence flag
    metadata.has_dhcp = true;
    metadata.protocol = "UDP";
    metadata.application_protocol = "dhcp";
    
    // Parse DHCP header using PcapPlusPlus API
    const pcpp::dhcp_header* dhcpHeader = dhcpLayer->getDhcpHeader();
    if (!dhcpHeader) {
        return false;
    }
    
    // Extract basic DHCP header fields
    metadata.dhcp.op = dhcpHeader->opCode;
    metadata.dhcp.htype = dhcpHeader->hardwareType;
    metadata.dhcp.hlen = dhcpHeader->hardwareAddressLength;
    metadata.dhcp.hops = dhcpHeader->hops;
    metadata.dhcp.xid = ntohl(dhcpHeader->transactionID);
    metadata.dhcp.secs = ntohs(dhcpHeader->secondsElapsed);
    metadata.dhcp.flags = ntohs(dhcpHeader->flags);
    
    // Extract broadcast flag
    metadata.dhcp.broadcast_flag = (metadata.dhcp.flags & 0x8000) != 0;
    
    // Convert IP addresses to strings
    metadata.dhcp.ciaddr = ipToString(dhcpHeader->clientIpAddress);
    metadata.dhcp.yiaddr = ipToString(dhcpHeader->yourIpAddress);
    metadata.dhcp.siaddr = ipToString(dhcpHeader->serverIpAddress);
    metadata.dhcp.giaddr = ipToString(dhcpHeader->gatewayIpAddress);
    
    // Extract client hardware address (MAC)
    if (metadata.dhcp.hlen > 0 && metadata.dhcp.hlen <= 16) {
        metadata.dhcp.chaddr = macToString(dhcpHeader->clientHardwareAddress, metadata.dhcp.hlen);
    }
    
    // Extract server name and boot file name
    if (dhcpHeader->serverName[0] != '\0') {
        metadata.dhcp.sname = std::string(reinterpret_cast<const char*>(dhcpHeader->serverName), 
                                         strnlen(reinterpret_cast<const char*>(dhcpHeader->serverName), 64));
    }
    
    if (dhcpHeader->bootFilename[0] != '\0') {
        metadata.dhcp.file = std::string(reinterpret_cast<const char*>(dhcpHeader->bootFilename),
                                        strnlen(reinterpret_cast<const char*>(dhcpHeader->bootFilename), 128));
    }
    
    // Set human-readable strings
    metadata.dhcp.op_str = (metadata.dhcp.op == 1) ? "BOOTREQUEST" : 
                          (metadata.dhcp.op == 2) ? "BOOTREPLY" : 
                          "UNKNOWN(" + std::to_string(metadata.dhcp.op) + ")";
    
    // Parse DHCP options using PcapPlusPlus API
    pcpp::DhcpOption option = dhcpLayer->getFirstOptionData();
    while (option.isNotNull()) {
        uint8_t optionType = static_cast<uint8_t>(option.getType());
        
        switch (optionType) {
            case DHCP_OPT_MESSAGE_TYPE:
                if (option.getDataSize() >= 1) {
                    metadata.dhcp.message_type = option.getValueAs<uint8_t>();
                    switch (metadata.dhcp.message_type) {
                        case 1: metadata.dhcp.message_type_str = "DISCOVER"; break;
                        case 2: metadata.dhcp.message_type_str = "OFFER"; break;
                        case 3: metadata.dhcp.message_type_str = "REQUEST"; break;
                        case 4: metadata.dhcp.message_type_str = "DECLINE"; break;
                        case 5: metadata.dhcp.message_type_str = "ACK"; break;
                        case 6: metadata.dhcp.message_type_str = "NAK"; break;
                        case 7: metadata.dhcp.message_type_str = "RELEASE"; break;
                        case 8: metadata.dhcp.message_type_str = "INFORM"; break;
                        default: metadata.dhcp.message_type_str = "UNKNOWN(" + std::to_string(metadata.dhcp.message_type) + ")"; break;
                    }
                }
                break;
                
            case DHCP_OPT_LEASE_TIME:
                if (option.getDataSize() >= 4) {
                    metadata.dhcp.lease_time = ntohl(option.getValueAs<uint32_t>());
                }
                break;
                
            case DHCP_OPT_SUBNET_MASK:
                if (option.getDataSize() >= 4) {
                    metadata.dhcp.subnet_mask = ipToString(option.getValueAs<uint32_t>());
                }
                break;
                
            case DHCP_OPT_ROUTER:
                if (option.getDataSize() >= 4) {
                    metadata.dhcp.router = ipToString(option.getValueAs<uint32_t>());
                }
                break;
                
            case DHCP_OPT_DNS_SERVERS:
                if (option.getDataSize() >= 4) {
                    std::stringstream dns_ss;
                    size_t num_dns = option.getDataSize() / 4;
                    const uint32_t* dns_data = reinterpret_cast<const uint32_t*>(option.getValue());
                    for (size_t i = 0; i < num_dns; ++i) {
                        if (i > 0) dns_ss << ",";
                        dns_ss << ipToString(dns_data[i]);
                    }
                    metadata.dhcp.dns_servers = dns_ss.str();
                }
                break;
                
            case DHCP_OPT_DOMAIN_NAME:
                if (option.getDataSize() > 0) {
                    metadata.dhcp.domain_name = std::string(
                        reinterpret_cast<const char*>(option.getValue()), 
                        option.getDataSize()
                    );
                }
                break;
                
            case DHCP_OPT_SERVER_ID:
                if (option.getDataSize() >= 4) {
                    metadata.dhcp.dhcp_server_id = ipToString(option.getValueAs<uint32_t>());
                }
                break;
        }
        
        // Get next option
        option = dhcpLayer->getNextOptionData(option);
    }
    
    return true;
}

bool DHCPParser::isDHCPPacket(pcpp::Packet& packet) {
    auto* udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
    if (!udpLayer) {
        return false;
    }
    
    uint16_t srcPort = udpLayer->getSrcPort();
    uint16_t dstPort = udpLayer->getDstPort();
    
    // DHCP uses ports 67 (server) and 68 (client)
    // Server->Client: src=67, dst=68
    // Client->Server: src=68, dst=67
    return (srcPort == 67 && dstPort == 68) || (srcPort == 68 && dstPort == 67);
}

bool DHCPParser::validateDHCPPacket(const uint8_t* data, size_t length) {
    // Minimum DHCP packet size (header + magic cookie)
    if (length < 240) {
        return false;
    }
    
    // Check magic cookie at offset 236
    const uint32_t* magic = reinterpret_cast<const uint32_t*>(data + 236);
    return ntohl(*magic) == DHCP_MAGIC_COOKIE;
}

bool DHCPParser::parseHeader(const uint8_t* data, PacketMetadata& metadata) {
    // This method is kept for potential future use with raw parsing
    // Currently using PcapPlusPlus API in the main parse method
    return true;
}

bool DHCPParser::parseOptions(const uint8_t* data, size_t length, PacketMetadata& metadata) {
    // This method is kept for potential future use with raw parsing
    // Currently using PcapPlusPlus API in the main parse method
    return true;
}

std::string DHCPParser::ipToString(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = ip;
    return std::string(inet_ntoa(addr));
}

std::string DHCPParser::macToString(const uint8_t* mac, uint8_t length) {
    std::ostringstream oss;
    for (uint8_t i = 0; i < length && i < 16; ++i) {
        if (i > 0) oss << ":";
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mac[i]);
    }
    return oss.str();
}

std::string DHCPParser::getMessageTypeString(uint8_t type) {
    switch (type) {
        case 1: return "DISCOVER";
        case 2: return "OFFER";
        case 3: return "REQUEST";
        case 4: return "DECLINE";
        case 5: return "ACK";
        case 6: return "NAK";
        case 7: return "RELEASE";
        case 8: return "INFORM";
        case 9: return "FORCERENEW";
        case 10: return "LEASEQUERY";
        case 11: return "LEASEUNASSIGNED";
        case 12: return "LEASEUNKNOWN";
        case 13: return "LEASEACTIVE";
        default: return "UNKNOWN(" + std::to_string(type) + ")";
    }
}

void DHCPParser::formatForCSV(const DHCPMetadata& dhcp_meta, std::ostringstream& line, const std::string& separator) {
    line << "DHCP_OP:" << static_cast<int>(dhcp_meta.op) << separator;
    line << "DHCP_OP_STR:" << dhcp_meta.op_str << separator;
    line << "DHCP_HTYPE:" << static_cast<int>(dhcp_meta.htype) << separator;
    line << "DHCP_HLEN:" << static_cast<int>(dhcp_meta.hlen) << separator;
    line << "DHCP_HOPS:" << static_cast<int>(dhcp_meta.hops) << separator;
    line << "DHCP_XID:" << std::hex << "0x" << dhcp_meta.xid << std::dec << separator;
    line << "DHCP_SECS:" << dhcp_meta.secs << separator;
    line << "DHCP_FLAGS:" << std::hex << "0x" << dhcp_meta.flags << std::dec << separator;
    
    line << "DHCP_BROADCAST_FLAG:" << (dhcp_meta.broadcast_flag ? "1" : "0") << separator;
    
    line << "DHCP_CLIENT_IP:" << dhcp_meta.ciaddr << separator;
    line << "DHCP_YOUR_IP:" << dhcp_meta.yiaddr << separator;
    line << "DHCP_SERVER_IP:" << dhcp_meta.siaddr << separator;
    line << "DHCP_GATEWAY_IP:" << dhcp_meta.giaddr << separator;
    line << "DHCP_CLIENT_MAC:" << dhcp_meta.chaddr << separator;
    
    if (dhcp_meta.message_type != 0) {
        line << "DHCP_MESSAGE_TYPE:" << static_cast<int>(dhcp_meta.message_type) << separator;
        line << "DHCP_MESSAGE_TYPE_STR:" << dhcp_meta.message_type_str << separator;
    } else {
        line << "DHCP_MESSAGE_TYPE:0" << separator;
        line << "DHCP_MESSAGE_TYPE_STR:" << separator;
    }
    
    if (dhcp_meta.lease_time != 0) {
        line << "DHCP_LEASE_TIME:" << dhcp_meta.lease_time << separator;
    } else {
        line << "DHCP_LEASE_TIME:0" << separator;
    }
    
    line << "DHCP_SUBNET_MASK:" << dhcp_meta.subnet_mask << separator;
    line << "DHCP_ROUTER:" << dhcp_meta.router << separator;
    line << "DHCP_DNS_SERVERS:" << dhcp_meta.dns_servers << separator;
    line << "DHCP_DOMAIN_NAME:" << dhcp_meta.domain_name << separator;
    line << "DHCP_SERVER_ID:" << dhcp_meta.dhcp_server_id << separator;
    line << "DHCP_SERVER_NAME:" << dhcp_meta.sname << separator;
    line << "DHCP_BOOT_FILE:" << dhcp_meta.file << separator;
}

void DHCPParser::formatForJSON(const DHCPMetadata& dhcp_meta, std::ostringstream& oss, const std::function<std::string(const std::string&)>& escapeJsonString) {
    oss << "\"DHCP_OP\":" << static_cast<int>(dhcp_meta.op) << ",";
    oss << "\"DHCP_OP_STR\":\"" << escapeJsonString(dhcp_meta.op_str) << "\",";
    oss << "\"DHCP_HTYPE\":" << static_cast<int>(dhcp_meta.htype) << ",";
    oss << "\"DHCP_HLEN\":" << static_cast<int>(dhcp_meta.hlen) << ",";
    oss << "\"DHCP_HOPS\":" << static_cast<int>(dhcp_meta.hops) << ",";
    oss << "\"DHCP_XID\":\"0x" << std::hex << dhcp_meta.xid << std::dec << "\",";
    oss << "\"DHCP_SECS\":" << dhcp_meta.secs << ",";
    oss << "\"DHCP_FLAGS\":\"0x" << std::hex << dhcp_meta.flags << std::dec << "\",";
    oss << "\"DHCP_BROADCAST_FLAG\":" << (dhcp_meta.broadcast_flag ? "true" : "false") << ",";
    oss << "\"DHCP_CLIENT_IP\":\"" << escapeJsonString(dhcp_meta.ciaddr) << "\",";
    oss << "\"DHCP_YOUR_IP\":\"" << escapeJsonString(dhcp_meta.yiaddr) << "\",";
    oss << "\"DHCP_SERVER_IP\":\"" << escapeJsonString(dhcp_meta.siaddr) << "\",";
    oss << "\"DHCP_GATEWAY_IP\":\"" << escapeJsonString(dhcp_meta.giaddr) << "\",";
    oss << "\"DHCP_CLIENT_MAC\":\"" << escapeJsonString(dhcp_meta.chaddr) << "\",";
    oss << "\"DHCP_MESSAGE_TYPE\":" << static_cast<int>(dhcp_meta.message_type) << ",";
    oss << "\"DHCP_MESSAGE_TYPE_STR\":\"" << escapeJsonString(dhcp_meta.message_type_str) << "\",";
    oss << "\"DHCP_LEASE_TIME\":" << dhcp_meta.lease_time << ",";
    oss << "\"DHCP_SUBNET_MASK\":\"" << escapeJsonString(dhcp_meta.subnet_mask) << "\",";
    oss << "\"DHCP_ROUTER\":\"" << escapeJsonString(dhcp_meta.router) << "\",";
    oss << "\"DHCP_DNS_SERVERS\":\"" << escapeJsonString(dhcp_meta.dns_servers) << "\",";
    oss << "\"DHCP_DOMAIN_NAME\":\"" << escapeJsonString(dhcp_meta.domain_name) << "\",";
    oss << "\"DHCP_SERVER_ID\":\"" << escapeJsonString(dhcp_meta.dhcp_server_id) << "\",";
    oss << "\"DHCP_SERVER_NAME\":\"" << escapeJsonString(dhcp_meta.sname) << "\",";
    oss << "\"DHCP_BOOT_FILE\":\"" << escapeJsonString(dhcp_meta.file) << "\",";
}

std::string DHCPParser::formatForConsole(const DHCPMetadata& dhcp_meta) {
    std::ostringstream oss;
    oss << "HAS_DHCP: YES ";
    oss << "DHCP_OP: " << static_cast<int>(dhcp_meta.op) << " ";
    oss << "DHCP_OP_STR: " << dhcp_meta.op_str << " ";
    oss << "DHCP_HTYPE: " << static_cast<int>(dhcp_meta.htype) << " ";
    oss << "DHCP_HLEN: " << static_cast<int>(dhcp_meta.hlen) << " ";
    oss << "DHCP_HOPS: " << static_cast<int>(dhcp_meta.hops) << " ";
    oss << "DHCP_XID: 0x" << std::hex << dhcp_meta.xid << std::dec << " ";
    oss << "DHCP_SECS: " << dhcp_meta.secs << " ";
    oss << "DHCP_FLAGS: 0x" << std::hex << dhcp_meta.flags << std::dec << " ";
    
    if (dhcp_meta.broadcast_flag) {
        oss << "DHCP_BROADCAST_FLAG: YES ";
    }
    
    if (!dhcp_meta.ciaddr.empty() && dhcp_meta.ciaddr != "0.0.0.0") {
        oss << "DHCP_CLIENT_IP: " << dhcp_meta.ciaddr << " ";
    }
    if (!dhcp_meta.yiaddr.empty() && dhcp_meta.yiaddr != "0.0.0.0") {
        oss << "DHCP_YOUR_IP: " << dhcp_meta.yiaddr << " ";
    }
    if (!dhcp_meta.siaddr.empty() && dhcp_meta.siaddr != "0.0.0.0") {
        oss << "DHCP_SERVER_IP: " << dhcp_meta.siaddr << " ";
    }
    if (!dhcp_meta.giaddr.empty() && dhcp_meta.giaddr != "0.0.0.0") {
        oss << "DHCP_GATEWAY_IP: " << dhcp_meta.giaddr << " ";
    }
    
    if (!dhcp_meta.chaddr.empty()) {
        oss << "DHCP_CLIENT_MAC: " << dhcp_meta.chaddr << " ";
    }
    
    if (dhcp_meta.message_type != 0) {
        oss << "DHCP_MESSAGE_TYPE: " << static_cast<int>(dhcp_meta.message_type) << " ";
        oss << "DHCP_MESSAGE_TYPE_STR: " << dhcp_meta.message_type_str << " ";
    }
    
    if (dhcp_meta.lease_time != 0) {
        oss << "DHCP_LEASE_TIME: " << dhcp_meta.lease_time << " ";
    }
    
    if (!dhcp_meta.subnet_mask.empty() && dhcp_meta.subnet_mask != "0.0.0.0") {
        oss << "DHCP_SUBNET_MASK: " << dhcp_meta.subnet_mask << " ";
    }
    if (!dhcp_meta.router.empty() && dhcp_meta.router != "0.0.0.0") {
        oss << "DHCP_ROUTER: " << dhcp_meta.router << " ";
    }
    if (!dhcp_meta.dns_servers.empty()) {
        oss << "DHCP_DNS_SERVERS: " << dhcp_meta.dns_servers << " ";
    }
    if (!dhcp_meta.domain_name.empty()) {
        oss << "DHCP_DOMAIN_NAME: " << dhcp_meta.domain_name << " ";
    }
    if (!dhcp_meta.dhcp_server_id.empty() && dhcp_meta.dhcp_server_id != "0.0.0.0") {
        oss << "DHCP_SERVER_ID: " << dhcp_meta.dhcp_server_id << " ";
    }
    
    if (!dhcp_meta.sname.empty()) {
        oss << "DHCP_SERVER_NAME: " << dhcp_meta.sname << " ";
    }
    if (!dhcp_meta.file.empty()) {
        oss << "DHCP_BOOT_FILE: " << dhcp_meta.file << " ";
    }
    
    return oss.str();
}
