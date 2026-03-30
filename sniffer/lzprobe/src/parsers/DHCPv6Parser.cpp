#include "parsers/DHCPv6Parser.h"
#include <pcapplusplus/UdpLayer.h>
#include <pcapplusplus/IPv6Layer.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <sstream>
#include <iomanip>

// DHCPv6 option codes (RFC 3315, 3633, 3646, 4704)
enum DHCPv6OptionCode {
    DHCPV6_OPT_CLIENTID = 1,
    DHCPV6_OPT_SERVERID = 2,
    DHCPV6_OPT_IA_NA = 3,
    DHCPV6_OPT_IA_TA = 4,
    DHCPV6_OPT_IAADDR = 5,
    DHCPV6_OPT_ORO = 6,
    DHCPV6_OPT_PREFERENCE = 7,
    DHCPV6_OPT_ELAPSED_TIME = 8,
    DHCPV6_OPT_RELAY_MSG = 9,
    DHCPV6_OPT_AUTH = 11,
    DHCPV6_OPT_UNICAST = 12,
    DHCPV6_OPT_STATUS_CODE = 13,
    DHCPV6_OPT_RAPID_COMMIT = 14,
    DHCPV6_OPT_USER_CLASS = 15,
    DHCPV6_OPT_VENDOR_CLASS = 16,
    DHCPV6_OPT_VENDOR_OPTS = 17,
    DHCPV6_OPT_INTERFACE_ID = 18,
    DHCPV6_OPT_RECONF_MSG = 19,
    DHCPV6_OPT_RECONF_ACCEPT = 20,
    DHCPV6_OPT_SIP_SERVERS = 21,
    DHCPV6_OPT_DNS_SERVERS = 23,
    DHCPV6_OPT_DOMAIN_LIST = 24,
    DHCPV6_OPT_IA_PD = 25,
    DHCPV6_OPT_IA_PREFIX = 26,
    DHCPV6_OPT_NTP_SERVERS = 56,
    DHCPV6_OPT_END = 255
};

// DHCPv6 message types (RFC 3315)
enum DHCPv6MessageType {
    DHCPV6_MSG_SOLICIT = 1,
    DHCPV6_MSG_ADVERTISE = 2,
    DHCPV6_MSG_REQUEST = 3,
    DHCPV6_MSG_CONFIRM = 4,
    DHCPV6_MSG_RENEW = 5,
    DHCPV6_MSG_REBIND = 6,
    DHCPV6_MSG_REPLY = 7,
    DHCPV6_MSG_RELEASE = 8,
    DHCPV6_MSG_DECLINE = 9,
    DHCPV6_MSG_RECONFIGURE = 10,
    DHCPV6_MSG_INFORMATION_REQUEST = 11,
    DHCPV6_MSG_RELAY_FORW = 12,
    DHCPV6_MSG_RELAY_REPL = 13
};

bool DHCPv6Parser::parse(pcpp::Packet& packet, PacketMetadata& metadata) {
    // First check if this is a potential DHCPv6 packet based on UDP ports
    if (!isDHCPv6Packet(packet)) {
        return false;
    }
    
    // Check if this is an IPv6 packet
    auto* ipv6Layer = packet.getLayerOfType<pcpp::IPv6Layer>();
    if (!ipv6Layer) {
        return false;
    }
    
    // Get UDP layer
    auto* udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
    if (!udpLayer) {
        return false;
    }
    
    // Set DHCPv6 presence flag
    metadata.has_dhcpv6 = true;
    metadata.protocol = "UDP";
    metadata.application_protocol = "dhcpv6";
    
    // Get UDP payload (DHCPv6 data)
    const uint8_t* dhcpv6Data = udpLayer->getLayerPayload();
    size_t dhcpv6DataLen = udpLayer->getLayerPayloadSize();
    
    if (!dhcpv6Data || dhcpv6DataLen < 4) {
        return false;
    }
    
    // Validate DHCPv6 packet structure
    if (!validateDHCPv6Packet(dhcpv6Data, dhcpv6DataLen)) {
        return false;
    }
    
    // Parse DHCPv6 header
    if (!parseHeader(dhcpv6Data, metadata)) {
        return false;
    }
    
    // Parse DHCPv6 options
    if (dhcpv6DataLen > 4) {
        if (!parseOptions(dhcpv6Data + 4, dhcpv6DataLen - 4, metadata)) {
            // Options parsing failed, but we still have valid header
            // Continue with basic information
        }
    }
    
    return true;
}

bool DHCPv6Parser::isDHCPv6Packet(pcpp::Packet& packet) {
    auto* udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
    if (!udpLayer) {
        return false;
    }
    
    uint16_t srcPort = udpLayer->getSrcPort();
    uint16_t dstPort = udpLayer->getDstPort();
    
    // DHCPv6 uses ports 546 (client) and 547 (server)
    // Client->Server: src=546, dst=547
    // Server->Client: src=547, dst=546
    return (srcPort == 546 && dstPort == 547) || (srcPort == 547 && dstPort == 546);
}

bool DHCPv6Parser::validateDHCPv6Packet(const uint8_t* data, size_t length) {
    // Minimum DHCPv6 packet size (message type + transaction ID)
    if (length < 4) {
        return false;
    }
    
    // Check message type validity
    uint8_t msgType = data[0];
    if (msgType < 1 || msgType > 13) {
        return false;
    }
    
    return true;
}

bool DHCPv6Parser::parseHeader(const uint8_t* data, PacketMetadata& metadata) {
    // Parse DHCPv6 header fields
    metadata.dhcpv6.msg_type = data[0];
    metadata.dhcpv6.message_type = data[0];
    
    // Transaction ID is 3 bytes starting at offset 1
    metadata.dhcpv6.transaction_id = (data[1] << 16) | (data[2] << 8) | data[3];
    
    // Set human-readable message type
    metadata.dhcpv6.message_type_str = getMessageTypeString(data[0]);
    
    return true;
}

bool DHCPv6Parser::parseOptions(const uint8_t* data, size_t length, PacketMetadata& metadata) {
    size_t offset = 0;
    
    while (offset + 4 <= length) {
        // Parse option header
        uint16_t optionCode = (data[offset] << 8) | data[offset + 1];
        uint16_t optionLen = (data[offset + 2] << 8) | data[offset + 3];
        
        // Check if we have enough data for the option
        if (offset + 4 + optionLen > length) {
            break;
        }
        
        const uint8_t* optionData = data + offset + 4;
        
        // Parse specific options
        switch (optionCode) {
            case DHCPV6_OPT_CLIENTID:
                if (optionLen >= 2) {
                    uint16_t duidType = (optionData[0] << 8) | optionData[1];
                    metadata.dhcpv6.client_id = "DUID-" + std::to_string(duidType) + ":" + 
                                               duidToString(optionData + 2, optionLen - 2);
                }
                break;
                
            case DHCPV6_OPT_SERVERID:
                if (optionLen >= 2) {
                    uint16_t duidType = (optionData[0] << 8) | optionData[1];
                    metadata.dhcpv6.server_id = "DUID-" + std::to_string(duidType) + ":" + 
                                               duidToString(optionData + 2, optionLen - 2);
                }
                break;
                
            case DHCPV6_OPT_IA_NA:
                if (optionLen >= 12) {
                    uint32_t iaid = (optionData[0] << 24) | (optionData[1] << 16) | 
                                   (optionData[2] << 8) | optionData[3];
                    uint32_t t1 = (optionData[4] << 24) | (optionData[5] << 16) | 
                                 (optionData[6] << 8) | optionData[7];
                    uint32_t t2 = (optionData[8] << 24) | (optionData[9] << 16) | 
                                 (optionData[10] << 8) | optionData[11];
                    metadata.dhcpv6.ia_na = "IAID:" + std::to_string(iaid) + 
                                           " T1:" + std::to_string(t1) + 
                                           " T2:" + std::to_string(t2);
                }
                break;
                
            case DHCPV6_OPT_IA_TA:
                if (optionLen >= 4) {
                    uint32_t iaid = (optionData[0] << 24) | (optionData[1] << 16) | 
                                   (optionData[2] << 8) | optionData[3];
                    metadata.dhcpv6.ia_ta = "IAID:" + std::to_string(iaid);
                }
                break;
                
            case DHCPV6_OPT_IAADDR:
                if (optionLen >= 24) {
                    std::string ipv6 = ipv6ToString(optionData);
                    uint32_t preferred = (optionData[16] << 24) | (optionData[17] << 16) | 
                                        (optionData[18] << 8) | optionData[19];
                    uint32_t valid = (optionData[20] << 24) | (optionData[21] << 16) | 
                                   (optionData[22] << 8) | optionData[23];
                    metadata.dhcpv6.iaaddr = "IPv6:" + ipv6 + 
                                            " Preferred:" + std::to_string(preferred) + 
                                            " Valid:" + std::to_string(valid);
                }
                break;
                
            case DHCPV6_OPT_DNS_SERVERS:
                if (optionLen >= 16 && optionLen % 16 == 0) {
                    std::ostringstream dns_ss;
                    size_t num_dns = optionLen / 16;
                    for (size_t i = 0; i < num_dns; ++i) {
                        if (i > 0) dns_ss << ",";
                        dns_ss << ipv6ToString(optionData + i * 16);
                    }
                    metadata.dhcpv6.dns_servers = dns_ss.str();
                }
                break;
                
            case DHCPV6_OPT_DOMAIN_LIST:
                if (optionLen > 0) {
                    // Parse domain list (simplified - just take first domain)
                    size_t domain_len = optionData[0];
                    if (domain_len > 0 && domain_len < optionLen) {
                        metadata.dhcpv6.domain_list = std::string(
                            reinterpret_cast<const char*>(optionData + 1), 
                            domain_len
                        );
                    }
                }
                break;
                
            case DHCPV6_OPT_SIP_SERVERS:
                if (optionLen >= 16 && optionLen % 16 == 0) {
                    std::ostringstream sip_ss;
                    size_t num_sip = optionLen / 16;
                    for (size_t i = 0; i < num_sip; ++i) {
                        if (i > 0) sip_ss << ",";
                        sip_ss << ipv6ToString(optionData + i * 16);
                    }
                    metadata.dhcpv6.sip_servers = sip_ss.str();
                }
                break;
                
            case DHCPV6_OPT_NTP_SERVERS:
                if (optionLen >= 16 && optionLen % 16 == 0) {
                    std::ostringstream ntp_ss;
                    size_t num_ntp = optionLen / 16;
                    for (size_t i = 0; i < num_ntp; ++i) {
                        if (i > 0) ntp_ss << ",";
                        ntp_ss << ipv6ToString(optionData + i * 16);
                    }
                    metadata.dhcpv6.ntp_servers = ntp_ss.str();
                }
                break;
                
            case DHCPV6_OPT_RAPID_COMMIT:
                metadata.dhcpv6.rapid_commit = "YES";
                break;
                
            case DHCPV6_OPT_USER_CLASS:
                if (optionLen > 0) {
                    metadata.dhcpv6.user_class = "Length:" + std::to_string(optionLen);
                }
                break;
                
            case DHCPV6_OPT_VENDOR_CLASS:
                if (optionLen >= 4) {
                    uint32_t vendor_id = (optionData[0] << 24) | (optionData[1] << 16) | 
                                        (optionData[2] << 8) | optionData[3];
                    metadata.dhcpv6.vendor_class = "VendorID:" + std::to_string(vendor_id);
                }
                break;
                
            case DHCPV6_OPT_VENDOR_OPTS:
                if (optionLen >= 4) {
                    uint32_t vendor_id = (optionData[0] << 24) | (optionData[1] << 16) | 
                                        (optionData[2] << 8) | optionData[3];
                    metadata.dhcpv6.vendor_opts = "VendorID:" + std::to_string(vendor_id);
                }
                break;
                
            case DHCPV6_OPT_INTERFACE_ID:
                if (optionLen > 0) {
                    metadata.dhcpv6.interface_id = "Length:" + std::to_string(optionLen);
                }
                break;
                
            case DHCPV6_OPT_RECONF_MSG:
                if (optionLen >= 1) {
                    uint8_t msg_type = optionData[0];
                    metadata.dhcpv6.reconfigure_msg = "Type:" + std::to_string(msg_type);
                }
                break;
                
            case DHCPV6_OPT_RECONF_ACCEPT:
                metadata.dhcpv6.reconfigure_accept = "YES";
                break;
                
            case DHCPV6_OPT_END:
                // End of options
                return true;
        }
        
        // Move to next option
        offset += 4 + optionLen;
    }
    
    return true;
}

std::string DHCPv6Parser::ipv6ToString(const uint8_t* ipv6) {
    std::ostringstream oss;
    for (int i = 0; i < 16; i++) {
        if (i > 0) oss << ":";
        oss << std::hex << std::setw(2) << std::setfill('0') 
            << static_cast<int>(ipv6[i]);
    }
    return oss.str();
}

std::string DHCPv6Parser::duidToString(const uint8_t* duid, uint16_t length) {
    std::ostringstream oss;
    for (uint16_t i = 0; i < length && i < 128; ++i) {
        if (i > 0) oss << ":";
        oss << std::hex << std::setw(2) << std::setfill('0') 
            << static_cast<int>(duid[i]);
    }
    return oss.str();
}

std::string DHCPv6Parser::getMessageTypeString(uint8_t type) {
    switch (type) {
        case DHCPV6_MSG_SOLICIT: return "SOLICIT";
        case DHCPV6_MSG_ADVERTISE: return "ADVERTISE";
        case DHCPV6_MSG_REQUEST: return "REQUEST";
        case DHCPV6_MSG_CONFIRM: return "CONFIRM";
        case DHCPV6_MSG_RENEW: return "RENEW";
        case DHCPV6_MSG_REBIND: return "REBIND";
        case DHCPV6_MSG_REPLY: return "REPLY";
        case DHCPV6_MSG_RELEASE: return "RELEASE";
        case DHCPV6_MSG_DECLINE: return "DECLINE";
        case DHCPV6_MSG_RECONFIGURE: return "RECONFIGURE";
        case DHCPV6_MSG_INFORMATION_REQUEST: return "INFORMATION_REQUEST";
        case DHCPV6_MSG_RELAY_FORW: return "RELAY_FORW";
        case DHCPV6_MSG_RELAY_REPL: return "RELAY_REPL";
        default: return "UNKNOWN(" + std::to_string(type) + ")";
    }
}

void DHCPv6Parser::formatForCSV(const DHCPv6Metadata& dhcpv6_meta, std::ostringstream& line, const std::string& separator) {
    line << "DHCPV6_MSG_TYPE:" << static_cast<int>(dhcpv6_meta.msg_type) << separator;
    line << "DHCPV6_MSG_TYPE_STR:" << dhcpv6_meta.message_type_str << separator;
    line << "DHCPV6_TRANSACTION_ID:0x" << std::hex << dhcpv6_meta.transaction_id << std::dec << separator;
    
    line << "DHCPV6_CLIENT_ID:" << dhcpv6_meta.client_id << separator;
    line << "DHCPV6_SERVER_ID:" << dhcpv6_meta.server_id << separator;
    line << "DHCPV6_IA_NA:" << dhcpv6_meta.ia_na << separator;
    line << "DHCPV6_IA_TA:" << dhcpv6_meta.ia_ta << separator;
    line << "DHCPV6_IAADDR:" << dhcpv6_meta.iaaddr << separator;
    line << "DHCPV6_DNS_SERVERS:" << dhcpv6_meta.dns_servers << separator;
    line << "DHCPV6_DOMAIN_LIST:" << dhcpv6_meta.domain_list << separator;
    line << "DHCPV6_SIP_SERVERS:" << dhcpv6_meta.sip_servers << separator;
    line << "DHCPV6_NTP_SERVERS:" << dhcpv6_meta.ntp_servers << separator;
    line << "DHCPV6_RAPID_COMMIT:" << dhcpv6_meta.rapid_commit << separator;
    line << "DHCPV6_USER_CLASS:" << dhcpv6_meta.user_class << separator;
    line << "DHCPV6_VENDOR_CLASS:" << dhcpv6_meta.vendor_class << separator;
    line << "DHCPV6_VENDOR_OPTS:" << dhcpv6_meta.vendor_opts << separator;
    line << "DHCPV6_INTERFACE_ID:" << dhcpv6_meta.interface_id << separator;
    line << "DHCPV6_RECONF_MSG:" << dhcpv6_meta.reconfigure_msg << separator;
    line << "DHCPV6_RECONF_ACCEPT:" << dhcpv6_meta.reconfigure_accept << separator;
}

void DHCPv6Parser::formatForJSON(const DHCPv6Metadata& dhcpv6_meta, std::ostringstream& oss, const std::function<std::string(const std::string&)>& escapeJsonString) {
    oss << "\"DHCPV6_MSG_TYPE\":" << static_cast<int>(dhcpv6_meta.msg_type) << ",";
    oss << "\"DHCPV6_MSG_TYPE_STR\":\"" << escapeJsonString(dhcpv6_meta.message_type_str) << "\",";
    oss << "\"DHCPV6_TRANSACTION_ID\":\"0x" << std::hex << dhcpv6_meta.transaction_id << std::dec << "\",";
    
    oss << "\"DHCPV6_CLIENT_ID\":\"" << escapeJsonString(dhcpv6_meta.client_id) << "\",";
    oss << "\"DHCPV6_SERVER_ID\":\"" << escapeJsonString(dhcpv6_meta.server_id) << "\",";
    oss << "\"DHCPV6_IA_NA\":\"" << escapeJsonString(dhcpv6_meta.ia_na) << "\",";
    oss << "\"DHCPV6_IA_TA\":\"" << escapeJsonString(dhcpv6_meta.ia_ta) << "\",";
    oss << "\"DHCPV6_IAADDR\":\"" << escapeJsonString(dhcpv6_meta.iaaddr) << "\",";
    oss << "\"DHCPV6_DNS_SERVERS\":\"" << escapeJsonString(dhcpv6_meta.dns_servers) << "\",";
    oss << "\"DHCPV6_DOMAIN_LIST\":\"" << escapeJsonString(dhcpv6_meta.domain_list) << "\",";
    oss << "\"DHCPV6_SIP_SERVERS\":\"" << escapeJsonString(dhcpv6_meta.sip_servers) << "\",";
    oss << "\"DHCPV6_NTP_SERVERS\":\"" << escapeJsonString(dhcpv6_meta.ntp_servers) << "\",";
    oss << "\"DHCPV6_RAPID_COMMIT\":\"" << escapeJsonString(dhcpv6_meta.rapid_commit) << "\",";
    oss << "\"DHCPV6_USER_CLASS\":\"" << escapeJsonString(dhcpv6_meta.user_class) << "\",";
    oss << "\"DHCPV6_VENDOR_CLASS\":\"" << escapeJsonString(dhcpv6_meta.vendor_class) << "\",";
    oss << "\"DHCPV6_VENDOR_OPTS\":\"" << escapeJsonString(dhcpv6_meta.vendor_opts) << "\",";
    oss << "\"DHCPV6_INTERFACE_ID\":\"" << escapeJsonString(dhcpv6_meta.interface_id) << "\",";
    oss << "\"DHCPV6_RECONF_MSG\":\"" << escapeJsonString(dhcpv6_meta.reconfigure_msg) << "\",";
    oss << "\"DHCPV6_RECONF_ACCEPT\":\"" << escapeJsonString(dhcpv6_meta.reconfigure_accept) << "\",";
}

std::string DHCPv6Parser::formatForConsole(const DHCPv6Metadata& dhcpv6_meta) {
    std::ostringstream oss;
    oss << "HAS_DHCPV6: YES ";
    oss << "DHCPV6_MSG_TYPE: " << static_cast<int>(dhcpv6_meta.msg_type) << " ";
    oss << "DHCPV6_MSG_TYPE_STR: " << dhcpv6_meta.message_type_str << " ";
    oss << "DHCPV6_TRANSACTION_ID: 0x" << std::hex << dhcpv6_meta.transaction_id << std::dec << " ";
    
    if (!dhcpv6_meta.client_id.empty()) {
        oss << "DHCPV6_CLIENT_ID: " << dhcpv6_meta.client_id << " ";
    }
    if (!dhcpv6_meta.server_id.empty()) {
        oss << "DHCPV6_SERVER_ID: " << dhcpv6_meta.server_id << " ";
    }
    if (!dhcpv6_meta.ia_na.empty()) {
        oss << "DHCPV6_IA_NA: " << dhcpv6_meta.ia_na << " ";
    }
    if (!dhcpv6_meta.ia_ta.empty()) {
        oss << "DHCPV6_IA_TA: " << dhcpv6_meta.ia_ta << " ";
    }
    if (!dhcpv6_meta.iaaddr.empty()) {
        oss << "DHCPV6_IAADDR: " << dhcpv6_meta.iaaddr << " ";
    }
    if (!dhcpv6_meta.dns_servers.empty()) {
        oss << "DHCPV6_DNS_SERVERS: " << dhcpv6_meta.dns_servers << " ";
    }
    if (!dhcpv6_meta.domain_list.empty()) {
        oss << "DHCPV6_DOMAIN_LIST: " << dhcpv6_meta.domain_list << " ";
    }
    if (!dhcpv6_meta.sip_servers.empty()) {
        oss << "DHCPV6_SIP_SERVERS: " << dhcpv6_meta.sip_servers << " ";
    }
    if (!dhcpv6_meta.ntp_servers.empty()) {
        oss << "DHCPV6_NTP_SERVERS: " << dhcpv6_meta.ntp_servers << " ";
    }
    if (!dhcpv6_meta.rapid_commit.empty()) {
        oss << "DHCPV6_RAPID_COMMIT: " << dhcpv6_meta.rapid_commit << " ";
    }
    if (!dhcpv6_meta.user_class.empty()) {
        oss << "DHCPV6_USER_CLASS: " << dhcpv6_meta.user_class << " ";
    }
    if (!dhcpv6_meta.vendor_class.empty()) {
        oss << "DHCPV6_VENDOR_CLASS: " << dhcpv6_meta.vendor_class << " ";
    }
    if (!dhcpv6_meta.vendor_opts.empty()) {
        oss << "DHCPV6_VENDOR_OPTS: " << dhcpv6_meta.vendor_opts << " ";
    }
    if (!dhcpv6_meta.interface_id.empty()) {
        oss << "DHCPV6_INTERFACE_ID: " << dhcpv6_meta.interface_id << " ";
    }
    if (!dhcpv6_meta.reconfigure_msg.empty()) {
        oss << "DHCPV6_RECONF_MSG: " << dhcpv6_meta.reconfigure_msg << " ";
    }
    if (!dhcpv6_meta.reconfigure_accept.empty()) {
        oss << "DHCPV6_RECONF_ACCEPT: " << dhcpv6_meta.reconfigure_accept << " ";
    }
    
    return oss.str();
}

