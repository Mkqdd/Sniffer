#include "LoggerManager.h"
#include "BaseParser.h"
#include "parsers/DHCPParser.h"
#include "parsers/DHCPv6Parser.h"
#include "parsers/DNSParser.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <mutex>

LoggerManager::LoggerManager() : outputDirectory("logs"), useJsonFormat(false) {
    // Don't initialize log files here - wait for explicit initialization
}

LoggerManager::LoggerManager(const std::string& outputDir) : outputDirectory(outputDir), useJsonFormat(false) {
    // Don't initialize log files here - wait for explicit initialization
}

void LoggerManager::initializeLogFiles() {
    // Create output directory if it doesn't exist
    std::string cmd = "mkdir -p " + outputDirectory;
    system(cmd.c_str());
    
    // Initialize log files in current output directory
    logFile.open(outputDirectory + "/packet_capture.log");
    ethernetLogFile.open(outputDirectory + "/ethernet_packets.log");
    wifiLogFile.open(outputDirectory + "/wifi_packets.log");
    errorLogFile.open(outputDirectory + "/error_packets.log");
    connLogFile.open(outputDirectory + "/conn.log");
}

void LoggerManager::setOutputFormat(bool useJson) {
    useJsonFormat = useJson;
}

void LoggerManager::setOutputDirectory(const std::string& outputDir) {
    std::lock_guard<std::mutex> lock(logMutex);
    
    // Close existing files
    if (logFile.is_open()) logFile.close();
    if (ethernetLogFile.is_open()) ethernetLogFile.close();
    if (wifiLogFile.is_open()) wifiLogFile.close();
    if (errorLogFile.is_open()) errorLogFile.close();
    if (connLogFile.is_open()) connLogFile.close();
    
    // Update output directory
    outputDirectory = outputDir;
    
    // Initialize log files in new directory
    initializeLogFiles();
}

void LoggerManager::setOutputDirectoryFromFile(const std::string& inputFile, const std::string& baseOutputDir) {
    // Extract filename from path
    std::string filename = inputFile;
    size_t lastSlash = filename.find_last_of("/\\");
    if (lastSlash != std::string::npos) {
        filename = filename.substr(lastSlash + 1);
    }
    
    // Extract protocol name from filename (remove _test.pcap suffix)
    std::string protocolName = filename;
    
    // Remove .pcap extension
    size_t dotPos = protocolName.find_last_of('.');
    if (dotPos != std::string::npos) {
        protocolName = protocolName.substr(0, dotPos);
    }
    
    // Remove _test suffix if present
    size_t testPos = protocolName.find("_test");
    if (testPos != std::string::npos) {
        protocolName = protocolName.substr(0, testPos);
    }
    
    // Create subdirectory path and update output directory
    outputDirectory = baseOutputDir + "/" + protocolName;
    
    // Initialize log files in the new directory
    initializeLogFiles();
}

LoggerManager::~LoggerManager() {
    if (logFile.is_open()) logFile.close();
    if (ethernetLogFile.is_open()) ethernetLogFile.close();
    if (wifiLogFile.is_open()) wifiLogFile.close();
    if (errorLogFile.is_open()) errorLogFile.close();
}

void LoggerManager::logPacket(const PacketMetadata& metadata) {
    if (useJsonFormat) {
        logPacketJSON(metadata);
    } else {
        logPacketCSV(metadata);
    }
}

void LoggerManager::logPacketCSV(const PacketMetadata& metadata) {
    std::lock_guard<std::mutex> lock(logMutex);
    
    std::ostringstream oss;
    const std::string separator = ",";  // Can be changed to "," for CSV format
    
    // Basic metadata
    oss << std::fixed << std::setprecision(6) << "TIMESTAMP:" << metadata.timestamp << separator;
    
    // Data link layer metadata
    if (metadata.has_ethernet) {
        oss << "SRC_MAC:";
        for (int i = 0; i < 6; i++) {
            if (i > 0) oss << ":";
            oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(metadata.ethernet.src_mac[i]);
        }
        oss << std::dec << std::setfill(' ') << separator;
        
        oss << "DST_MAC:";
        for (int i = 0; i < 6; i++) {
            if (i > 0) oss << ":";
            oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(metadata.ethernet.dst_mac[i]);
        }
        oss << std::dec << std::setfill(' ') << separator;
        
        oss << "ETHERTYPE:" << BaseParser::etherTypeToString(metadata.ethernet.ethertype) << separator;
    } else if (metadata.has_wifi) {
        // WiFi metadata
        oss << "WIFI_SRC_MAC:";
        for (int i = 0; i < 6; i++) {
            if (i > 0) oss << ":";
            oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(metadata.wifi.src_mac[i]);
        }
        oss << std::dec << std::setfill(' ') << separator;
        
        oss << "WIFI_DST_MAC:";
        for (int i = 0; i < 6; i++) {
            if (i > 0) oss << ":";
            oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(metadata.wifi.dst_mac[i]);
        }
        oss << std::dec << std::setfill(' ') << separator;
        
        oss << "WIFI_BSSID:";
        for (int i = 0; i < 6; i++) {
            if (i > 0) oss << ":";
            oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(metadata.wifi.bssid[i]);
        }
        oss << std::dec << std::setfill(' ') << separator;
        
        oss << "WIFI_FRAME_TYPE:" << static_cast<int>(metadata.wifi.frame_type) << separator;
        oss << "WIFI_FRAME_SUBTYPE:" << static_cast<int>(metadata.wifi.frame_subtype) << separator;
        oss << "WIFI_TO_DS:" << (metadata.wifi.to_ds ? "1" : "0") << separator;
        oss << "WIFI_FROM_DS:" << (metadata.wifi.from_ds ? "1" : "0") << separator;
        oss << "WIFI_SEQUENCE:" << metadata.wifi.sequence_number << separator;
        
        if (metadata.wifi.rssi != 0) oss << "WIFI_RSSI:" << static_cast<int>(metadata.wifi.rssi) << separator;
        if (metadata.wifi.channel != 0) oss << "WIFI_CHANNEL:" << static_cast<int>(metadata.wifi.channel) << separator;
    } else {
        oss << "SRC_MAC:00:00:00:00:00:00" << separator;
        oss << "DST_MAC:00:00:00:00:00:00" << separator;
        oss << "ETHERTYPE:0" << separator;
    }
    
    // VLAN metadata - only output if VLAN is present
    if (metadata.has_vlan) {
        oss << "HAS_VLAN:1" << separator;
        oss << "VLAN_ID:" << metadata.vlan.vlan_id << separator;
        oss << "VLAN_PRIORITY:" << static_cast<int>(metadata.vlan.vlan_priority) << separator;
    }
    
    // GRE metadata
    if (metadata.has_gre) {
        oss << "HAS_GRE:1" << separator;
        oss << "GRE_VERSION:" << static_cast<int>(metadata.gre.version) << separator;
        oss << "GRE_PROTOCOL:" << std::hex << metadata.gre.protocol << std::dec << separator;
        oss << "GRE_RECURSION_CONTROL:" << static_cast<int>(metadata.gre.recursion_control) << separator;
        oss << "GRE_CHECKSUM_BIT:" << (metadata.gre.checksum_bit ? "1" : "0") << separator;
        oss << "GRE_ROUTING_BIT:" << (metadata.gre.routing_bit ? "1" : "0") << separator;
        oss << "GRE_KEY_BIT:" << (metadata.gre.key_bit ? "1" : "0") << separator;
        oss << "GRE_SEQUENCE_BIT:" << (metadata.gre.sequence_bit ? "1" : "0") << separator;
        oss << "GRE_STRICT_SOURCE_ROUTE:" << (metadata.gre.strict_source_route ? "1" : "0") << separator;
        oss << "GRE_ACK_SEQUENCE_BIT:" << (metadata.gre.ack_sequence_bit ? "1" : "0") << separator;
        
        if (metadata.gre.checksum_bit) {
            oss << "GRE_CHECKSUM:" << std::hex << metadata.gre.checksum << std::dec << separator;
        } else {
            oss << "GRE_CHECKSUM:0" << separator;
        }
        
        if (metadata.gre.routing_bit) {
            oss << "GRE_OFFSET:" << metadata.gre.offset << separator;
        } else {
            oss << "GRE_OFFSET:0" << separator;
        }
        
        if (metadata.gre.key_bit) {
            oss << "GRE_KEY:" << std::hex << metadata.gre.key << std::dec << separator;
        } else {
            oss << "GRE_KEY:0" << separator;
        }
        
        if (metadata.gre.sequence_bit) {
            oss << "GRE_SEQUENCE:" << metadata.gre.sequence << separator;
        } else {
            oss << "GRE_SEQUENCE:0" << separator;
        }
        
        if (metadata.gre.ack_sequence_bit) {
            oss << "GRE_ACK_SEQUENCE:" << metadata.gre.ack_sequence << separator;
        } else {
            oss << "GRE_ACK_SEQUENCE:0" << separator;
        }
        
        if (metadata.gre.version == 1) {
            oss << "GRE_PAYLOAD_LENGTH:" << metadata.gre.payload_length << separator;
            oss << "GRE_CALL_ID:" << metadata.gre.call_id << separator;
        } else {
            oss << "GRE_PAYLOAD_LENGTH:0" << separator;
            oss << "GRE_CALL_ID:0" << separator;
        }
    }
    
    // Network layer metadata
    oss << "SRC_IP:" << metadata.srcIP << separator;
    oss << "DST_IP:" << metadata.dstIP << separator;
    oss << "PROTOCOL:" << metadata.protocol << separator;
    
    // IPv6 specific fields (only output if IPv6 is present)
    if (metadata.has_ipv6) {
        oss << "IPV6_HOP_LIMIT:" << static_cast<int>(metadata.ipv6.hop_limit) << separator;
        oss << "IPV6_FLOW_LABEL:" << metadata.ipv6.flow_label << separator;
        oss << "IPV6_TRAFFIC_CLASS:" << static_cast<int>(metadata.ipv6.traffic_class) << separator;
        oss << "IPV6_NEXT_HEADER:" << static_cast<int>(metadata.ipv6.next_header) << separator;
        oss << "IPV6_PAYLOAD_LENGTH:" << metadata.ipv6.payload_length << separator;
        
        // IPv6 extension headers
        if (metadata.ipv6.hop_by_hop.present) {
            oss << "IPV6_HOP_BY_HOP:1" << separator;
            oss << "IPV6_HOP_BY_HOP_TYPE:" << static_cast<int>(metadata.ipv6.hop_by_hop.type) << separator;
            oss << "IPV6_HOP_BY_HOP_LENGTH:" << static_cast<int>(metadata.ipv6.hop_by_hop.length) << separator;
        }
        
        if (metadata.ipv6.routing.present) {
            oss << "IPV6_ROUTING:1" << separator;
            oss << "IPV6_ROUTING_TYPE:" << static_cast<int>(metadata.ipv6.routing.type) << separator;
            oss << "IPV6_ROUTING_LENGTH:" << static_cast<int>(metadata.ipv6.routing.length) << separator;
            oss << "IPV6_ROUTING_TYPE_VALUE:" << static_cast<int>(metadata.ipv6.routing_type) << separator;
            oss << "IPV6_SEGMENTS_LEFT:" << static_cast<int>(metadata.ipv6.segments_left) << separator;
        }
        
        if (metadata.ipv6.fragment.present) {
            oss << "IPV6_FRAGMENT:1" << separator;
            oss << "IPV6_FRAGMENT_TYPE:" << static_cast<int>(metadata.ipv6.fragment.type) << separator;
            oss << "IPV6_FRAGMENT_LENGTH:" << static_cast<int>(metadata.ipv6.fragment.length) << separator;
            oss << "IPV6_FRAGMENT_OFFSET:" << metadata.ipv6.fragment_offset << separator;
            oss << "IPV6_FRAGMENT_MORE:" << (metadata.ipv6.fragment_more ? "1" : "0") << separator;
            oss << "IPV6_FRAGMENT_ID:" << metadata.ipv6.fragment_id << separator;
        }
        
        if (metadata.ipv6.destination.present) {
            oss << "IPV6_DESTINATION:1" << separator;
            oss << "IPV6_DESTINATION_TYPE:" << static_cast<int>(metadata.ipv6.destination.type) << separator;
            oss << "IPV6_DESTINATION_LENGTH:" << static_cast<int>(metadata.ipv6.destination.length) << separator;
        }
        
        if (metadata.ipv6.ah.present) {
            oss << "IPV6_AH:1" << separator;
            oss << "IPV6_AH_TYPE:" << static_cast<int>(metadata.ipv6.ah.type) << separator;
            oss << "IPV6_AH_LENGTH:" << static_cast<int>(metadata.ipv6.ah.length) << separator;
        }
        
        if (metadata.ipv6.esp.present) {
            oss << "IPV6_ESP:1" << separator;
            oss << "IPV6_ESP_TYPE:" << static_cast<int>(metadata.ipv6.esp.type) << separator;
            oss << "IPV6_ESP_LENGTH:" << static_cast<int>(metadata.ipv6.esp.length) << separator;
        }
    }
    
    // Transport layer metadata
    oss << "SRC_PORT:" << metadata.srcPort << separator;
    oss << "DST_PORT:" << metadata.dstPort << separator;
    
    // TCP specific fields
    if (metadata.has_tcp) {
        oss << "TCP_SEQ:" << metadata.tcp.seq << separator;
        oss << "TCP_ACK:" << metadata.tcp.ack << separator;
        
        // TCP flags - output readable flags
        if (metadata.tcp.flags > 0) {
            oss << "TCP_FLAGS:[";
            if (metadata.tcp.syn) oss << "S";  // SYN
            if (metadata.tcp.ack_flag) oss << "A";  // ACK
            if (metadata.tcp.fin) oss << "F";  // FIN
            if (metadata.tcp.rst) oss << "R";  // RST
            if (metadata.tcp.psh) oss << "P";  // PSH
            oss << "]" << separator;
        } else {
            oss << "TCP_FLAGS:0" << separator;
        }
        
        oss << "TCP_WINDOW:" << metadata.tcp.window << separator;
    } else {
        oss << "TCP_SEQ:0" << separator;
        oss << "TCP_ACK:0" << separator;
        oss << "TCP_FLAGS:0" << separator;
        oss << "TCP_WINDOW:0" << separator;
    }
    
    // UDP specific fields
    if (metadata.has_udp) {
        oss << "UDP_LENGTH:" << metadata.udp.length << separator;
    } else {
        oss << "UDP_LENGTH:0" << separator;
    }
    
    // ARP specific fields (only output if ARP is present)
    if (metadata.has_arp) {
        oss << "ARP_HARDWARE_TYPE:" << metadata.arp.hardware_type << separator;
        oss << "ARP_PROTOCOL_TYPE:0x" << std::hex << metadata.arp.protocol_type << std::dec << separator;
        
        // Convert ARP operation to string
        std::string arpOpStr;
        switch (metadata.arp.operation) {
            case 1: arpOpStr = "REQUEST"; break;
            case 2: arpOpStr = "REPLY"; break;
            case 3: arpOpStr = "RARP_REQUEST"; break;
            case 4: arpOpStr = "RARP_REPLY"; break;
            case 5: arpOpStr = "DRARP_REQUEST"; break;
            case 6: arpOpStr = "DRARP_REPLY"; break;
            case 7: arpOpStr = "DRARP_ERROR"; break;
            case 8: arpOpStr = "INARP_REQUEST"; break;
            case 9: arpOpStr = "INARP_REPLY"; break;
            default: arpOpStr = "UNKNOWN(" + std::to_string(metadata.arp.operation) + ")"; break;
        }
        oss << "ARP_OPERATION:" << arpOpStr << separator;
        
        oss << "ARP_SENDER_MAC:" << metadata.arp.sender_mac_str << separator;
        oss << "ARP_SENDER_IP:" << metadata.arp.sender_ip_str << separator;
        oss << "ARP_TARGET_MAC:" << metadata.arp.target_mac_str << separator;
        oss << "ARP_TARGET_IP:" << metadata.arp.target_ip_str << separator;
    }
    
    // ICMP specific fields (only output if ICMP is present)
    if (metadata.has_icmp) {
        // Convert ICMP type to string
        std::string icmpTypeStr;
        switch (metadata.icmp.type) {
            case 0: icmpTypeStr = "ECHO_REPLY"; break;
            case 3: icmpTypeStr = "DEST_UNREACHABLE"; break;
            case 4: icmpTypeStr = "SOURCE_QUENCH"; break;
            case 5: icmpTypeStr = "REDIRECT"; break;
            case 8: icmpTypeStr = "ECHO_REQUEST"; break;
            case 11: icmpTypeStr = "TIME_EXCEEDED"; break;
            case 12: icmpTypeStr = "PARAM_PROBLEM"; break;
            case 13: icmpTypeStr = "TIMESTAMP_REQUEST"; break;
            case 14: icmpTypeStr = "TIMESTAMP_REPLY"; break;
            case 15: icmpTypeStr = "INFO_REQUEST"; break;
            case 16: icmpTypeStr = "INFO_REPLY"; break;
            default: icmpTypeStr = "TYPE_" + std::to_string(metadata.icmp.type); break;
        }
        oss << "ICMP_TYPE:" << icmpTypeStr << separator;
        oss << "ICMP_CODE:" << (int)metadata.icmp.code << separator;
        oss << "ICMP_CHECKSUM:0x" << std::hex << metadata.icmp.checksum << std::dec << separator;
        
        // For echo request/reply
        if (metadata.icmp.type == 0 || metadata.icmp.type == 8) {
            oss << "ICMP_IDENTIFIER:" << metadata.icmp.identifier << separator;
            oss << "ICMP_SEQUENCE:" << metadata.icmp.sequence << separator;
        }
        
        // For destination unreachable
        if (metadata.icmp.type == 3) {
            oss << "ICMP_ORIGINAL_IP:" << 
                ((metadata.icmp.original_ip >> 24) & 0xFF) << "." <<
                ((metadata.icmp.original_ip >> 16) & 0xFF) << "." <<
                ((metadata.icmp.original_ip >> 8) & 0xFF) << "." <<
                (metadata.icmp.original_ip & 0xFF) << separator;
            oss << "ICMP_ORIGINAL_PROTOCOL:" << (int)metadata.icmp.original_protocol << separator;
            oss << "ICMP_ORIGINAL_PORT:" << metadata.icmp.original_port << separator;
        }
        
        // For redirect messages
        if (metadata.icmp.type == 5) {
            oss << "ICMP_GATEWAY_IP:" << 
                ((metadata.icmp.gateway_ip >> 24) & 0xFF) << "." <<
                ((metadata.icmp.gateway_ip >> 16) & 0xFF) << "." <<
                ((metadata.icmp.gateway_ip >> 8) & 0xFF) << "." <<
                (metadata.icmp.gateway_ip & 0xFF) << separator;
        }
    }
    
    // HTTP specific fields
    if (metadata.has_http) {
        oss << "HTTP_TYPE:" << metadata.http.type << separator;
        oss << "HTTP_METHOD:" << metadata.http.method << separator;
        oss << "HTTP_URI:" << metadata.http.uri << separator;
        oss << "HTTP_VERSION:" << metadata.http.version << separator;
        
        if (metadata.http.is_response) {
            oss << "HTTP_STATUS_CODE:" << metadata.http.status_code << separator;
            oss << "HTTP_STATUS_TEXT:" << metadata.http.status_text << separator;
        }
        
        // Common HTTP headers
        if (!metadata.http.host.empty()) oss << "HTTP_HOST:" << metadata.http.host << separator;
        if (!metadata.http.user_agent.empty()) oss << "HTTP_USER_AGENT:" << metadata.http.user_agent << separator;
        if (!metadata.http.content_type.empty()) oss << "HTTP_CONTENT_TYPE:" << metadata.http.content_type << separator;
        if (!metadata.http.content_length.empty()) oss << "HTTP_CONTENT_LENGTH:" << metadata.http.content_length << separator;
        if (!metadata.http.connection.empty()) oss << "HTTP_CONNECTION:" << metadata.http.connection << separator;
        if (!metadata.http.accept.empty()) oss << "HTTP_ACCEPT:" << metadata.http.accept << separator;
        if (!metadata.http.accept_encoding.empty()) oss << "HTTP_ACCEPT_ENCODING:" << metadata.http.accept_encoding << separator;
        if (!metadata.http.accept_language.empty()) oss << "HTTP_ACCEPT_LANGUAGE:" << metadata.http.accept_language << separator;
        if (!metadata.http.cache_control.empty()) oss << "HTTP_CACHE_CONTROL:" << metadata.http.cache_control << separator;
        if (!metadata.http.cookie.empty()) oss << "HTTP_COOKIE:" << metadata.http.cookie << separator;
        if (!metadata.http.set_cookie.empty()) oss << "HTTP_SET_COOKIE:" << metadata.http.set_cookie << separator;
        if (!metadata.http.referer.empty()) oss << "HTTP_REFERER:" << metadata.http.referer << separator;
        if (!metadata.http.location.empty()) oss << "HTTP_LOCATION:" << metadata.http.location << separator;
        if (!metadata.http.server.empty()) oss << "HTTP_SERVER:" << metadata.http.server << separator;
        if (!metadata.http.date.empty()) oss << "HTTP_DATE:" << metadata.http.date << separator;
        if (!metadata.http.last_modified.empty()) oss << "HTTP_LAST_MODIFIED:" << metadata.http.last_modified << separator;
        if (!metadata.http.etag.empty()) oss << "HTTP_ETAG:" << metadata.http.etag << separator;
        if (!metadata.http.expires.empty()) oss << "HTTP_EXPIRES:" << metadata.http.expires << separator;
        
        // HTTP body information
        if (metadata.http.body_length > 0) {
            oss << "HTTP_BODY_LENGTH:" << metadata.http.body_length << separator;
            if (!metadata.http.body_preview.empty()) oss << "HTTP_BODY_PREVIEW:" << metadata.http.body_preview << separator;
        }
    }
    
    // BGP specific fields (only output if BGP is present)
    if (metadata.has_bgp) {
        oss << "HAS_BGP:1" << separator;
        oss << "BGP_MARKER:" << metadata.bgp.marker << separator;
        oss << "BGP_LENGTH:" << metadata.bgp.length << separator;
        oss << "BGP_TYPE:" << static_cast<int>(metadata.bgp.type) << separator;
        oss << "BGP_TYPE_STR:" << metadata.bgp.type_str << separator;
        
        // BGP OPEN message fields
        if (metadata.bgp.type == BGPMetadata::OPEN) {
            oss << "BGP_VERSION:" << static_cast<int>(metadata.bgp.version) << separator;
            oss << "BGP_MY_AS:" << metadata.bgp.my_as << separator;
            oss << "BGP_HOLD_TIME:" << metadata.bgp.hold_time << separator;
            oss << "BGP_IDENTIFIER:" << metadata.bgp.bgp_identifier << separator;
            
            // Optional parameters
            if (!metadata.bgp.optional_parameters.empty()) {
                oss << "BGP_OPTIONAL_PARAMETERS:";
                for (size_t i = 0; i < metadata.bgp.optional_parameters.size(); i++) {
                    if (i > 0) oss << ";";
                    oss << metadata.bgp.optional_parameters[i];
                }
                oss << separator;
            } else {
                oss << "BGP_OPTIONAL_PARAMETERS:" << separator;
            }
        }
        // Note: BGP OPEN fields are only output when BGP type is OPEN
        
        // BGP UPDATE message fields
        if (metadata.bgp.type == BGPMetadata::UPDATE) {
            // Withdrawn routes
            if (!metadata.bgp.withdrawn_routes.empty()) {
                oss << "BGP_WITHDRAWN_ROUTES:";
                for (size_t i = 0; i < metadata.bgp.withdrawn_routes.size(); i++) {
                    if (i > 0) oss << ";";
                    oss << metadata.bgp.withdrawn_routes[i];
                }
                oss << separator;
            } else {
                oss << "BGP_WITHDRAWN_ROUTES:" << separator;
            }
            
            // Path attributes
            if (!metadata.bgp.path_attributes.empty()) {
                oss << "BGP_PATH_ATTRIBUTES:";
                for (size_t i = 0; i < metadata.bgp.path_attributes.size(); i++) {
                    if (i > 0) oss << ";";
                    oss << metadata.bgp.path_attributes[i];
                }
                oss << separator;
            } else {
                oss << "BGP_PATH_ATTRIBUTES:" << separator;
            }
            
            // Specific path attributes
            if (!metadata.bgp.origin.empty()) oss << "BGP_ORIGIN:" << metadata.bgp.origin << separator;
            else oss << "BGP_ORIGIN:" << separator;
            
            if (!metadata.bgp.as_path.empty()) oss << "BGP_AS_PATH:" << metadata.bgp.as_path << separator;
            else oss << "BGP_AS_PATH:" << separator;
            
            if (!metadata.bgp.next_hop.empty()) oss << "BGP_NEXT_HOP:" << metadata.bgp.next_hop << separator;
            else oss << "BGP_NEXT_HOP:" << separator;
            
            if (metadata.bgp.local_pref > 0) oss << "BGP_LOCAL_PREF:" << metadata.bgp.local_pref << separator;
            else oss << "BGP_LOCAL_PREF:0" << separator;
            
            if (metadata.bgp.med > 0) oss << "BGP_MED:" << metadata.bgp.med << separator;
            else oss << "BGP_MED:0" << separator;
            
            if (!metadata.bgp.community.empty()) oss << "BGP_COMMUNITY:" << metadata.bgp.community << separator;
            else oss << "BGP_COMMUNITY:" << separator;
            
            if (!metadata.bgp.mp_reach_nlri.empty()) oss << "BGP_MP_REACH_NLRI:" << metadata.bgp.mp_reach_nlri << separator;
            else oss << "BGP_MP_REACH_NLRI:" << separator;
            
            if (!metadata.bgp.mp_unreach_nlri.empty()) oss << "BGP_MP_UNREACH_NLRI:" << metadata.bgp.mp_unreach_nlri << separator;
            else oss << "BGP_MP_UNREACH_NLRI:" << separator;
            
            // NLRI
            if (!metadata.bgp.nlri.empty()) {
                oss << "BGP_NLRI:";
                for (size_t i = 0; i < metadata.bgp.nlri.size(); i++) {
                    if (i > 0) oss << ";";
                    oss << metadata.bgp.nlri[i];
                }
                oss << separator;
            } else {
                oss << "BGP_NLRI:" << separator;
            }
        }
        // Note: BGP UPDATE fields are only output when BGP type is UPDATE
        
        // BGP NOTIFICATION message fields
        if (metadata.bgp.type == BGPMetadata::NOTIFICATION) {
            oss << "BGP_ERROR_CODE:" << static_cast<int>(metadata.bgp.error_code) << separator;
            oss << "BGP_ERROR_SUBCODE:" << static_cast<int>(metadata.bgp.error_subcode) << separator;
            if (!metadata.bgp.error_data.empty()) oss << "BGP_ERROR_DATA:" << metadata.bgp.error_data << separator;
            else oss << "BGP_ERROR_DATA:" << separator;
        }
        // Note: BGP NOTIFICATION fields are only output when BGP type is NOTIFICATION
        
        // BGP ROUTE-REFRESH message fields
        if (metadata.bgp.type == BGPMetadata::ROUTE_REFRESH) {
            oss << "BGP_AFI:" << metadata.bgp.afi << separator;
            oss << "BGP_SAFI:" << static_cast<int>(metadata.bgp.safi) << separator;
            oss << "BGP_RESERVED:" << static_cast<int>(metadata.bgp.reserved) << separator;
        }
        // Note: BGP ROUTE-REFRESH fields are only output when BGP type is ROUTE-REFRESH
    }
    // Note: BGP fields are only output when has_bgp = true
    
    // Packet length information
    oss << "PACKET_LENGTH:" << metadata.packet_length << separator;
    oss << "PAYLOAD_LENGTH:" << metadata.payload_length << separator;
    oss << "CONTROL_FIELD_SIZE:" << (metadata.packet_length - metadata.payload_length);

    const std::string text = oss.str();
    std::string category = "general";
    if (metadata.has_ethernet) category = "ethernet";
    else if (metadata.has_wifi) category = "wifi";
    
    std::ostream* out = nullptr;
    if (category == "ethernet" && ethernetLogFile.is_open()) out = &ethernetLogFile;
    else if (category == "wifi" && wifiLogFile.is_open()) out = &wifiLogFile;
    else if (category == "error" && errorLogFile.is_open()) out = &errorLogFile;

    if (out) {
        (*out) << text << std::endl;
    } else if (logFile.is_open()) {
        logFile << text << std::endl;
    } else {
        std::cout << text << std::endl;
    }
}

void LoggerManager::logPacketJSON(const PacketMetadata& metadata) {
    std::lock_guard<std::mutex> lock(logMutex);
    
    std::ostringstream oss;
    oss << "{";
    
    // Basic metadata
    oss << "\"TIMESTAMP\":" << metadata.timestamp << ",";
    
    // Data link layer metadata
    if (metadata.has_ethernet) {
        oss << "\"SRC_MAC\":\"";
        for (int i = 0; i < 6; i++) {
            if (i > 0) oss << ":";
            oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(metadata.ethernet.src_mac[i]);
        }
        oss << std::dec << std::setfill(' ') << "\",";
        
        oss << "\"DST_MAC\":\"";
        for (int i = 0; i < 6; i++) {
            if (i > 0) oss << ":";
            oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(metadata.ethernet.dst_mac[i]);
        }
        oss << std::dec << std::setfill(' ') << "\",";
        
        oss << "\"ETHERTYPE\":\"" << BaseParser::etherTypeToString(metadata.ethernet.ethertype) << "\",";
    } else if (metadata.has_wifi) {
        // WiFi metadata
        oss << "\"WIFI_SRC_MAC\":\"";
        for (int i = 0; i < 6; i++) {
            if (i > 0) oss << ":";
            oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(metadata.wifi.src_mac[i]);
        }
        oss << std::dec << std::setfill(' ') << "\",";
        
        oss << "\"WIFI_DST_MAC\":\"";
        for (int i = 0; i < 6; i++) {
            if (i > 0) oss << ":";
            oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(metadata.wifi.dst_mac[i]);
        }
        oss << std::dec << std::setfill(' ') << "\",";
        
        oss << "\"WIFI_BSSID\":\"";
        for (int i = 0; i < 6; i++) {
            if (i > 0) oss << ":";
            oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(metadata.wifi.bssid[i]);
        }
        oss << std::dec << std::setfill(' ') << "\",";
        
        oss << "\"WIFI_FRAME_TYPE\":" << static_cast<int>(metadata.wifi.frame_type) << ",";
        oss << "\"WIFI_FRAME_SUBTYPE\":" << static_cast<int>(metadata.wifi.frame_subtype) << ",";
        oss << "\"WIFI_TO_DS\":" << (metadata.wifi.to_ds ? "true" : "false") << ",";
        oss << "\"WIFI_FROM_DS\":" << (metadata.wifi.from_ds ? "true" : "false") << ",";
        oss << "\"WIFI_SEQUENCE\":" << metadata.wifi.sequence_number << ",";
        
        if (metadata.wifi.rssi != 0) oss << "\"WIFI_RSSI\":" << static_cast<int>(metadata.wifi.rssi) << ",";
        if (metadata.wifi.channel != 0) oss << "\"WIFI_CHANNEL\":" << static_cast<int>(metadata.wifi.channel) << ",";
    } else {
        oss << "\"SRC_MAC\":\"00:00:00:00:00:00\",";
        oss << "\"DST_MAC\":\"00:00:00:00:00:00\",";
        oss << "\"ETHERTYPE\":0,";
    }
    
    // VLAN metadata - only output if VLAN is present
    if (metadata.has_vlan) {
        oss << "\"HAS_VLAN\":true,";
        oss << "\"VLAN_ID\":" << metadata.vlan.vlan_id << ",";
        oss << "\"VLAN_PRIORITY\":" << static_cast<int>(metadata.vlan.vlan_priority) << ",";
    }
    
    // GRE metadata - only output if GRE is present
    if (metadata.has_gre) {
        oss << "\"HAS_GRE\":true,";
        oss << "\"GRE_VERSION\":" << static_cast<int>(metadata.gre.version) << ",";
        oss << "\"GRE_PROTOCOL\":\"" << std::hex << metadata.gre.protocol << std::dec << "\",";
        oss << "\"GRE_RECURSION_CONTROL\":" << static_cast<int>(metadata.gre.recursion_control) << ",";
        oss << "\"GRE_CHECKSUM_BIT\":" << (metadata.gre.checksum_bit ? "true" : "false") << ",";
        oss << "\"GRE_ROUTING_BIT\":" << (metadata.gre.routing_bit ? "true" : "false") << ",";
        oss << "\"GRE_KEY_BIT\":" << (metadata.gre.key_bit ? "true" : "false") << ",";
        oss << "\"GRE_SEQUENCE_BIT\":" << (metadata.gre.sequence_bit ? "true" : "false") << ",";
        oss << "\"GRE_STRICT_SOURCE_ROUTE\":" << (metadata.gre.strict_source_route ? "true" : "false") << ",";
        oss << "\"GRE_ACK_SEQUENCE_BIT\":" << (metadata.gre.ack_sequence_bit ? "true" : "false") << ",";
        
        if (metadata.gre.checksum_bit) {
            oss << "\"GRE_CHECKSUM\":\"" << std::hex << metadata.gre.checksum << std::dec << "\",";
        } else {
            oss << "\"GRE_CHECKSUM\":0,";
        }
        
        if (metadata.gre.routing_bit) {
            oss << "\"GRE_OFFSET\":" << metadata.gre.offset << ",";
        } else {
            oss << "\"GRE_OFFSET\":0,";
        }
        
        if (metadata.gre.key_bit) {
            oss << "\"GRE_KEY\":\"" << std::hex << metadata.gre.key << std::dec << "\",";
        } else {
            oss << "\"GRE_KEY\":0,";
        }
        
        if (metadata.gre.sequence_bit) {
            oss << "\"GRE_SEQUENCE\":" << metadata.gre.sequence << ",";
        } else {
            oss << "\"GRE_SEQUENCE\":0,";
        }
        
        if (metadata.gre.ack_sequence_bit) {
            oss << "\"GRE_ACK_SEQUENCE\":" << metadata.gre.ack_sequence << ",";
        } else {
            oss << "\"GRE_ACK_SEQUENCE\":0,";
        }
        
        if (metadata.gre.version == 1) {
            oss << "\"GRE_PAYLOAD_LENGTH\":" << metadata.gre.payload_length << ",";
            oss << "\"GRE_CALL_ID\":" << metadata.gre.call_id << ",";
        } else {
            oss << "\"GRE_PAYLOAD_LENGTH\":0,";
            oss << "\"GRE_CALL_ID\":0,";
        }
    }
    
    // Network layer metadata
    oss << "\"SRC_IP\":\"" << metadata.srcIP << "\",";
    oss << "\"DST_IP\":\"" << metadata.dstIP << "\",";
    oss << "\"PROTOCOL\":" << metadata.protocol << ",";
    
    // IPv6 specific fields (only output if IPv6 is present)
    if (metadata.has_ipv6) {
        oss << "\"IPV6_HOP_LIMIT\":" << static_cast<int>(metadata.ipv6.hop_limit) << ",";
        oss << "\"IPV6_FLOW_LABEL\":" << metadata.ipv6.flow_label << ",";
        oss << "\"IPV6_TRAFFIC_CLASS\":" << static_cast<int>(metadata.ipv6.traffic_class) << ",";
        oss << "\"IPV6_NEXT_HEADER\":" << static_cast<int>(metadata.ipv6.next_header) << ",";
        oss << "\"IPV6_PAYLOAD_LENGTH\":" << metadata.ipv6.payload_length << ",";
        
        // IPv6 extension headers
        if (metadata.ipv6.hop_by_hop.present) {
            oss << "\"IPV6_HOP_BY_HOP\":true,";
            oss << "\"IPV6_HOP_BY_HOP_TYPE\":" << static_cast<int>(metadata.ipv6.hop_by_hop.type) << ",";
            oss << "\"IPV6_HOP_BY_HOP_LENGTH\":" << static_cast<int>(metadata.ipv6.hop_by_hop.length) << ",";
        }
        
        if (metadata.ipv6.routing.present) {
            oss << "\"IPV6_ROUTING\":true,";
            oss << "\"IPV6_ROUTING_TYPE\":" << static_cast<int>(metadata.ipv6.routing.type) << ",";
            oss << "\"IPV6_ROUTING_LENGTH\":" << static_cast<int>(metadata.ipv6.routing.length) << ",";
            oss << "\"IPV6_ROUTING_TYPE_VALUE\":" << static_cast<int>(metadata.ipv6.routing_type) << ",";
            oss << "\"IPV6_SEGMENTS_LEFT\":" << static_cast<int>(metadata.ipv6.segments_left) << ",";
        }
        
        if (metadata.ipv6.fragment.present) {
            oss << "\"IPV6_FRAGMENT\":true,";
            oss << "\"IPV6_FRAGMENT_TYPE\":" << static_cast<int>(metadata.ipv6.fragment.type) << ",";
            oss << "\"IPV6_FRAGMENT_LENGTH\":" << static_cast<int>(metadata.ipv6.fragment.length) << ",";
            oss << "\"IPV6_FRAGMENT_OFFSET\":" << metadata.ipv6.fragment_offset << ",";
            oss << "\"IPV6_FRAGMENT_MORE\":" << (metadata.ipv6.fragment_more ? "true" : "false") << ",";
            oss << "\"IPV6_FRAGMENT_ID\":" << metadata.ipv6.fragment_id << ",";
        }
        
        if (metadata.ipv6.destination.present) {
            oss << "\"IPV6_DESTINATION\":true,";
            oss << "\"IPV6_DESTINATION_TYPE\":" << static_cast<int>(metadata.ipv6.destination.type) << ",";
            oss << "\"IPV6_DESTINATION_LENGTH\":" << static_cast<int>(metadata.ipv6.destination.length) << ",";
        }
        
        if (metadata.ipv6.ah.present) {
            oss << "\"IPV6_AH\":true,";
            oss << "\"IPV6_AH_TYPE\":" << static_cast<int>(metadata.ipv6.ah.type) << ",";
            oss << "\"IPV6_AH_LENGTH\":" << static_cast<int>(metadata.ipv6.ah.length) << ",";
        }
        
        if (metadata.ipv6.esp.present) {
            oss << "\"IPV6_ESP\":true,";
            oss << "\"IPV6_ESP_TYPE\":" << static_cast<int>(metadata.ipv6.esp.type) << ",";
            oss << "\"IPV6_ESP_LENGTH\":" << static_cast<int>(metadata.ipv6.esp.length) << ",";
        }
    }
    
    // Transport layer metadata
    oss << "\"SRC_PORT\":" << metadata.srcPort << ",";
    oss << "\"DST_PORT\":" << metadata.dstPort << ",";
    
    // TCP specific fields
    if (metadata.has_tcp) {
        oss << "\"TCP_SEQ\":" << metadata.tcp.seq << ",";
        oss << "\"TCP_ACK\":" << metadata.tcp.ack << ",";
        
        // TCP flags - output readable flags
        if (metadata.tcp.flags > 0) {
            oss << "\"TCP_FLAGS\":\"";
            if (metadata.tcp.syn) oss << "S";  // SYN
            if (metadata.tcp.ack_flag) oss << "A";  // ACK
            if (metadata.tcp.fin) oss << "F";  // FIN
            if (metadata.tcp.rst) oss << "R";  // RST
            if (metadata.tcp.psh) oss << "P";  // PSH
            oss << "\", ";
        } else {
            oss << "\"TCP_FLAGS\":0,";
        }
        
        oss << "\"TCP_WINDOW\":" << metadata.tcp.window << ",";
    }
    
    // UDP specific fields
    if (metadata.has_udp) {
        oss << "\"UDP_LENGTH\":" << metadata.udp.length << ",";
    }
    
    // ARP specific fields (only output if ARP is present)
    if (metadata.has_arp) {
        oss << "\"ARP_HARDWARE_TYPE\":" << metadata.arp.hardware_type << ",";
        oss << "\"ARP_PROTOCOL_TYPE\":" << std::hex << metadata.arp.protocol_type << std::dec << ",";
        
        // Convert ARP operation to string
        std::string arpOpStr;
        switch (metadata.arp.operation) {
            case 1: arpOpStr = "REQUEST"; break;
            case 2: arpOpStr = "REPLY"; break;
            case 3: arpOpStr = "RARP_REQUEST"; break;
            case 4: arpOpStr = "RARP_REPLY"; break;
            case 5: arpOpStr = "DRARP_REQUEST"; break;
            case 6: arpOpStr = "DRARP_REPLY"; break;
            case 7: arpOpStr = "DRARP_ERROR"; break;
            case 8: arpOpStr = "INARP_REQUEST"; break;
            case 9: arpOpStr = "INARP_REPLY"; break;
            default: arpOpStr = "UNKNOWN(" + std::to_string(metadata.arp.operation) + ")"; break;
        }
        oss << "\"ARP_OPERATION\":\"" << arpOpStr << "\",";
        
        oss << "\"ARP_SENDER_MAC\":\"" << metadata.arp.sender_mac_str << "\",";
        oss << "\"ARP_SENDER_IP\":\"" << metadata.arp.sender_ip_str << "\",";
        oss << "\"ARP_TARGET_MAC\":\"" << metadata.arp.target_mac_str << "\",";
        oss << "\"ARP_TARGET_IP\":\"" << metadata.arp.target_ip_str << "\",";
    }
    
    // ICMP specific fields (only output if ICMP is present)
    if (metadata.has_icmp) {
        // Convert ICMP type to string
        std::string icmpTypeStr;
        switch (metadata.icmp.type) {
            case 0: icmpTypeStr = "ECHO_REPLY"; break;
            case 3: icmpTypeStr = "DEST_UNREACHABLE"; break;
            case 4: icmpTypeStr = "SOURCE_QUENCH"; break;
            case 5: icmpTypeStr = "REDIRECT"; break;
            case 8: icmpTypeStr = "ECHO_REQUEST"; break;
            case 11: icmpTypeStr = "TIME_EXCEEDED"; break;
            case 12: icmpTypeStr = "PARAM_PROBLEM"; break;
            case 13: icmpTypeStr = "TIMESTAMP_REQUEST"; break;
            case 14: icmpTypeStr = "TIMESTAMP_REPLY"; break;
            case 15: icmpTypeStr = "INFO_REQUEST"; break;
            case 16: icmpTypeStr = "INFO_REPLY"; break;
            default: icmpTypeStr = "TYPE_" + std::to_string(metadata.icmp.type); break;
        }
        oss << "\"ICMP_TYPE\":\"" << icmpTypeStr << "\",";
        oss << "\"ICMP_CODE\":" << (int)metadata.icmp.code << ",";
        oss << "\"ICMP_CHECKSUM\":" << metadata.icmp.checksum << ",";
        
        // For echo request/reply
        if (metadata.icmp.type == 0 || metadata.icmp.type == 8) {
            oss << "\"ICMP_IDENTIFIER\":" << metadata.icmp.identifier << ",";
            oss << "\"ICMP_SEQUENCE\":" << metadata.icmp.sequence << ",";
        }
        
        // For destination unreachable
        if (metadata.icmp.type == 3) {
            oss << "\"ICMP_ORIGINAL_IP\":\"" << 
                ((metadata.icmp.original_ip >> 24) & 0xFF) << "." <<
                ((metadata.icmp.original_ip >> 16) & 0xFF) << "." <<
                ((metadata.icmp.original_ip >> 8) & 0xFF) << "." <<
                (metadata.icmp.original_ip & 0xFF) << "\",";
            oss << "\"ICMP_ORIGINAL_PROTOCOL\":" << (int)metadata.icmp.original_protocol << ",";
            oss << "\"ICMP_ORIGINAL_PORT\":" << metadata.icmp.original_port << ",";
        }
        
        // For redirect messages
        if (metadata.icmp.type == 5) {
            oss << "\"ICMP_GATEWAY_IP\":\"" << 
                ((metadata.icmp.gateway_ip >> 24) & 0xFF) << "." <<
                ((metadata.icmp.gateway_ip >> 16) & 0xFF) << "." <<
                ((metadata.icmp.gateway_ip >> 8) & 0xFF) << "." <<
                (metadata.icmp.gateway_ip & 0xFF) << "\",";
        }
    }
    
    // HTTP specific fields
    if (metadata.has_http) {
        oss << "\"HTTP_TYPE\":\"" << metadata.http.type << "\",";
        oss << "\"HTTP_METHOD\":\"" << metadata.http.method << "\",";
        oss << "\"HTTP_URI\":\"" << metadata.http.uri << "\",";
        oss << "\"HTTP_VERSION\":\"" << metadata.http.version << "\",";
        
        if (metadata.http.is_response) {
            oss << "\"HTTP_STATUS_CODE\":" << metadata.http.status_code << ",";
            oss << "\"HTTP_STATUS_TEXT\":\"" << metadata.http.status_text << "\",";
        }
        
        // Common HTTP headers
        if (!metadata.http.host.empty()) oss << "\"HTTP_HOST\":\"" << metadata.http.host << "\",";
        if (!metadata.http.user_agent.empty()) oss << "\"HTTP_USER_AGENT\":\"" << metadata.http.user_agent << "\",";
        if (!metadata.http.content_type.empty()) oss << "\"HTTP_CONTENT_TYPE\":\"" << metadata.http.content_type << "\",";
        if (!metadata.http.content_length.empty()) oss << "\"HTTP_CONTENT_LENGTH\":\"" << metadata.http.content_length << "\",";
        if (!metadata.http.connection.empty()) oss << "\"HTTP_CONNECTION\":\"" << metadata.http.connection << "\",";
        if (!metadata.http.accept.empty()) oss << "\"HTTP_ACCEPT\":\"" << metadata.http.accept << "\",";
        if (!metadata.http.accept_encoding.empty()) oss << "\"HTTP_ACCEPT_ENCODING\":\"" << metadata.http.accept_encoding << "\",";
        if (!metadata.http.accept_language.empty()) oss << "\"HTTP_ACCEPT_LANGUAGE\":\"" << metadata.http.accept_language << "\",";
        if (!metadata.http.cache_control.empty()) oss << "\"HTTP_CACHE_CONTROL\":\"" << metadata.http.cache_control << "\",";
        if (!metadata.http.cookie.empty()) oss << "\"HTTP_COOKIE\":\"" << metadata.http.cookie << "\",";
        if (!metadata.http.set_cookie.empty()) oss << "\"HTTP_SET_COOKIE\":\"" << metadata.http.set_cookie << "\",";
        if (!metadata.http.referer.empty()) oss << "\"HTTP_REFERER\":\"" << metadata.http.referer << "\",";
        if (!metadata.http.location.empty()) oss << "\"HTTP_LOCATION\":\"" << metadata.http.location << "\",";
        if (!metadata.http.server.empty()) oss << "\"HTTP_SERVER\":\"" << metadata.http.server << "\",";
        if (!metadata.http.date.empty()) oss << "\"HTTP_DATE\":\"" << metadata.http.date << "\",";
        if (!metadata.http.last_modified.empty()) oss << "\"HTTP_LAST_MODIFIED\":\"" << metadata.http.last_modified << "\",";
        if (!metadata.http.etag.empty()) oss << "\"HTTP_ETAG\":\"" << metadata.http.etag << "\",";
        if (!metadata.http.expires.empty()) oss << "\"HTTP_EXPIRES\":\"" << metadata.http.expires << "\",";
        
        // HTTP body information
        if (metadata.http.body_length > 0) {
            oss << "\"HTTP_BODY_LENGTH\":" << metadata.http.body_length << ",";
            if (!metadata.http.body_preview.empty()) oss << "\"HTTP_BODY_PREVIEW\":\"" << metadata.http.body_preview << "\",";
        }
    }
    
    // BGP specific fields (only output if BGP is present)
    if (metadata.has_bgp) {
        oss << "\"HAS_BGP\":true,";
        oss << "\"BGP_MARKER\":\"" << escapeJsonString(metadata.bgp.marker) << "\",";
        oss << "\"BGP_LENGTH\":" << metadata.bgp.length << ",";
        oss << "\"BGP_TYPE\":" << static_cast<int>(metadata.bgp.type) << ",";
        oss << "\"BGP_TYPE_STR\":\"" << escapeJsonString(metadata.bgp.type_str) << "\",";
        
        // BGP OPEN message fields
        if (metadata.bgp.type == BGPMetadata::OPEN) {
            oss << "\"BGP_VERSION\":" << static_cast<int>(metadata.bgp.version) << ",";
            oss << "\"BGP_MY_AS\":" << metadata.bgp.my_as << ",";
            oss << "\"BGP_HOLD_TIME\":" << metadata.bgp.hold_time << ",";
            oss << "\"BGP_IDENTIFIER\":\"" << escapeJsonString(metadata.bgp.bgp_identifier) << "\",";
            
            // Optional parameters
            if (!metadata.bgp.optional_parameters.empty()) {
                oss << "\"BGP_OPTIONAL_PARAMETERS\":[";
                for (size_t i = 0; i < metadata.bgp.optional_parameters.size(); i++) {
                    if (i > 0) oss << ",";
                    oss << "\"" << escapeJsonString(metadata.bgp.optional_parameters[i]) << "\"";
                }
                oss << "],";
            } else {
                oss << "\"BGP_OPTIONAL_PARAMETERS\":[],";
            }
        }
        // Note: BGP OPEN fields are only output when BGP type is OPEN
        
        // BGP UPDATE message fields
        if (metadata.bgp.type == BGPMetadata::UPDATE) {
            // Withdrawn routes
            if (!metadata.bgp.withdrawn_routes.empty()) {
                oss << "\"BGP_WITHDRAWN_ROUTES\":[";
                for (size_t i = 0; i < metadata.bgp.withdrawn_routes.size(); i++) {
                    if (i > 0) oss << ",";
                    oss << "\"" << escapeJsonString(metadata.bgp.withdrawn_routes[i]) << "\"";
                }
                oss << "],";
            } else {
                oss << "\"BGP_WITHDRAWN_ROUTES\":[],";
            }
            
            // Path attributes
            if (!metadata.bgp.path_attributes.empty()) {
                oss << "\"BGP_PATH_ATTRIBUTES\":[";
                for (size_t i = 0; i < metadata.bgp.path_attributes.size(); i++) {
                    if (i > 0) oss << ",";
                    oss << "\"" << escapeJsonString(metadata.bgp.path_attributes[i]) << "\"";
                }
                oss << "],";
            } else {
                oss << "\"BGP_PATH_ATTRIBUTES\":[],";
            }
            
            // Specific path attributes
            if (!metadata.bgp.origin.empty()) oss << "\"BGP_ORIGIN\":\"" << escapeJsonString(metadata.bgp.origin) << "\",";
            else oss << "\"BGP_ORIGIN\":\"\",";
            
            if (!metadata.bgp.as_path.empty()) oss << "\"BGP_AS_PATH\":\"" << escapeJsonString(metadata.bgp.as_path) << "\",";
            else oss << "\"BGP_AS_PATH\":\"\",";
            
            if (!metadata.bgp.next_hop.empty()) oss << "\"BGP_NEXT_HOP\":\"" << escapeJsonString(metadata.bgp.next_hop) << "\",";
            else oss << "\"BGP_NEXT_HOP\":\"\",";
            
            if (metadata.bgp.local_pref > 0) oss << "\"BGP_LOCAL_PREF\":" << metadata.bgp.local_pref << ",";
            else oss << "\"BGP_LOCAL_PREF\":0,";
            
            if (metadata.bgp.med > 0) oss << "\"BGP_MED\":" << metadata.bgp.med << ",";
            else oss << "\"BGP_MED\":0,";
            
            if (!metadata.bgp.community.empty()) oss << "\"BGP_COMMUNITY\":\"" << escapeJsonString(metadata.bgp.community) << "\",";
            else oss << "\"BGP_COMMUNITY\":\"\",";
            
            if (!metadata.bgp.mp_reach_nlri.empty()) oss << "\"BGP_MP_REACH_NLRI\":\"" << escapeJsonString(metadata.bgp.mp_reach_nlri) << "\",";
            else oss << "\"BGP_MP_REACH_NLRI\":\"\",";
            
            if (!metadata.bgp.mp_unreach_nlri.empty()) oss << "\"BGP_MP_UNREACH_NLRI\":\"" << escapeJsonString(metadata.bgp.mp_unreach_nlri) << "\",";
            else oss << "\"BGP_MP_UNREACH_NLRI\":\"\",";
            
            // NLRI
            if (!metadata.bgp.nlri.empty()) {
                oss << "\"BGP_NLRI\":[";
                for (size_t i = 0; i < metadata.bgp.nlri.size(); i++) {
                    if (i > 0) oss << ",";
                    oss << "\"" << escapeJsonString(metadata.bgp.nlri[i]) << "\"";
                }
                oss << "],";
            } else {
                oss << "\"BGP_NLRI\":[],";
            }
        }
        // Note: BGP UPDATE fields are only output when BGP type is UPDATE
        
        // BGP NOTIFICATION message fields
        if (metadata.bgp.type == BGPMetadata::NOTIFICATION) {
            oss << "\"BGP_ERROR_CODE\":" << static_cast<int>(metadata.bgp.error_code) << ",";
            oss << "\"BGP_ERROR_SUBCODE\":" << static_cast<int>(metadata.bgp.error_subcode) << ",";
            if (!metadata.bgp.error_data.empty()) oss << "\"BGP_ERROR_DATA\":\"" << escapeJsonString(metadata.bgp.error_data) << "\",";
            else oss << "\"BGP_ERROR_DATA\":\"\",";
        }
        // Note: BGP NOTIFICATION fields are only output when BGP type is NOTIFICATION
        
        // BGP ROUTE-REFRESH message fields
        if (metadata.bgp.type == BGPMetadata::ROUTE_REFRESH) {
            oss << "\"BGP_AFI\":" << metadata.bgp.afi << ",";
            oss << "\"BGP_SAFI\":" << static_cast<int>(metadata.bgp.safi) << ",";
            oss << "\"BGP_RESERVED\":" << static_cast<int>(metadata.bgp.reserved) << ",";
        }
        // Note: BGP ROUTE-REFRESH fields are only output when BGP type is ROUTE-REFRESH
    }
    // Note: BGP fields are only output when has_bgp = true
    
    // Packet length information
    oss << "\"PACKET_LENGTH\":" << metadata.packet_length << ",";
    oss << "\"PAYLOAD_LENGTH\":" << metadata.payload_length << ",";
    oss << "\"CONTROL_FIELD_SIZE\":" << (metadata.packet_length - metadata.payload_length);

    oss << "}";

    if (logFile.is_open())
        logFile << oss.str() << std::endl;
    else
        std::cout << oss.str() << std::endl;
}

void LoggerManager::logConn(const PacketMetadata& metadata, const std::string& category)
{
    if (useJsonFormat) {
        logConnJSON(metadata, category);
    } else {
        logConnCSV(metadata, category);
    }
}

void LoggerManager::logConnCSV(const PacketMetadata& metadata, const std::string& category)
{
    std::lock_guard<std::mutex> lock(logMutex);

    std::ostringstream line;
    const std::string separator = ",";
    
    // Basic metadata
    line << std::fixed << std::setprecision(6) << "TIMESTAMP:" << metadata.timestamp << separator;
    
    // Data link layer metadata
    if (metadata.has_ethernet) {
        line << "SRC_MAC:";
        for (int i = 0; i < 6; i++) { 
            if (i > 0) line << ":"; 
            line << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(metadata.ethernet.src_mac[i]); 
        }
        line << std::dec << std::setfill(' ') << separator;
        line << "DST_MAC:";
        for (int i = 0; i < 6; i++) { 
            if (i > 0) line << ":"; 
            line << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(metadata.ethernet.dst_mac[i]); 
        }
        line << std::dec << std::setfill(' ') << separator;
        line << "ETHERTYPE:" << BaseParser::etherTypeToString(metadata.ethernet.ethertype) << separator;
    } else if (metadata.has_wifi) {
        // WiFi metadata
        line << "WIFI_SRC_MAC:";
        for (int i = 0; i < 6; i++) {
            if (i > 0) line << ":";
            line << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(metadata.wifi.src_mac[i]);
        }
        line << std::dec << std::setfill(' ') << separator;
        line << "WIFI_DST_MAC:";
        for (int i = 0; i < 6; i++) {
            if (i > 0) line << ":";
            line << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(metadata.wifi.dst_mac[i]);
        }
        line << std::dec << std::setfill(' ') << separator;
        line << "WIFI_BSSID:";
        for (int i = 0; i < 6; i++) {
            if (i > 0) line << ":";
            line << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(metadata.wifi.bssid[i]);
        }
        line << std::dec << std::setfill(' ') << separator;
        line << "WIFI_FRAME_TYPE:" << static_cast<int>(metadata.wifi.frame_type) << separator;
        line << "WIFI_FRAME_SUBTYPE:" << static_cast<int>(metadata.wifi.frame_subtype) << separator;
        line << "WIFI_TO_DS:" << (metadata.wifi.to_ds ? "1" : "0") << separator;
        line << "WIFI_FROM_DS:" << (metadata.wifi.from_ds ? "1" : "0") << separator;
        line << "WIFI_SEQUENCE:" << metadata.wifi.sequence_number << separator;
        if (metadata.wifi.rssi != 0) line << "WIFI_RSSI:" << static_cast<int>(metadata.wifi.rssi) << separator;
        if (metadata.wifi.channel != 0) line << "WIFI_CHANNEL:" << static_cast<int>(metadata.wifi.channel) << separator;
    } else {
        line << "SRC_MAC:00:00:00:00:00:00" << separator;
        line << "DST_MAC:00:00:00:00:00:00" << separator;
        line << "ETHERTYPE:0" << separator;
    }
    
    if (metadata.has_vlan) { 
        line << "HAS_VLAN:1" << separator;
        line << "VLAN_ID:" << metadata.vlan.vlan_id << separator; 
        line << "VLAN_PRIORITY:" << static_cast<int>(metadata.vlan.vlan_priority) << separator; 
    }
    
    if (metadata.has_gre) {
        line << "HAS_GRE:1" << separator;
        line << "GRE_VERSION:" << static_cast<int>(metadata.gre.version) << separator;
        line << "GRE_PROTOCOL:" << std::hex << metadata.gre.protocol << std::dec << separator;
        line << "GRE_RECURSION_CONTROL:" << static_cast<int>(metadata.gre.recursion_control) << separator;
        line << "GRE_CHECKSUM_BIT:" << (metadata.gre.checksum_bit ? "1" : "0") << separator;
        line << "GRE_ROUTING_BIT:" << (metadata.gre.routing_bit ? "1" : "0") << separator;
        line << "GRE_KEY_BIT:" << (metadata.gre.key_bit ? "1" : "0") << separator;
        line << "GRE_SEQUENCE_BIT:" << (metadata.gre.sequence_bit ? "1" : "0") << separator;
        line << "GRE_STRICT_SOURCE_ROUTE:" << (metadata.gre.strict_source_route ? "1" : "0") << separator;
        line << "GRE_ACK_SEQUENCE_BIT:" << (metadata.gre.ack_sequence_bit ? "1" : "0") << separator;
        if (metadata.gre.checksum_bit) line << "GRE_CHECKSUM:" << std::hex << metadata.gre.checksum << std::dec << separator; else line << "GRE_CHECKSUM:0" << separator;
        if (metadata.gre.routing_bit) line << "GRE_OFFSET:" << metadata.gre.offset << separator; else line << "GRE_OFFSET:0" << separator;
        if (metadata.gre.key_bit) line << "GRE_KEY:" << std::hex << metadata.gre.key << std::dec << separator; else line << "GRE_KEY:0" << separator;
        if (metadata.gre.sequence_bit) line << "GRE_SEQUENCE:" << metadata.gre.sequence << separator; else line << "GRE_SEQUENCE:0" << separator;
        if (metadata.gre.ack_sequence_bit) line << "GRE_ACK_SEQUENCE:" << metadata.gre.ack_sequence << separator; else line << "GRE_ACK_SEQUENCE:0" << separator;
        if (metadata.gre.version == 1) { 
            line << "GRE_PAYLOAD_LENGTH:" << metadata.gre.payload_length << separator; 
            line << "GRE_CALL_ID:" << metadata.gre.call_id << separator; 
        }
        else { 
            line << "GRE_PAYLOAD_LENGTH:0" << separator << "GRE_CALL_ID:0" << separator; 
        }
    }
    
    line << "SRC_IP:" << metadata.srcIP << separator;
    line << "DST_IP:" << metadata.dstIP << separator;
    line << "PROTOCOL:" << metadata.protocol << separator;
    
    // IPv6 specific fields (only output if IPv6 is present)
    if (metadata.has_ipv6) {
        line << "IPV6_HOP_LIMIT:" << static_cast<int>(metadata.ipv6.hop_limit) << separator;
        line << "IPV6_FLOW_LABEL:" << metadata.ipv6.flow_label << separator;
        line << "IPV6_TRAFFIC_CLASS:" << static_cast<int>(metadata.ipv6.traffic_class) << separator;
        line << "IPV6_NEXT_HEADER:" << static_cast<int>(metadata.ipv6.next_header) << separator;
        line << "IPV6_PAYLOAD_LENGTH:" << metadata.ipv6.payload_length << separator;
        
        // IPv6 extension headers
        if (metadata.ipv6.hop_by_hop.present) {
            line << "IPV6_HOP_BY_HOP:1" << separator;
            line << "IPV6_HOP_BY_HOP_TYPE:" << static_cast<int>(metadata.ipv6.hop_by_hop.type) << separator;
            line << "IPV6_HOP_BY_HOP_LENGTH:" << static_cast<int>(metadata.ipv6.hop_by_hop.length) << separator;
        }
        
        if (metadata.ipv6.routing.present) {
            line << "IPV6_ROUTING:1" << separator;
            line << "IPV6_ROUTING_TYPE:" << static_cast<int>(metadata.ipv6.routing.type) << separator;
            line << "IPV6_ROUTING_LENGTH:" << static_cast<int>(metadata.ipv6.routing.length) << separator;
            line << "IPV6_ROUTING_TYPE_VALUE:" << static_cast<int>(metadata.ipv6.routing_type) << separator;
            line << "IPV6_SEGMENTS_LEFT:" << static_cast<int>(metadata.ipv6.segments_left) << separator;
        }
        
        if (metadata.ipv6.fragment.present) {
            line << "IPV6_FRAGMENT:1" << separator;
            line << "IPV6_FRAGMENT_TYPE:" << static_cast<int>(metadata.ipv6.fragment.type) << separator;
            line << "IPV6_FRAGMENT_LENGTH:" << static_cast<int>(metadata.ipv6.fragment.length) << separator;
            line << "IPV6_FRAGMENT_OFFSET:" << metadata.ipv6.fragment_offset << separator;
            line << "IPV6_FRAGMENT_MORE:" << (metadata.ipv6.fragment_more ? "1" : "0") << separator;
            line << "IPV6_FRAGMENT_ID:" << metadata.ipv6.fragment_id << separator;
        }
        
        if (metadata.ipv6.destination.present) {
            line << "IPV6_DESTINATION:1" << separator;
            line << "IPV6_DESTINATION_TYPE:" << static_cast<int>(metadata.ipv6.destination.type) << separator;
            line << "IPV6_DESTINATION_LENGTH:" << static_cast<int>(metadata.ipv6.destination.length) << separator;
        }
        
        if (metadata.ipv6.ah.present) {
            line << "IPV6_AH:1" << separator;
            line << "IPV6_AH_TYPE:" << static_cast<int>(metadata.ipv6.ah.type) << separator;
            line << "IPV6_AH_LENGTH:" << static_cast<int>(metadata.ipv6.ah.length) << separator;
        }
        
        if (metadata.ipv6.esp.present) {
            line << "IPV6_ESP:1" << separator;
            line << "IPV6_ESP_TYPE:" << static_cast<int>(metadata.ipv6.esp.type) << separator;
            line << "IPV6_ESP_LENGTH:" << static_cast<int>(metadata.ipv6.esp.length) << separator;
        }
    }
    line << "SRC_PORT:" << metadata.srcPort << separator;
    line << "DST_PORT:" << metadata.dstPort << separator;
    
    if (metadata.has_tcp) {
        line << "TCP_SEQ:" << metadata.tcp.seq << separator;
        line << "TCP_ACK:" << metadata.tcp.ack << separator;
        if (metadata.tcp.flags > 0) {
            line << "TCP_FLAGS:[";
            if (metadata.tcp.syn) line << "S";
            if (metadata.tcp.ack_flag) line << "A";
            if (metadata.tcp.fin) line << "F";
            if (metadata.tcp.rst) line << "R";
            if (metadata.tcp.psh) line << "P";
            line << "]" << separator;
        } else {
            line << "TCP_FLAGS:0" << separator;
        }
        line << "TCP_WINDOW:" << metadata.tcp.window << separator;
    } else {
        line << "TCP_SEQ:0" << separator;
        line << "TCP_ACK:0" << separator;
        line << "TCP_FLAGS:0" << separator;
        line << "TCP_WINDOW:0" << separator;
    }
    
    if (metadata.has_udp) {
        line << "UDP_LENGTH:" << metadata.udp.length << separator;
    } else {
        line << "UDP_LENGTH:0" << separator;
    }
    
    // HTTP specific fields
    if (metadata.has_http) {
        line << "HTTP_TYPE:" << metadata.http.type << separator;
        line << "HTTP_METHOD:" << metadata.http.method << separator;
        line << "HTTP_URI:" << metadata.http.uri << separator;
        line << "HTTP_VERSION:" << metadata.http.version << separator;
        
        if (metadata.http.is_response) {
            line << "HTTP_STATUS_CODE:" << metadata.http.status_code << separator;
            line << "HTTP_STATUS_TEXT:" << metadata.http.status_text << separator;
        }
        
        // Common HTTP headers
        if (!metadata.http.host.empty()) line << "HTTP_HOST:" << metadata.http.host << separator;
        if (!metadata.http.user_agent.empty()) line << "HTTP_USER_AGENT:" << metadata.http.user_agent << separator;
        if (!metadata.http.content_type.empty()) line << "HTTP_CONTENT_TYPE:" << metadata.http.content_type << separator;
        if (!metadata.http.content_length.empty()) line << "HTTP_CONTENT_LENGTH:" << metadata.http.content_length << separator;
        if (!metadata.http.connection.empty()) line << "HTTP_CONNECTION:" << metadata.http.connection << separator;
        if (!metadata.http.accept.empty()) line << "HTTP_ACCEPT:" << metadata.http.accept << separator;
        if (!metadata.http.accept_encoding.empty()) line << "HTTP_ACCEPT_ENCODING:" << metadata.http.accept_encoding << separator;
        if (!metadata.http.accept_language.empty()) line << "HTTP_ACCEPT_LANGUAGE:" << metadata.http.accept_language << separator;
        if (!metadata.http.cache_control.empty()) line << "HTTP_CACHE_CONTROL:" << metadata.http.cache_control << separator;
        if (!metadata.http.cookie.empty()) line << "HTTP_COOKIE:" << metadata.http.cookie << separator;
        if (!metadata.http.set_cookie.empty()) line << "HTTP_SET_COOKIE:" << metadata.http.set_cookie << separator;
        if (!metadata.http.referer.empty()) line << "HTTP_REFERER:" << metadata.http.referer << separator;
        if (!metadata.http.location.empty()) line << "HTTP_LOCATION:" << metadata.http.location << separator;
        if (!metadata.http.server.empty()) line << "HTTP_SERVER:" << metadata.http.server << separator;
        if (!metadata.http.date.empty()) line << "HTTP_DATE:" << metadata.http.date << separator;
        if (!metadata.http.last_modified.empty()) line << "HTTP_LAST_MODIFIED:" << metadata.http.last_modified << separator;
        if (!metadata.http.etag.empty()) line << "HTTP_ETAG:" << metadata.http.etag << separator;
        if (!metadata.http.expires.empty()) line << "HTTP_EXPIRES:" << metadata.http.expires << separator;
        
        // HTTP body information
        if (metadata.http.body_length > 0) {
            line << "HTTP_BODY_LENGTH:" << metadata.http.body_length << separator;
            if (!metadata.http.body_preview.empty()) line << "HTTP_BODY_PREVIEW:" << metadata.http.body_preview << separator;
        }
    }
    
    // ARP specific fields (only output if ARP is present)
    if (metadata.has_arp) {
        line << "ARP_HARDWARE_TYPE:" << metadata.arp.hardware_type << separator;
        line << "ARP_PROTOCOL_TYPE:0x" << std::hex << metadata.arp.protocol_type << std::dec << separator;
        
        // Convert ARP operation to string
        std::string arpOpStr;
        switch (metadata.arp.operation) {
            case 1: arpOpStr = "REQUEST"; break;
            case 2: arpOpStr = "REPLY"; break;
            case 3: arpOpStr = "RARP_REQUEST"; break;
            case 4: arpOpStr = "RARP_REPLY"; break;
            case 5: arpOpStr = "DRARP_REQUEST"; break;
            case 6: arpOpStr = "DRARP_REPLY"; break;
            case 7: arpOpStr = "DRARP_ERROR"; break;
            case 8: arpOpStr = "INARP_REQUEST"; break;
            case 9: arpOpStr = "INARP_REPLY"; break;
            default: arpOpStr = "UNKNOWN(" + std::to_string(metadata.arp.operation) + ")"; break;
        }
        line << "ARP_OPERATION:" << arpOpStr << separator;
        
        line << "ARP_SENDER_MAC:" << metadata.arp.sender_mac_str << separator;
        line << "ARP_SENDER_IP:" << metadata.arp.sender_ip_str << separator;
        line << "ARP_TARGET_MAC:" << metadata.arp.target_mac_str << separator;
        line << "ARP_TARGET_IP:" << metadata.arp.target_ip_str << separator;
    }
    
    // ICMP specific fields (only output if ICMP is present)
    if (metadata.has_icmp) {
        // Convert ICMP type to string
        std::string icmpTypeStr;
        switch (metadata.icmp.type) {
            case 0: icmpTypeStr = "ECHO_REPLY"; break;
            case 3: icmpTypeStr = "DEST_UNREACHABLE"; break;
            case 4: icmpTypeStr = "SOURCE_QUENCH"; break;
            case 5: icmpTypeStr = "REDIRECT"; break;
            case 8: icmpTypeStr = "ECHO_REQUEST"; break;
            case 11: icmpTypeStr = "TIME_EXCEEDED"; break;
            case 12: icmpTypeStr = "PARAM_PROBLEM"; break;
            case 13: icmpTypeStr = "TIMESTAMP_REQUEST"; break;
            case 14: icmpTypeStr = "TIMESTAMP_REPLY"; break;
            case 15: icmpTypeStr = "INFO_REQUEST"; break;
            case 16: icmpTypeStr = "INFO_REPLY"; break;
            default: icmpTypeStr = "TYPE_" + std::to_string(metadata.icmp.type); break;
        }
        line << "ICMP_TYPE:" << icmpTypeStr << separator;
        line << "ICMP_CODE:" << (int)metadata.icmp.code << separator;
        line << "ICMP_CHECKSUM:0x" << std::hex << metadata.icmp.checksum << std::dec << separator;
        
        // For echo request/reply
        if (metadata.icmp.type == 0 || metadata.icmp.type == 8) {
            line << "ICMP_IDENTIFIER:" << metadata.icmp.identifier << separator;
            line << "ICMP_SEQUENCE:" << metadata.icmp.sequence << separator;
        }
        
        // For destination unreachable
        if (metadata.icmp.type == 3) {
            line << "ICMP_ORIGINAL_IP:" << 
                ((metadata.icmp.original_ip >> 24) & 0xFF) << "." <<
                ((metadata.icmp.original_ip >> 16) & 0xFF) << "." <<
                ((metadata.icmp.original_ip >> 8) & 0xFF) << "." <<
                (metadata.icmp.original_ip & 0xFF) << separator;
            line << "ICMP_ORIGINAL_PROTOCOL:" << (int)metadata.icmp.original_protocol << separator;
            line << "ICMP_ORIGINAL_PORT:" << metadata.icmp.original_port << separator;
        }
        
        // For redirect messages
        if (metadata.icmp.type == 5) {
            line << "ICMP_GATEWAY_IP:" << 
                ((metadata.icmp.gateway_ip >> 24) & 0xFF) << "." <<
                ((metadata.icmp.gateway_ip >> 16) & 0xFF) << "." <<
                ((metadata.icmp.gateway_ip >> 8) & 0xFF) << "." <<
                (metadata.icmp.gateway_ip & 0xFF) << separator;
        }
    }
    
    if (metadata.has_dns) {
        // DNS specific fields
        line << "HAS_DNS:" << (metadata.has_dns ? "true" : "false") << separator;
        line << "DNS_TRANSACTION_ID:" << std::hex << "0x" << metadata.dns.transaction_id << std::dec << separator;
        line << "DNS_MESSAGE_TYPE:" << metadata.dns.message_type << separator;
        line << "DNS_OPCODE:" << metadata.dns.opcode_str << separator;
        line << "DNS_RCODE:" << metadata.dns.rcode_str << separator;
        
        // DNS flags
        line << "DNS_FLAGS:" << DNSParser::getFlagsString(metadata.dns) << separator;
        
        // Counts
        line << "DNS_QUESTIONS:" << metadata.dns.questions << separator;
        line << "DNS_ANSWERS:" << metadata.dns.answers << separator;
        line << "DNS_AUTHORITY:" << metadata.dns.authority_records << separator;
        line << "DNS_ADDITIONAL:" << metadata.dns.additional_records << separator;
        
        // Question section
        if (!metadata.dns.qname.empty()) {
            line << "DNS_QNAME:" << metadata.dns.qname << separator;
            line << "DNS_QTYPE:" << metadata.dns.qtype_str << separator;
            line << "DNS_QCLASS:" << metadata.dns.qclass_str << separator;
        } else {
            line << "DNS_QNAME:" << separator;
            line << "DNS_QTYPE:" << separator;
            line << "DNS_QCLASS:" << separator;
        }
        
        // Answer records (first few)
        if (!metadata.dns.answer_records.empty()) {
            line << "DNS_ANSWERS_DETAIL:";
            for (size_t i = 0; i < std::min(static_cast<size_t>(3), metadata.dns.answer_records.size()); i++) {
                const auto& record = metadata.dns.answer_records[i];
                if (i > 0) line << ";";
                line << record.name << ":" << record.type_str << ":" << record.rdata;
            }
            line << separator;
            if (metadata.dns.answer_records.size() > 3) {
                line << "DNS_MORE_ANSWERS:" << (metadata.dns.answer_records.size() - 3) << separator;
            } else {
                line << "DNS_MORE_ANSWERS:0" << separator;
            }
        } else {
            line << "DNS_ANSWERS_DETAIL:" << separator;
            line << "DNS_MORE_ANSWERS:0" << separator;
        }
        
        line << "DNS_PACKET_SIZE:" << metadata.dns.dns_packet_size << separator;
    }
    
    if (metadata.has_dhcp) {
        // DHCP specific fields
        line << "HAS_DHCP:" << (metadata.has_dhcp ? "true" : "false") << separator;
        DHCPParser::formatForCSV(metadata.dhcp, line, separator);
    }
    
    if (metadata.has_dhcpv6) {
        // DHCPv6 specific fields
        line << "HAS_DHCPV6:" << (metadata.has_dhcpv6 ? "true" : "false") << separator;
        DHCPv6Parser::formatForCSV(metadata.dhcpv6, line, separator);
    }
    
    if (metadata.has_ntp) {
        // NTP specific fields
        line << "HAS_NTP:" << (metadata.has_ntp ? "true" : "false") << separator;
        line << "NTP_LI:" << static_cast<int>(metadata.ntp.li) << separator;
        line << "NTP_LI_STR:" << metadata.ntp.li_str << separator;
        line << "NTP_VN:" << static_cast<int>(metadata.ntp.vn) << separator;
        line << "NTP_VN_STR:" << metadata.ntp.vn_str << separator;
        line << "NTP_MODE:" << static_cast<int>(metadata.ntp.mode) << separator;
        line << "NTP_MODE_STR:" << metadata.ntp.mode_str << separator;
        line << "NTP_STRATUM:" << static_cast<int>(metadata.ntp.stratum) << separator;
        line << "NTP_STRATUM_STR:" << metadata.ntp.stratum_str << separator;
        line << "NTP_POLL:" << static_cast<int>(metadata.ntp.poll) << separator;
        line << "NTP_PRECISION:" << static_cast<int>(metadata.ntp.precision) << separator;
        line << "NTP_ROOT_DELAY:" << metadata.ntp.root_delay << separator;
        line << "NTP_ROOT_DISPERSION:" << metadata.ntp.root_dispersion << separator;
        line << "NTP_REFERENCE_ID:" << std::hex << "0x" << metadata.ntp.reference_id << std::dec << separator;
        line << "NTP_REFERENCE_ID_STR:" << metadata.ntp.reference_id_str << separator;
        line << "NTP_REFERENCE_TIMESTAMP:" << metadata.ntp.reference_timestamp << separator;
        line << "NTP_ORIGINATE_TIMESTAMP:" << metadata.ntp.originate_timestamp << separator;
        line << "NTP_RECEIVE_TIMESTAMP:" << metadata.ntp.receive_timestamp << separator;
        line << "NTP_TRANSMIT_TIMESTAMP:" << metadata.ntp.transmit_timestamp << separator;
        line << "NTP_TIME_OFFSET:" << std::fixed << std::setprecision(3) << metadata.ntp.time_offset << separator;
        line << "NTP_ROUND_TRIP_DELAY:" << std::fixed << std::setprecision(3) << metadata.ntp.round_trip_delay << separator;
    }
    
    // FTP specific fields - only output for FTP packets
    if (metadata.has_ftp) {
        line << "HAS_FTP:1" << separator;
        line << "FTP_TYPE:" << metadata.ftp.type << separator;
        
        if (metadata.ftp.is_control) {
            if (metadata.ftp.is_request && !metadata.ftp.command.empty()) {
                line << "FTP_COMMAND:" << metadata.ftp.command << separator;
                if (!metadata.ftp.arguments.empty()) {
                    line << "FTP_ARGUMENTS:" << metadata.ftp.arguments << separator;
                } else {
                    line << "FTP_ARGUMENTS:" << separator;
                }
            } else {
                line << "FTP_COMMAND:" << separator;
                line << "FTP_ARGUMENTS:" << separator;
            }
            
            if (metadata.ftp.is_response && metadata.ftp.response_code != 0) {
                line << "FTP_RESPONSE_CODE:" << metadata.ftp.response_code << separator;
                if (!metadata.ftp.response_text.empty()) {
                    line << "FTP_RESPONSE_TEXT:" << metadata.ftp.response_text << separator;
                } else {
                    line << "FTP_RESPONSE_TEXT:" << separator;
                }
            } else {
                line << "FTP_RESPONSE_CODE:0" << separator;
                line << "FTP_RESPONSE_TEXT:" << separator;
            }
        } else {
            line << "FTP_COMMAND:" << separator;
            line << "FTP_ARGUMENTS:" << separator;
            line << "FTP_RESPONSE_CODE:0" << separator;
            line << "FTP_RESPONSE_TEXT:" << separator;
        }
        
        if (metadata.ftp.is_data) {
            line << "FTP_DATA_LENGTH:" << metadata.ftp.data_length << separator;
            if (!metadata.ftp.transfer_mode.empty()) {
                line << "FTP_TRANSFER_MODE:" << metadata.ftp.transfer_mode << separator;
            } else {
                line << "FTP_TRANSFER_MODE:" << separator;
            }
            if (!metadata.ftp.data_preview.empty()) {
                line << "FTP_DATA_PREVIEW:" << metadata.ftp.data_preview << separator;
            } else {
                line << "FTP_DATA_PREVIEW:" << separator;
            }
        } else {
            line << "FTP_DATA_LENGTH:0" << separator;
            line << "FTP_TRANSFER_MODE:" << separator;
            line << "FTP_DATA_PREVIEW:" << separator;
        }
    }
    
    // SMTP metadata (only output for SMTP packets)
    if (metadata.has_smtp) {
        line << "HAS_SMTP:1" << separator;
        line << "SMTP_TYPE:" << metadata.smtp.type << separator;
        
        if (metadata.smtp.is_request) {
            if (!metadata.smtp.command.empty()) {
                line << "SMTP_COMMAND:" << metadata.smtp.command << separator;
            } else {
                line << "SMTP_COMMAND:" << separator;
            }
            if (!metadata.smtp.arguments.empty()) {
                line << "SMTP_ARGUMENTS:" << metadata.smtp.arguments << separator;
            } else {
                line << "SMTP_ARGUMENTS:" << separator;
            }
            line << "SMTP_STATUS_CODE:0" << separator;
            line << "SMTP_STATUS_TEXT:" << separator;
        } else if (metadata.smtp.is_response) {
            line << "SMTP_COMMAND:" << separator;
            line << "SMTP_ARGUMENTS:" << separator;
            line << "SMTP_STATUS_CODE:" << metadata.smtp.status_code << separator;
            if (!metadata.smtp.status_text.empty()) {
                line << "SMTP_STATUS_TEXT:" << metadata.smtp.status_text << separator;
            } else {
                line << "SMTP_STATUS_TEXT:" << separator;
            }
        } else {
            line << "SMTP_COMMAND:" << separator;
            line << "SMTP_ARGUMENTS:" << separator;
            line << "SMTP_STATUS_CODE:0" << separator;
            line << "SMTP_STATUS_TEXT:" << separator;
        }
        
        line << "SMTP_MESSAGE_LENGTH:" << metadata.smtp.message_length << separator;
        if (!metadata.smtp.message_preview.empty()) {
            line << "SMTP_MESSAGE_PREVIEW:" << metadata.smtp.message_preview << separator;
        } else {
            line << "SMTP_MESSAGE_PREVIEW:" << separator;
        }
    }
    
    // SSH metadata (only output for SSH packets)
    if (metadata.has_ssh) {
        line << "HAS_SSH:1" << separator;
        line << "SSH_MESSAGE_TYPE:" << metadata.ssh.message_type << separator;
        
        if (metadata.ssh.is_identification) {
            line << "SSH_IDENTIFICATION_STRING:" << escapeJsonString(metadata.ssh.identification_string) << separator;
            line << "SSH_SOFTWARE_VERSION:" << metadata.ssh.software_version << separator;
            line << "SSH_PROTOCOL_VERSION:" << metadata.ssh.protocol_version << separator;
        } else {
            line << "SSH_IDENTIFICATION_STRING:" << separator;
            line << "SSH_SOFTWARE_VERSION:" << separator;
            line << "SSH_PROTOCOL_VERSION:" << separator;
        }
        
        if (metadata.ssh.is_handshake) {
            line << "SSH_HANDSHAKE_MESSAGE_TYPE:" << static_cast<int>(metadata.ssh.handshake_message_type) << separator;
            line << "SSH_HANDSHAKE_TYPE_STR:" << metadata.ssh.handshake_type_str << separator;
            line << "SSH_PACKET_LENGTH:" << metadata.ssh.packet_length << separator;
            line << "SSH_PADDING_LENGTH:" << metadata.ssh.padding_length << separator;
            line << "SSH_MESSAGE_CONTENT_LENGTH:" << metadata.ssh.message_content_length << separator;
        } else {
            line << "SSH_HANDSHAKE_MESSAGE_TYPE:0" << separator;
            line << "SSH_HANDSHAKE_TYPE_STR:" << separator;
            line << "SSH_PACKET_LENGTH:0" << separator;
            line << "SSH_PADDING_LENGTH:0" << separator;
            line << "SSH_MESSAGE_CONTENT_LENGTH:0" << separator;
        }
        
        if (metadata.ssh.is_key_exchange) {
            line << "SSH_COOKIE_HEX:" << metadata.ssh.cookie_hex << separator;
            line << "SSH_KEY_EXCHANGE_ALGORITHMS:" << escapeJsonString(metadata.ssh.key_exchange_algorithms) << separator;
            line << "SSH_SERVER_HOST_KEY_ALGORITHMS:" << escapeJsonString(metadata.ssh.server_host_key_algorithms) << separator;
            line << "SSH_ENCRYPTION_ALGORITHMS_CLIENT_TO_SERVER:" << escapeJsonString(metadata.ssh.encryption_algorithms_client_to_server) << separator;
            line << "SSH_ENCRYPTION_ALGORITHMS_SERVER_TO_CLIENT:" << escapeJsonString(metadata.ssh.encryption_algorithms_server_to_client) << separator;
            line << "SSH_MAC_ALGORITHMS_CLIENT_TO_SERVER:" << escapeJsonString(metadata.ssh.mac_algorithms_client_to_server) << separator;
            line << "SSH_MAC_ALGORITHMS_SERVER_TO_CLIENT:" << escapeJsonString(metadata.ssh.mac_algorithms_server_to_client) << separator;
            line << "SSH_COMPRESSION_ALGORITHMS_CLIENT_TO_SERVER:" << escapeJsonString(metadata.ssh.compression_algorithms_client_to_server) << separator;
            line << "SSH_COMPRESSION_ALGORITHMS_SERVER_TO_CLIENT:" << escapeJsonString(metadata.ssh.compression_algorithms_server_to_client) << separator;
            line << "SSH_LANGUAGES_CLIENT_TO_SERVER:" << escapeJsonString(metadata.ssh.languages_client_to_server) << separator;
            line << "SSH_LANGUAGES_SERVER_TO_CLIENT:" << escapeJsonString(metadata.ssh.languages_server_to_client) << separator;
            line << "SSH_FIRST_KEX_PACKET_FOLLOWS:" << (metadata.ssh.first_kex_packet_follows ? "1" : "0") << separator;
        } else {
            line << "SSH_COOKIE_HEX:" << separator;
            line << "SSH_KEY_EXCHANGE_ALGORITHMS:" << separator;
            line << "SSH_SERVER_HOST_KEY_ALGORITHMS:" << separator;
            line << "SSH_ENCRYPTION_ALGORITHMS_CLIENT_TO_SERVER:" << separator;
            line << "SSH_ENCRYPTION_ALGORITHMS_SERVER_TO_CLIENT:" << separator;
            line << "SSH_MAC_ALGORITHMS_CLIENT_TO_SERVER:" << separator;
            line << "SSH_MAC_ALGORITHMS_SERVER_TO_CLIENT:" << separator;
            line << "SSH_COMPRESSION_ALGORITHMS_CLIENT_TO_SERVER:" << separator;
            line << "SSH_COMPRESSION_ALGORITHMS_SERVER_TO_CLIENT:" << separator;
            line << "SSH_LANGUAGES_CLIENT_TO_SERVER:" << separator;
            line << "SSH_LANGUAGES_SERVER_TO_CLIENT:" << separator;
            line << "SSH_FIRST_KEX_PACKET_FOLLOWS:0" << separator;
        }
        
        line << "SSH_TOTAL_MESSAGE_LENGTH:" << metadata.ssh.total_message_length << separator;
        if (!metadata.ssh.message_preview.empty()) {
            line << "SSH_MESSAGE_PREVIEW:" << escapeJsonString(metadata.ssh.message_preview) << separator;
        } else {
            line << "SSH_MESSAGE_PREVIEW:" << separator;
        }
        line << "SSH_SESSION_INFO:" << escapeJsonString(metadata.ssh.session_info) << separator;
    }
    
    // Telnet metadata (only output for Telnet packets)
    if (metadata.has_telnet) {
        line << "HAS_TELNET:1" << separator;
        line << "TELNET_TYPE:" << metadata.telnet.type << separator;
        line << "TELNET_SESSION_TYPE:" << metadata.telnet.session_type << separator;
        line << "TELNET_IS_CONTROL:" << (metadata.telnet.is_control ? "1" : "0") << separator;
        line << "TELNET_IS_TEXT:" << (metadata.telnet.is_text ? "1" : "0") << separator;
        line << "TELNET_COMMAND_COUNT:" << metadata.telnet.command_count << separator;
        line << "TELNET_IAC_SEQUENCES:" << metadata.telnet.iac_sequences << separator;
        line << "TELNET_TEXT_SEQUENCES:" << metadata.telnet.text_sequences << separator;
        line << "TELNET_TOTAL_DATA_LENGTH:" << metadata.telnet.total_data_length << separator;
        
        if (metadata.telnet.hasCommands()) {
            line << "TELNET_COMMAND_SUMMARY:" << metadata.telnet.getCommandSummary() << separator;
        } else {
            line << "TELNET_COMMAND_SUMMARY:No commands" << separator;
        }
        
        if (metadata.telnet.hasText()) {
            line << "TELNET_TEXT_LENGTH:" << metadata.telnet.text_length << separator;
            line << "TELNET_TEXT_PREVIEW:" << escapeJsonString(metadata.telnet.getTextPreview()) << separator;
            if (!metadata.telnet.filtered_text.empty()) {
                line << "TELNET_FILTERED_TEXT:" << escapeJsonString(metadata.telnet.filtered_text) << separator;
            } else {
                line << "TELNET_FILTERED_TEXT:" << separator;
            }
        } else {
            line << "TELNET_TEXT_LENGTH:0" << separator;
            line << "TELNET_TEXT_PREVIEW:" << separator;
            line << "TELNET_FILTERED_TEXT:" << separator;
        }
    }
    
    // SSL/TLS specific fields (only output if SSL/TLS is present)
    if (metadata.has_ssl) {
        line << "HAS_SSL: true" << separator;
        line << "SSL_TYPE:" << SSLParser::getRecordTypeString(metadata.ssl.record_type) << separator;
        line << "SSL_VERSION:" << SSLParser::getVersionString(metadata.ssl.record_version) << separator;
        line << "SSL_LENGTH:" << metadata.ssl.record_length << separator;
        
        // Output different fields based on SSL layer type
        if (metadata.ssl.is_handshake_layer) {
            line << "SSL_HANDSHAKE_TYPE:" << SSLParser::getHandshakeTypeString(metadata.ssl.handshake_data.handshake_type) << separator;
            line << "SSL_HANDSHAKE_VERSION:" << SSLParser::getVersionString(metadata.ssl.handshake_data.handshake_version) << separator;
            line << "SSL_HANDSHAKE_LENGTH:" << metadata.ssl.handshake_data.handshake_length << separator;
        }
        
        // Client/Server Hello specific fields (only for handshake layer)
        if (metadata.ssl.is_handshake_layer) {
            line << "SSL_IS_CLIENT_HELLO:" << (metadata.ssl.handshake_data.is_client_hello ? "1" : "0") << separator;
            line << "SSL_IS_SERVER_HELLO:" << (metadata.ssl.handshake_data.is_server_hello ? "1" : "0") << separator;
            line << "SSL_SESSION_ID_LENGTH:" << static_cast<int>(metadata.ssl.handshake_data.session_id_length) << separator;
            line << "SSL_SESSION_ID:" << SSLParser::bytesToHexString(metadata.ssl.handshake_data.session_id.data(), metadata.ssl.handshake_data.session_id.size(), 16) << separator;
            
            // Cipher suite information
            line << "SSL_CIPHER_SUITES_COUNT:" << metadata.ssl.handshake_data.cipher_suites.size() << separator;
            line << "SSL_CIPHER_SUITES:" << SSLParser::bytesToHexString(
                reinterpret_cast<const uint8_t*>(metadata.ssl.handshake_data.cipher_suites.data()), 
                metadata.ssl.handshake_data.cipher_suites.size() * 2, 32) << separator;
            line << "SSL_SELECTED_CIPHER_SUITE:" << metadata.ssl.handshake_data.selected_cipher_suite << separator;
            line << "SSL_SELECTED_CIPHER_SUITE_ID:0x" << std::hex << metadata.ssl.handshake_data.selected_cipher_suite_id << std::dec << separator;
        } else {
            line << "SSL_IS_CLIENT_HELLO:0" << separator;
            line << "SSL_IS_SERVER_HELLO:0" << separator;
            line << "SSL_SESSION_ID_LENGTH:0" << separator;
            line << "SSL_SESSION_ID:" << separator;
            line << "SSL_CIPHER_SUITES_COUNT:0" << separator;
            line << "SSL_CIPHER_SUITES:" << separator;
            line << "SSL_SELECTED_CIPHER_SUITE:" << separator;
            line << "SSL_SELECTED_CIPHER_SUITE_ID:0x0" << separator;
        }
        
        // Compression methods (only for handshake layer)
        if (metadata.ssl.is_handshake_layer) {
            line << "SSL_COMPRESSION_METHODS_COUNT:" << static_cast<int>(metadata.ssl.handshake_data.compression_methods_count) << separator;
            line << "SSL_COMPRESSION_METHODS:" << SSLParser::bytesToHexString(
                metadata.ssl.handshake_data.compression_methods.data(), metadata.ssl.handshake_data.compression_methods.size(), 16) << separator;
            
            // Extensions
            line << "SSL_EXTENSIONS_COUNT:" << metadata.ssl.handshake_data.extension_types.size() << separator;
            line << "SSL_EXTENSIONS:" << SSLParser::bytesToHexString(
                reinterpret_cast<const uint8_t*>(metadata.ssl.handshake_data.extension_types.data()), 
                metadata.ssl.handshake_data.extension_types.size() * 2, 32) << separator;
            
            // Supported groups (elliptic curves)
            line << "SSL_SUPPORTED_GROUPS_COUNT:" << metadata.ssl.handshake_data.supported_groups.size() << separator;
            line << "SSL_SUPPORTED_GROUPS:" << SSLParser::bytesToHexString(
                reinterpret_cast<const uint8_t*>(metadata.ssl.handshake_data.supported_groups.data()), 
                metadata.ssl.handshake_data.supported_groups.size() * 2, 32) << separator;
            line << "SSL_SUPPORTED_GROUP_NAMES:" << escapeJsonString(metadata.ssl.getSupportedGroupsString()) << separator;
            
            // EC point formats
            line << "SSL_EC_POINT_FORMATS_COUNT:" << metadata.ssl.handshake_data.ec_point_formats.size() << separator;
            line << "SSL_EC_POINT_FORMATS:" << SSLParser::bytesToHexString(
                metadata.ssl.handshake_data.ec_point_formats.data(), metadata.ssl.handshake_data.ec_point_formats.size(), 16) << separator;
            
            // Server name indication
            line << "SSL_SERVER_NAMES_COUNT:" << metadata.ssl.handshake_data.server_names.size() << separator;
            if (!metadata.ssl.handshake_data.server_names.empty()) {
                line << "SSL_SERVER_NAMES:" << escapeJsonString(metadata.ssl.handshake_data.server_names[0]) << separator;
            } else {
                line << "SSL_SERVER_NAMES:" << separator;
            }
            
            // Supported versions
            line << "SSL_SUPPORTED_VERSIONS_COUNT:" << metadata.ssl.handshake_data.supported_versions.size() << separator;
            line << "SSL_SUPPORTED_VERSIONS:" << SSLParser::bytesToHexString(
                reinterpret_cast<const uint8_t*>(metadata.ssl.handshake_data.supported_versions.data()), 
                metadata.ssl.handshake_data.supported_versions.size() * 2, 32) << separator;
            
            // Random data
            line << "SSL_RANDOM_DATA:" << SSLParser::bytesToHexString(metadata.ssl.handshake_data.random_data.data(), metadata.ssl.handshake_data.random_data.size(), 32) << separator;
        } else {
            line << "SSL_COMPRESSION_METHODS_COUNT:0" << separator;
            line << "SSL_COMPRESSION_METHODS:" << separator;
            line << "SSL_EXTENSIONS_COUNT:0" << separator;
            line << "SSL_EXTENSIONS:" << separator;
            line << "SSL_SUPPORTED_GROUPS_COUNT:0" << separator;
            line << "SSL_SUPPORTED_GROUPS:" << separator;
            line << "SSL_SUPPORTED_GROUP_NAMES:" << separator;
            line << "SSL_EC_POINT_FORMATS_COUNT:0" << separator;
            line << "SSL_EC_POINT_FORMATS:" << separator;
            line << "SSL_SERVER_NAMES_COUNT:0" << separator;
            line << "SSL_SERVER_NAMES:" << separator;
            line << "SSL_SUPPORTED_VERSIONS_COUNT:0" << separator;
            line << "SSL_SUPPORTED_VERSIONS:" << separator;
            line << "SSL_RANDOM_DATA:" << separator;
        }
        
        // Certificate information (only for handshake layer)
        if (metadata.ssl.is_handshake_layer) {
            line << "SSL_HAS_CERTIFICATE:" << (metadata.ssl.handshake_data.has_certificate ? "1" : "0") << separator;
            line << "SSL_CERTIFICATE_COUNT:" << metadata.ssl.handshake_data.certificate_count << separator;
            if (!metadata.ssl.handshake_data.certificate_subjects.empty()) {
                line << "SSL_CERTIFICATE_SUBJECTS:" << escapeJsonString(metadata.ssl.handshake_data.certificate_subjects[0]) << separator;
            } else {
                line << "SSL_CERTIFICATE_SUBJECTS:" << separator;
            }
        } else {
            line << "SSL_HAS_CERTIFICATE:0" << separator;
            line << "SSL_CERTIFICATE_COUNT:0" << separator;
            line << "SSL_CERTIFICATE_SUBJECTS:" << separator;
        }
        
        // X.509 Certificate metadata (parsed from ASN.1) - only for handshake layer
        if (metadata.ssl.is_handshake_layer && !metadata.ssl.handshake_data.certificates.empty()) {
            const auto& cert = metadata.ssl.handshake_data.certificates[0]; // Use first certificate for now
            
            // Basic certificate information
            line << "CERTIFICATE.VERSION:" << cert.version << separator;
            line << "CERTIFICATE.SERIAL:" << escapeJsonString(cert.serial_number) << separator;
            line << "CERTIFICATE.SIGNATURE_ALGORITHM_OID:" << escapeJsonString(cert.signature_algorithm_oid) << separator;
            line << "CERTIFICATE.SIGNATURE_ALGORITHM_NAME:" << escapeJsonString(cert.signature_algorithm_name) << separator;
            
            // Issuer information
            line << "CERTIFICATE.ISSUER:" << escapeJsonString(cert.getIssuerString()) << separator;
            line << "CERTIFICATE.ISSUER_COUNTRY:" << escapeJsonString(cert.issuer_country) << separator;
            line << "CERTIFICATE.ISSUER_ORGANIZATION:" << escapeJsonString(cert.issuer_organization) << separator;
            line << "CERTIFICATE.ISSUER_ORGANIZATIONAL_UNIT:" << escapeJsonString(cert.issuer_organizational_unit) << separator;
            line << "CERTIFICATE.ISSUER_COMMON_NAME:" << escapeJsonString(cert.issuer_common_name) << separator;
            line << "CERTIFICATE.ISSUER_STATE:" << escapeJsonString(cert.issuer_state) << separator;
            line << "CERTIFICATE.ISSUER_LOCALITY:" << escapeJsonString(cert.issuer_locality) << separator;
            line << "CERTIFICATE.ISSUER_EMAIL:" << escapeJsonString(cert.issuer_email) << separator;
            
            // Validity period
            line << "CERTIFICATE.NOT_VALID_BEFORE:" << cert.not_valid_before << separator;
            line << "CERTIFICATE.NOT_VALID_AFTER:" << cert.not_valid_after << separator;
            line << "CERTIFICATE.NOT_VALID_BEFORE_STR:" << escapeJsonString(cert.not_valid_before_str) << separator;
            line << "CERTIFICATE.NOT_VALID_AFTER_STR:" << escapeJsonString(cert.not_valid_after_str) << separator;
            
            // Subject information
            line << "CERTIFICATE.SUBJECT:" << escapeJsonString(cert.getSubjectString()) << separator;
            line << "CERTIFICATE.SUBJECT_COUNTRY:" << escapeJsonString(cert.subject_country) << separator;
            line << "CERTIFICATE.SUBJECT_ORGANIZATION:" << escapeJsonString(cert.subject_organization) << separator;
            line << "CERTIFICATE.SUBJECT_ORGANIZATIONAL_UNIT:" << escapeJsonString(cert.subject_organizational_unit) << separator;
            line << "CERTIFICATE.SUBJECT_COMMON_NAME:" << escapeJsonString(cert.subject_common_name) << separator;
            line << "CERTIFICATE.SUBJECT_STATE:" << escapeJsonString(cert.subject_state) << separator;
            line << "CERTIFICATE.SUBJECT_LOCALITY:" << escapeJsonString(cert.subject_locality) << separator;
            line << "CERTIFICATE.SUBJECT_EMAIL:" << escapeJsonString(cert.subject_email) << separator;
            
            // Public key information
            line << "CERTIFICATE.KEY_ALGORITHM_OID:" << escapeJsonString(cert.key_algorithm_oid) << separator;
            line << "CERTIFICATE.KEY_ALGORITHM_NAME:" << escapeJsonString(cert.key_algorithm_name) << separator;
            line << "CERTIFICATE.KEY_TYPE:" << escapeJsonString(cert.key_type) << separator;
            line << "CERTIFICATE.KEY_LENGTH:" << cert.key_length << separator;
            line << "CERTIFICATE.EXPONENT:" << escapeJsonString(cert.exponent) << separator;
            line << "CERTIFICATE.PUBLIC_KEY_HEX:" << escapeJsonString(cert.public_key_hex) << separator;
            line << "CERTIFICATE.PUBLIC_KEY_MODULUS:" << escapeJsonString(cert.public_key_modulus) << separator;
            line << "CERTIFICATE.PUBLIC_KEY_EXPONENT:" << escapeJsonString(cert.public_key_exponent) << separator;
            
            // Extensions
            line << "CERTIFICATE.HAS_EXTENSIONS:" << (cert.has_extensions ? "1" : "0") << separator;
            
            // SAN (Subject Alternative Name)
            if (!cert.dns_names.empty()) {
                line << "SAN.DNS:";
                for (size_t i = 0; i < cert.dns_names.size(); ++i) {
                    if (i > 0) line << ";";
                    line << escapeJsonString(cert.dns_names[i]);
                }
                line << separator;
            } else {
                line << "SAN.DNS:" << separator;
            }
            
            if (!cert.email_addresses.empty()) {
                line << "SAN.EMAIL:";
                for (size_t i = 0; i < cert.email_addresses.size(); ++i) {
                    if (i > 0) line << ";";
                    line << escapeJsonString(cert.email_addresses[i]);
                }
                line << separator;
            } else {
                line << "SAN.EMAIL:" << separator;
            }
            
            if (!cert.ip_addresses.empty()) {
                line << "SAN.IP:";
                for (size_t i = 0; i < cert.ip_addresses.size(); ++i) {
                    if (i > 0) line << ";";
                    line << escapeJsonString(cert.ip_addresses[i]);
                }
                line << separator;
            } else {
                line << "SAN.IP:" << separator;
            }
            
            if (!cert.uris.empty()) {
                line << "SAN.URI:";
                for (size_t i = 0; i < cert.uris.size(); ++i) {
                    if (i > 0) line << ";";
                    line << escapeJsonString(cert.uris[i]);
                }
                line << separator;
            } else {
                line << "SAN.URI:" << separator;
            }
            
            // Key Usage
            line << "CERTIFICATE.KEY_USAGE_DIGITAL_SIGNATURE:" << (cert.key_usage_digital_signature ? "1" : "0") << separator;
            line << "CERTIFICATE.KEY_USAGE_NON_REPUDIATION:" << (cert.key_usage_non_repudiation ? "1" : "0") << separator;
            line << "CERTIFICATE.KEY_USAGE_KEY_ENCIPHERMENT:" << (cert.key_usage_key_encipherment ? "1" : "0") << separator;
            line << "CERTIFICATE.KEY_USAGE_DATA_ENCIPHERMENT:" << (cert.key_usage_data_encipherment ? "1" : "0") << separator;
            line << "CERTIFICATE.KEY_USAGE_KEY_AGREEMENT:" << (cert.key_usage_key_agreement ? "1" : "0") << separator;
            line << "CERTIFICATE.KEY_USAGE_KEY_CERT_SIGN:" << (cert.key_usage_key_cert_sign ? "1" : "0") << separator;
            line << "CERTIFICATE.KEY_USAGE_CRL_SIGN:" << (cert.key_usage_crl_sign ? "1" : "0") << separator;
            line << "CERTIFICATE.KEY_USAGE_ENCIPHER_ONLY:" << (cert.key_usage_encipher_only ? "1" : "0") << separator;
            line << "CERTIFICATE.KEY_USAGE_DECIPHER_ONLY:" << (cert.key_usage_decipher_only ? "1" : "0") << separator;
            
            // Extended Key Usage
            if (!cert.extended_key_usage.empty()) {
                line << "CERTIFICATE.EXTENDED_KEY_USAGE:";
                for (size_t i = 0; i < cert.extended_key_usage.size(); ++i) {
                    if (i > 0) line << ";";
                    line << escapeJsonString(cert.extended_key_usage[i]);
                }
                line << separator;
            } else {
                line << "CERTIFICATE.EXTENDED_KEY_USAGE:" << separator;
            }
            
            line << "CERTIFICATE.EXT_KEY_USAGE_SERVER_AUTH:" << (cert.ext_key_usage_server_auth ? "1" : "0") << separator;
            line << "CERTIFICATE.EXT_KEY_USAGE_CLIENT_AUTH:" << (cert.ext_key_usage_client_auth ? "1" : "0") << separator;
            line << "CERTIFICATE.EXT_KEY_USAGE_CODE_SIGNING:" << (cert.ext_key_usage_code_signing ? "1" : "0") << separator;
            line << "CERTIFICATE.EXT_KEY_USAGE_EMAIL_PROTECTION:" << (cert.ext_key_usage_email_protection ? "1" : "0") << separator;
            line << "CERTIFICATE.EXT_KEY_USAGE_TIME_STAMPING:" << (cert.ext_key_usage_time_stamping ? "1" : "0") << separator;
            line << "CERTIFICATE.EXT_KEY_USAGE_OCSP_SIGNING:" << (cert.ext_key_usage_ocsp_signing ? "1" : "0") << separator;
            
            // Basic Constraints
            line << "BASIC_CONSTRAINTS.CA:" << (cert.is_ca ? "1" : "0") << separator;
            line << "BASIC_CONSTRAINTS.PATH_LENGTH_CONSTRAINT:" << cert.path_length_constraint << separator;
            
            // Authority Information Access
            line << "CERTIFICATE.AUTHORITY_KEY_ID:" << escapeJsonString(cert.authority_key_id) << separator;
            line << "CERTIFICATE.AUTHORITY_CERT_ISSUER:" << escapeJsonString(cert.authority_cert_issuer) << separator;
            line << "CERTIFICATE.AUTHORITY_CERT_SERIAL:" << escapeJsonString(cert.authority_cert_serial) << separator;
            line << "CERTIFICATE.SUBJECT_KEY_ID:" << escapeJsonString(cert.subject_key_id) << separator;
            
            // CRL Distribution Points
            if (!cert.crl_distribution_points.empty()) {
                line << "CERTIFICATE.CRL_DISTRIBUTION_POINTS:";
                for (size_t i = 0; i < cert.crl_distribution_points.size(); ++i) {
                    if (i > 0) line << ";";
                    line << escapeJsonString(cert.crl_distribution_points[i]);
                }
                line << separator;
            } else {
                line << "CERTIFICATE.CRL_DISTRIBUTION_POINTS:" << separator;
            }
            
            // OCSP Responders
            if (!cert.ocsp_responders.empty()) {
                line << "CERTIFICATE.OCSP_RESPONDERS:";
                for (size_t i = 0; i < cert.ocsp_responders.size(); ++i) {
                    if (i > 0) line << ";";
                    line << escapeJsonString(cert.ocsp_responders[i]);
                }
                line << separator;
            } else {
                line << "CERTIFICATE.OCSP_RESPONDERS:" << separator;
            }
            
            // CA Issuers
            if (!cert.ca_issuers.empty()) {
                line << "CERTIFICATE.CA_ISSUERS:";
                for (size_t i = 0; i < cert.ca_issuers.size(); ++i) {
                    if (i > 0) line << ";";
                    line << escapeJsonString(cert.ca_issuers[i]);
                }
                line << separator;
            } else {
                line << "CERTIFICATE.CA_ISSUERS:" << separator;
            }
            
            // Certificate Policies
            if (!cert.certificate_policies.empty()) {
                line << "CERTIFICATE.CERTIFICATE_POLICIES:";
                for (size_t i = 0; i < cert.certificate_policies.size(); ++i) {
                    if (i > 0) line << ";";
                    line << escapeJsonString(cert.certificate_policies[i]);
                }
                line << separator;
            } else {
                line << "CERTIFICATE.CERTIFICATE_POLICIES:" << separator;
            }
            
            // Certificate fingerprinting
            line << "CERTIFICATE.FINGERPRINT_SHA1:" << escapeJsonString(cert.fingerprint_sha1) << separator;
            line << "CERTIFICATE.FINGERPRINT_SHA256:" << escapeJsonString(cert.fingerprint_sha256) << separator;
            line << "CERTIFICATE.FINGERPRINT_MD5:" << escapeJsonString(cert.fingerprint_md5) << separator;
            
            // Certificate validation
            line << "CERTIFICATE.IS_SELF_SIGNED:" << (cert.is_self_signed ? "1" : "0") << separator;
            line << "CERTIFICATE.IS_VALID:" << (cert.is_valid ? "1" : "0") << separator;
            line << "CERTIFICATE.VALIDATION_ERROR:" << escapeJsonString(cert.validation_error) << separator;
            
            // Raw ASN.1 data
            line << "CERTIFICATE.ASN1_DER_HEX:" << escapeJsonString(cert.asn1_der_hex) << separator;
        }
        
        // Alert information (only for alert layer)
        if (metadata.ssl.is_alert_layer) {
            line << "SSL_ALERT_LEVEL:" << static_cast<int>(metadata.ssl.alert_data.alert_level) << separator;
            line << "SSL_ALERT_DESCRIPTION:" << static_cast<int>(metadata.ssl.alert_data.alert_description) << separator;
        }
        
        // Change cipher spec (only for change cipher spec layer)
        if (metadata.ssl.is_change_cipher_spec_layer) {
            line << "SSL_IS_CHANGE_CIPHER_SPEC:" << (metadata.ssl.change_cipher_spec_data.is_change_cipher_spec ? "1" : "0") << separator;
        }
        
        // Application data (only for application data layer)
        if (metadata.ssl.is_application_data_layer) {
            line << "SSL_IS_APPLICATION_DATA:1" << separator;
            line << "SSL_APPLICATION_DATA_LENGTH:" << metadata.ssl.application_data_info.application_data_length << separator;
            line << "SSL_IS_ENCRYPTED:" << (metadata.ssl.application_data_info.is_encrypted ? "1" : "0") << separator;
        }
        
        // SSL state
        if (!metadata.ssl.ssl_state.empty()) {
            line << "SSL_STATE:" << escapeJsonString(metadata.ssl.ssl_state) << separator;
        } else {
            line << "SSL_STATE:" << separator;
        }
    }
    
    // BGP specific fields (only output if BGP is present)
    if (metadata.has_bgp) {
        line << "HAS_BGP:1" << separator;
        line << "BGP_MARKER:" << metadata.bgp.marker << separator;
        line << "BGP_LENGTH:" << metadata.bgp.length << separator;
        line << "BGP_TYPE:" << static_cast<int>(metadata.bgp.type) << separator;
        line << "BGP_TYPE_STR:" << metadata.bgp.type_str << separator;
        
        // BGP OPEN message fields
        if (metadata.bgp.type == BGPMetadata::OPEN) {
            line << "BGP_VERSION:" << static_cast<int>(metadata.bgp.version) << separator;
            line << "BGP_MY_AS:" << metadata.bgp.my_as << separator;
            line << "BGP_HOLD_TIME:" << metadata.bgp.hold_time << separator;
            line << "BGP_IDENTIFIER:" << metadata.bgp.bgp_identifier << separator;
            
            // Optional parameters
            if (!metadata.bgp.optional_parameters.empty()) {
                line << "BGP_OPTIONAL_PARAMETERS:";
                for (size_t i = 0; i < metadata.bgp.optional_parameters.size(); i++) {
                    if (i > 0) line << ";";
                    line << metadata.bgp.optional_parameters[i];
                }
                line << separator;
            } else {
                line << "BGP_OPTIONAL_PARAMETERS:" << separator;
            }
        }
        
        // BGP UPDATE message fields
        if (metadata.bgp.type == BGPMetadata::UPDATE) {
            // Withdrawn routes
            if (!metadata.bgp.withdrawn_routes.empty()) {
                line << "BGP_WITHDRAWN_ROUTES:";
                for (size_t i = 0; i < metadata.bgp.withdrawn_routes.size(); i++) {
                    if (i > 0) line << ";";
                    line << metadata.bgp.withdrawn_routes[i];
                }
                line << separator;
            } else {
                line << "BGP_WITHDRAWN_ROUTES:" << separator;
            }
            
            // Path attributes
            if (!metadata.bgp.path_attributes.empty()) {
                line << "BGP_PATH_ATTRIBUTES:";
                for (size_t i = 0; i < metadata.bgp.path_attributes.size(); i++) {
                    if (i > 0) line << ";";
                    line << metadata.bgp.path_attributes[i];
                }
                line << separator;
            } else {
                line << "BGP_PATH_ATTRIBUTES:" << separator;
            }
            
            // Specific path attributes
            if (!metadata.bgp.origin.empty()) line << "BGP_ORIGIN:" << metadata.bgp.origin << separator;
            else line << "BGP_ORIGIN:" << separator;
            
            if (!metadata.bgp.as_path.empty()) line << "BGP_AS_PATH:" << metadata.bgp.as_path << separator;
            else line << "BGP_AS_PATH:" << separator;
            
            if (!metadata.bgp.next_hop.empty()) line << "BGP_NEXT_HOP:" << metadata.bgp.next_hop << separator;
            else line << "BGP_NEXT_HOP:" << separator;
            
            if (metadata.bgp.local_pref > 0) line << "BGP_LOCAL_PREF:" << metadata.bgp.local_pref << separator;
            else line << "BGP_LOCAL_PREF:0" << separator;
            
            if (metadata.bgp.med > 0) line << "BGP_MED:" << metadata.bgp.med << separator;
            else line << "BGP_MED:0" << separator;
            
            if (!metadata.bgp.community.empty()) line << "BGP_COMMUNITY:" << metadata.bgp.community << separator;
            else line << "BGP_COMMUNITY:" << separator;
            
            if (!metadata.bgp.mp_reach_nlri.empty()) line << "BGP_MP_REACH_NLRI:" << metadata.bgp.mp_reach_nlri << separator;
            else line << "BGP_MP_REACH_NLRI:" << separator;
            
            if (!metadata.bgp.mp_unreach_nlri.empty()) line << "BGP_MP_UNREACH_NLRI:" << metadata.bgp.mp_unreach_nlri << separator;
            else line << "BGP_MP_UNREACH_NLRI:" << separator;
            
            // NLRI
            if (!metadata.bgp.nlri.empty()) {
                line << "BGP_NLRI:";
                for (size_t i = 0; i < metadata.bgp.nlri.size(); i++) {
                    if (i > 0) line << ";";
                    line << metadata.bgp.nlri[i];
                }
                line << separator;
            } else {
                line << "BGP_NLRI:" << separator;
            }
        }
        // Note: BGP UPDATE fields are only output when BGP type is UPDATE
        
        // BGP NOTIFICATION message fields
        if (metadata.bgp.type == BGPMetadata::NOTIFICATION) {
            line << "BGP_ERROR_CODE:" << static_cast<int>(metadata.bgp.error_code) << separator;
            line << "BGP_ERROR_SUBCODE:" << static_cast<int>(metadata.bgp.error_subcode) << separator;
            if (!metadata.bgp.error_data.empty()) line << "BGP_ERROR_DATA:" << metadata.bgp.error_data << separator;
            else line << "BGP_ERROR_DATA:" << separator;
        }
        // Note: BGP NOTIFICATION fields are only output when BGP type is NOTIFICATION
        
        // BGP ROUTE-REFRESH message fields
        if (metadata.bgp.type == BGPMetadata::ROUTE_REFRESH) {
            line << "BGP_AFI:" << metadata.bgp.afi << separator;
            line << "BGP_SAFI:" << static_cast<int>(metadata.bgp.safi) << separator;
            line << "BGP_RESERVED:" << static_cast<int>(metadata.bgp.reserved) << separator;
        }
        // Note: BGP ROUTE-REFRESH fields are only output when BGP type is ROUTE-REFRESH
    }
    // Note: BGP fields are only output when has_bgp = true
    
    line << "PACKET_LENGTH:" << metadata.packet_length << separator;
    line << "PAYLOAD_LENGTH:" << metadata.payload_length << separator;
    line << "CONTROL_FIELD_SIZE:" << (metadata.packet_length - metadata.payload_length);

    const std::string text = line.str();
    std::ostream* out = nullptr;
    if (category == "ethernet" && ethernetLogFile.is_open()) out = &ethernetLogFile;
    else if (category == "wifi" && wifiLogFile.is_open()) out = &wifiLogFile;
    else if (category == "error" && errorLogFile.is_open()) out = &errorLogFile;

    if (out) {
        (*out) << text << std::endl;
    } else if (logFile.is_open()) {
        logFile << text << std::endl;
    } else {
        std::cout << text << std::endl;
    }
}

std::string LoggerManager::escapeJsonString(const std::string& str) {
    std::string escaped;
    escaped.reserve(str.length() * 2); // Reserve space to avoid frequent reallocations
    
    for (char c : str) {
        switch (c) {
            case '"':  escaped += "\\\""; break;
            case '\\': escaped += "\\\\"; break;
            case '\b': escaped += "\\b"; break;
            case '\f': escaped += "\\f"; break;
            case '\n': escaped += "\\n"; break;
            case '\r': escaped += "\\r"; break;
            case '\t': escaped += "\\t"; break;
            default:
                if (c >= 0 && c < 32) {
                    // Control characters
                    escaped += "\\u";
                    escaped += "0000";
                    escaped[escaped.length()-2] = "0123456789abcdef"[(c >> 4) & 0xf];
                    escaped[escaped.length()-1] = "0123456789abcdef"[c & 0xf];
                } else {
                    escaped += c;
                }
                break;
        }
    }
    return escaped;
}

void LoggerManager::logConnJSON(const PacketMetadata& metadata, const std::string& category)
{
    std::lock_guard<std::mutex> lock(logMutex);

    std::ostringstream oss;
    oss << "{";
    
    // Basic metadata
    oss << "\"TIMESTAMP\":" << std::fixed << std::setprecision(6) << metadata.timestamp << ",";
    
    // Data link layer metadata
    if (metadata.has_ethernet) {
        oss << "\"SRC_MAC\":\"";
        for (int i = 0; i < 6; i++) { 
            if (i > 0) oss << ":"; 
            oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(metadata.ethernet.src_mac[i]); 
        }
        oss << std::dec << std::setfill(' ') << "\",";
        oss << "\"DST_MAC\":\"";
        for (int i = 0; i < 6; i++) { 
            if (i > 0) oss << ":"; 
            oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(metadata.ethernet.dst_mac[i]); 
        }
        oss << std::dec << std::setfill(' ') << "\",";
        oss << "\"ETHERTYPE\":\"" << BaseParser::etherTypeToString(metadata.ethernet.ethertype) << "\",";
    } else if (metadata.has_wifi) {
        // WiFi metadata
        oss << "\"WIFI_SRC_MAC\":\"";
        for (int i = 0; i < 6; i++) {
            if (i > 0) oss << ":";
            oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(metadata.wifi.src_mac[i]);
        }
        oss << std::dec << std::setfill(' ') << "\",";
        oss << "\"WIFI_DST_MAC\":\"";
        for (int i = 0; i < 6; i++) {
            if (i > 0) oss << ":";
            oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(metadata.wifi.dst_mac[i]);
        }
        oss << std::dec << std::setfill(' ') << "\",";
        oss << "\"WIFI_BSSID\":\"";
        for (int i = 0; i < 6; i++) {
            if (i > 0) oss << ":";
            oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(metadata.wifi.bssid[i]);
        }
        oss << std::dec << std::setfill(' ') << "\",";
        oss << "\"WIFI_FRAME_TYPE\":" << static_cast<int>(metadata.wifi.frame_type) << ",";
        oss << "\"WIFI_FRAME_SUBTYPE\":" << static_cast<int>(metadata.wifi.frame_subtype) << ",";
        oss << "\"WIFI_TO_DS\":" << (metadata.wifi.to_ds ? "true" : "false") << ",";
        oss << "\"WIFI_FROM_DS\":" << (metadata.wifi.from_ds ? "true" : "false") << ",";
        oss << "\"WIFI_SEQUENCE\":" << metadata.wifi.sequence_number << ",";
        if (metadata.wifi.rssi != 0) oss << "\"WIFI_RSSI\":" << static_cast<int>(metadata.wifi.rssi) << ",";
        if (metadata.wifi.channel != 0) oss << "\"WIFI_CHANNEL\":" << static_cast<int>(metadata.wifi.channel) << ",";
    } else {
        oss << "\"SRC_MAC\":\"00:00:00:00:00:00\",";
        oss << "\"DST_MAC\":\"00:00:00:00:00:00\",";
        oss << "\"ETHERTYPE\":0,";
    }
    
    if (metadata.has_vlan) { 
        oss << "\"HAS_VLAN\":true,";
        oss << "\"VLAN_ID\":" << metadata.vlan.vlan_id << ","; 
        oss << "\"VLAN_PRIORITY\":" << static_cast<int>(metadata.vlan.vlan_priority) << ","; 
    }
    
    if (metadata.has_gre) {
        oss << "\"HAS_GRE\":true,";
        oss << "\"GRE_VERSION\":" << static_cast<int>(metadata.gre.version) << ",";
        oss << "\"GRE_PROTOCOL\":\"" << std::hex << metadata.gre.protocol << std::dec << "\",";
        oss << "\"GRE_RECURSION_CONTROL\":" << static_cast<int>(metadata.gre.recursion_control) << ",";
        oss << "\"GRE_CHECKSUM_BIT\":" << (metadata.gre.checksum_bit ? "true" : "false") << ",";
        oss << "\"GRE_ROUTING_BIT\":" << (metadata.gre.routing_bit ? "true" : "false") << ",";
        oss << "\"GRE_KEY_BIT\":" << (metadata.gre.key_bit ? "true" : "false") << ",";
        oss << "\"GRE_SEQUENCE_BIT\":" << (metadata.gre.sequence_bit ? "true" : "false") << ",";
        oss << "\"GRE_STRICT_SOURCE_ROUTE\":" << (metadata.gre.strict_source_route ? "true" : "false") << ",";
        oss << "\"GRE_ACK_SEQUENCE_BIT\":" << (metadata.gre.ack_sequence_bit ? "true" : "false") << ",";
        if (metadata.gre.checksum_bit) oss << "\"GRE_CHECKSUM\":\"" << std::hex << metadata.gre.checksum << std::dec << "\","; else oss << "\"GRE_CHECKSUM\":0,";
        if (metadata.gre.routing_bit) oss << "\"GRE_OFFSET\":" << metadata.gre.offset << ","; else oss << "\"GRE_OFFSET\":0,";
        if (metadata.gre.key_bit) oss << "\"GRE_KEY\":\"" << std::hex << metadata.gre.key << std::dec << "\","; else oss << "\"GRE_KEY\":0,";
        if (metadata.gre.sequence_bit) oss << "\"GRE_SEQUENCE\":" << metadata.gre.sequence << ","; else oss << "\"GRE_SEQUENCE\":0,";
        if (metadata.gre.ack_sequence_bit) oss << "\"GRE_ACK_SEQUENCE\":" << metadata.gre.ack_sequence << ","; else oss << "\"GRE_ACK_SEQUENCE\":0,";
        if (metadata.gre.version == 1) { 
            oss << "\"GRE_PAYLOAD_LENGTH\":" << metadata.gre.payload_length << ","; 
            oss << "\"GRE_CALL_ID\":" << metadata.gre.call_id << ","; 
        }
        else { 
            oss << "\"GRE_PAYLOAD_LENGTH\":0," << "\"GRE_CALL_ID\":0,"; 
        }
    }
    
    oss << "\"SRC_IP\":\"" << metadata.srcIP << "\",";
    oss << "\"DST_IP\":\"" << metadata.dstIP << "\",";
    oss << "\"PROTOCOL\":\"" << metadata.protocol << "\",";
    
    // IPv6 specific fields (only output if IPv6 is present)
    if (metadata.has_ipv6) {
        oss << "\"IPV6_HOP_LIMIT\":" << static_cast<int>(metadata.ipv6.hop_limit) << ",";
        oss << "\"IPV6_FLOW_LABEL\":" << metadata.ipv6.flow_label << ",";
        oss << "\"IPV6_TRAFFIC_CLASS\":" << static_cast<int>(metadata.ipv6.traffic_class) << ",";
        oss << "\"IPV6_NEXT_HEADER\":" << static_cast<int>(metadata.ipv6.next_header) << ",";
        oss << "\"IPV6_PAYLOAD_LENGTH\":" << metadata.ipv6.payload_length << ",";
        
        // IPv6 extension headers
        if (metadata.ipv6.hop_by_hop.present) {
            oss << "\"IPV6_HOP_BY_HOP\":true,";
            oss << "\"IPV6_HOP_BY_HOP_TYPE\":" << static_cast<int>(metadata.ipv6.hop_by_hop.type) << ",";
            oss << "\"IPV6_HOP_BY_HOP_LENGTH\":" << static_cast<int>(metadata.ipv6.hop_by_hop.length) << ",";
        }
        
        if (metadata.ipv6.routing.present) {
            oss << "\"IPV6_ROUTING\":true,";
            oss << "\"IPV6_ROUTING_TYPE\":" << static_cast<int>(metadata.ipv6.routing.type) << ",";
            oss << "\"IPV6_ROUTING_LENGTH\":" << static_cast<int>(metadata.ipv6.routing.length) << ",";
            oss << "\"IPV6_ROUTING_TYPE_VALUE\":" << static_cast<int>(metadata.ipv6.routing_type) << ",";
            oss << "\"IPV6_SEGMENTS_LEFT\":" << static_cast<int>(metadata.ipv6.segments_left) << ",";
        }
        
        if (metadata.ipv6.fragment.present) {
            oss << "\"IPV6_FRAGMENT\":true,";
            oss << "\"IPV6_FRAGMENT_TYPE\":" << static_cast<int>(metadata.ipv6.fragment.type) << ",";
            oss << "\"IPV6_FRAGMENT_LENGTH\":" << static_cast<int>(metadata.ipv6.fragment.length) << ",";
            oss << "\"IPV6_FRAGMENT_OFFSET\":" << metadata.ipv6.fragment_offset << ",";
            oss << "\"IPV6_FRAGMENT_MORE\":" << (metadata.ipv6.fragment_more ? "true" : "false") << ",";
            oss << "\"IPV6_FRAGMENT_ID\":" << metadata.ipv6.fragment_id << ",";
        }
        
        if (metadata.ipv6.destination.present) {
            oss << "\"IPV6_DESTINATION\":true,";
            oss << "\"IPV6_DESTINATION_TYPE\":" << static_cast<int>(metadata.ipv6.destination.type) << ",";
            oss << "\"IPV6_DESTINATION_LENGTH\":" << static_cast<int>(metadata.ipv6.destination.length) << ",";
        }
        
        if (metadata.ipv6.ah.present) {
            oss << "\"IPV6_AH\":true,";
            oss << "\"IPV6_AH_TYPE\":" << static_cast<int>(metadata.ipv6.ah.type) << ",";
            oss << "\"IPV6_AH_LENGTH\":" << static_cast<int>(metadata.ipv6.ah.length) << ",";
        }
        
        if (metadata.ipv6.esp.present) {
            oss << "\"IPV6_ESP\":true,";
            oss << "\"IPV6_ESP_TYPE\":" << static_cast<int>(metadata.ipv6.esp.type) << ",";
            oss << "\"IPV6_ESP_LENGTH\":" << static_cast<int>(metadata.ipv6.esp.length) << ",";
        }
    }
    oss << "\"SRC_PORT\":" << metadata.srcPort << ",";
    oss << "\"DST_PORT\":" << metadata.dstPort << ",";
    
    if (metadata.has_tcp) {
        oss << "\"TCP_SEQ\":" << metadata.tcp.seq << ",";
        oss << "\"TCP_ACK\":" << metadata.tcp.ack << ",";
        if (metadata.tcp.flags > 0) {
            oss << "\"TCP_FLAGS\":\"";
            if (metadata.tcp.syn) oss << "S";
            if (metadata.tcp.ack_flag) oss << "A";
            if (metadata.tcp.fin) oss << "F";
            if (metadata.tcp.rst) oss << "R";
            if (metadata.tcp.psh) oss << "P";
            oss << "\",";
        } else {
            oss << "\"TCP_FLAGS\":0,";
        }
        oss << "\"TCP_WINDOW\":" << metadata.tcp.window << ",";
    }
    
    if (metadata.has_udp) {
        oss << "\"UDP_LENGTH\":" << metadata.udp.length << ",";
    }
    
    // HTTP specific fields
    if (metadata.has_http) {
        oss << "\"HTTP_TYPE\":\"" << metadata.http.type << "\",";
        oss << "\"HTTP_METHOD\":\"" << metadata.http.method << "\",";
        oss << "\"HTTP_URI\":\"" << metadata.http.uri << "\",";
        oss << "\"HTTP_VERSION\":\"" << metadata.http.version << "\",";
        
        if (metadata.http.is_response) {
            oss << "\"HTTP_STATUS_CODE\":" << metadata.http.status_code << ",";
            oss << "\"HTTP_STATUS_TEXT\":\"" << metadata.http.status_text << "\",";
        }
        
        // Common HTTP headers
        if (!metadata.http.host.empty()) oss << "\"HTTP_HOST\":\"" << metadata.http.host << "\",";
        if (!metadata.http.user_agent.empty()) oss << "\"HTTP_USER_AGENT\":\"" << metadata.http.user_agent << "\",";
        if (!metadata.http.content_type.empty()) oss << "\"HTTP_CONTENT_TYPE\":\"" << metadata.http.content_type << "\",";
        if (!metadata.http.content_length.empty()) oss << "\"HTTP_CONTENT_LENGTH\":\"" << metadata.http.content_length << "\",";
        if (!metadata.http.connection.empty()) oss << "\"HTTP_CONNECTION\":\"" << metadata.http.connection << "\",";
        if (!metadata.http.accept.empty()) oss << "\"HTTP_ACCEPT\":\"" << metadata.http.accept << "\",";
        if (!metadata.http.accept_encoding.empty()) oss << "\"HTTP_ACCEPT_ENCODING\":\"" << metadata.http.accept_encoding << "\",";
        if (!metadata.http.accept_language.empty()) oss << "\"HTTP_ACCEPT_LANGUAGE\":\"" << metadata.http.accept_language << "\",";
        if (!metadata.http.cache_control.empty()) oss << "\"HTTP_CACHE_CONTROL\":\"" << metadata.http.cache_control << "\",";
        if (!metadata.http.cookie.empty()) oss << "\"HTTP_COOKIE\":\"" << metadata.http.cookie << "\",";
        if (!metadata.http.set_cookie.empty()) oss << "\"HTTP_SET_COOKIE\":\"" << metadata.http.set_cookie << "\",";
        if (!metadata.http.referer.empty()) oss << "\"HTTP_REFERER\":\"" << metadata.http.referer << "\",";
        if (!metadata.http.location.empty()) oss << "\"HTTP_LOCATION\":\"" << metadata.http.location << "\",";
        if (!metadata.http.server.empty()) oss << "\"HTTP_SERVER\":\"" << metadata.http.server << "\",";
        if (!metadata.http.date.empty()) oss << "\"HTTP_DATE\":\"" << metadata.http.date << "\",";
        if (!metadata.http.last_modified.empty()) oss << "\"HTTP_LAST_MODIFIED\":\"" << metadata.http.last_modified << "\",";
        if (!metadata.http.etag.empty()) oss << "\"HTTP_ETAG\":\"" << metadata.http.etag << "\",";
        if (!metadata.http.expires.empty()) oss << "\"HTTP_EXPIRES\":\"" << metadata.http.expires << "\",";
        
        // HTTP body information
        if (metadata.http.body_length > 0) {
            oss << "\"HTTP_BODY_LENGTH\":" << metadata.http.body_length << ",";
            if (!metadata.http.body_preview.empty()) oss << "\"HTTP_BODY_PREVIEW\":\"" << metadata.http.body_preview << "\",";
        }
    }
    
    // ARP specific fields (only output if ARP is present)
    if (metadata.has_arp) {
        oss << "\"ARP_HARDWARE_TYPE\":" << metadata.arp.hardware_type << ",";
        oss << "\"ARP_PROTOCOL_TYPE\":" << std::hex << metadata.arp.protocol_type << std::dec << ",";
        
        // Convert ARP operation to string
        std::string arpOpStr;
        switch (metadata.arp.operation) {
            case 1: arpOpStr = "REQUEST"; break;
            case 2: arpOpStr = "REPLY"; break;
            case 3: arpOpStr = "RARP_REQUEST"; break;
            case 4: arpOpStr = "RARP_REPLY"; break;
            case 5: arpOpStr = "DRARP_REQUEST"; break;
            case 6: arpOpStr = "DRARP_REPLY"; break;
            case 7: arpOpStr = "DRARP_ERROR"; break;
            case 8: arpOpStr = "INARP_REQUEST"; break;
            case 9: arpOpStr = "INARP_REPLY"; break;
            default: arpOpStr = "UNKNOWN(" + std::to_string(metadata.arp.operation) + ")"; break;
        }
        oss << "\"ARP_OPERATION\":\"" << arpOpStr << "\",";
        
        oss << "\"ARP_SENDER_MAC\":\"" << metadata.arp.sender_mac_str << "\",";
        oss << "\"ARP_SENDER_IP\":\"" << metadata.arp.sender_ip_str << "\",";
        oss << "\"ARP_TARGET_MAC\":\"" << metadata.arp.target_mac_str << "\",";
        oss << "\"ARP_TARGET_IP\":\"" << metadata.arp.target_ip_str << "\",";
    }
    
    // ICMP specific fields (only output if ICMP is present)
    if (metadata.has_icmp) {
        // Convert ICMP type to string
        std::string icmpTypeStr;
        switch (metadata.icmp.type) {
            case 0: icmpTypeStr = "ECHO_REPLY"; break;
            case 3: icmpTypeStr = "DEST_UNREACHABLE"; break;
            case 4: icmpTypeStr = "SOURCE_QUENCH"; break;
            case 5: icmpTypeStr = "REDIRECT"; break;
            case 8: icmpTypeStr = "ECHO_REQUEST"; break;
            case 11: icmpTypeStr = "TIME_EXCEEDED"; break;
            case 12: icmpTypeStr = "PARAM_PROBLEM"; break;
            case 13: icmpTypeStr = "TIMESTAMP_REQUEST"; break;
            case 14: icmpTypeStr = "TIMESTAMP_REPLY"; break;
            case 15: icmpTypeStr = "INFO_REQUEST"; break;
            case 16: icmpTypeStr = "INFO_REPLY"; break;
            default: icmpTypeStr = "TYPE_" + std::to_string(metadata.icmp.type); break;
        }
        oss << "\"ICMP_TYPE\":\"" << icmpTypeStr << "\",";
        oss << "\"ICMP_CODE\":" << (int)metadata.icmp.code << ",";
        oss << "\"ICMP_CHECKSUM\":" << metadata.icmp.checksum << ",";
        
        // For echo request/reply
        if (metadata.icmp.type == 0 || metadata.icmp.type == 8) {
            oss << "\"ICMP_IDENTIFIER\":" << metadata.icmp.identifier << ",";
            oss << "\"ICMP_SEQUENCE\":" << metadata.icmp.sequence << ",";
        }
        
        // For destination unreachable
        if (metadata.icmp.type == 3) {
            oss << "\"ICMP_ORIGINAL_IP\":\"" << 
                ((metadata.icmp.original_ip >> 24) & 0xFF) << "." <<
                ((metadata.icmp.original_ip >> 16) & 0xFF) << "." <<
                ((metadata.icmp.original_ip >> 8) & 0xFF) << "." <<
                (metadata.icmp.original_ip & 0xFF) << "\",";
            oss << "\"ICMP_ORIGINAL_PROTOCOL\":" << (int)metadata.icmp.original_protocol << ",";
            oss << "\"ICMP_ORIGINAL_PORT\":" << metadata.icmp.original_port << ",";
        }
        
        // For redirect messages
        if (metadata.icmp.type == 5) {
            oss << "\"ICMP_GATEWAY_IP\":\"" << 
                ((metadata.icmp.gateway_ip >> 24) & 0xFF) << "." <<
                ((metadata.icmp.gateway_ip >> 16) & 0xFF) << "." <<
                ((metadata.icmp.gateway_ip >> 8) & 0xFF) << "." <<
                (metadata.icmp.gateway_ip & 0xFF) << "\",";
        }
    }
    
    // DNS specific fields
    if (metadata.has_dns) {
        oss << "\"HAS_DNS\":" << (metadata.has_dns ? "true" : "false") << ",";
        oss << "\"DNS_TRANSACTION_ID\":\"0x" << std::hex << metadata.dns.transaction_id << std::dec << "\",";
        oss << "\"DNS_MESSAGE_TYPE\":\"" << metadata.dns.message_type << "\",";
        oss << "\"DNS_OPCODE\":\"" << metadata.dns.opcode_str << "\",";
        oss << "\"DNS_RCODE\":\"" << metadata.dns.rcode_str << "\",";
        
        // DNS flags
        oss << "\"DNS_FLAGS\":\"" << DNSParser::getFlagsString(metadata.dns) << "\",";
        
        // Counts
        oss << "\"DNS_QUESTIONS\":" << metadata.dns.questions << ",";
        oss << "\"DNS_ANSWERS\":" << metadata.dns.answers << ",";
        oss << "\"DNS_AUTHORITY\":" << metadata.dns.authority_records << ",";
        oss << "\"DNS_ADDITIONAL\":" << metadata.dns.additional_records << ",";
        
        // Question section
        if (!metadata.dns.qname.empty()) {
            oss << "\"DNS_QNAME\":\"" << escapeJsonString(metadata.dns.qname) << "\",";
            oss << "\"DNS_QTYPE\":\"" << escapeJsonString(metadata.dns.qtype_str) << "\",";
            oss << "\"DNS_QCLASS\":\"" << escapeJsonString(metadata.dns.qclass_str) << "\",";
        } else {
            oss << "\"DNS_QNAME\":\"\",";
            oss << "\"DNS_QTYPE\":\"\",";
            oss << "\"DNS_QCLASS\":\"\",";
        }
        
        // Answer records (first few)
        if (!metadata.dns.answer_records.empty()) {
            oss << "\"DNS_ANSWERS_DETAIL\":\"";
            for (size_t i = 0; i < std::min(static_cast<size_t>(3), metadata.dns.answer_records.size()); i++) {
                const auto& record = metadata.dns.answer_records[i];
                if (i > 0) oss << ";";
                oss << escapeJsonString(record.name) << ":" << escapeJsonString(record.type_str) << ":" << escapeJsonString(record.rdata);
            }
            oss << "\",";
            oss << "\"DNS_MORE_ANSWERS\":" << (metadata.dns.answer_records.size() > 3 ? metadata.dns.answer_records.size() - 3 : 0) << ",";
        } else {
            oss << "\"DNS_ANSWERS_DETAIL\":\"\",";
            oss << "\"DNS_MORE_ANSWERS\":0,";
        }
        
        oss << "\"DNS_PACKET_SIZE\":" << metadata.dns.dns_packet_size << ",";
    }
    
    if (metadata.has_dhcp) {
        // DHCP specific fields
        oss << "\"HAS_DHCP\":" << (metadata.has_dhcp ? "true" : "false") << ",";
        DHCPParser::formatForJSON(metadata.dhcp, oss, [this](const std::string& str) { return escapeJsonString(str); });
    }
    
    if (metadata.has_dhcpv6) {
        // DHCPv6 specific fields
        oss << "\"HAS_DHCPV6\":" << (metadata.has_dhcpv6 ? "true" : "false") << ",";
        DHCPv6Parser::formatForJSON(metadata.dhcpv6, oss, [this](const std::string& str) { return escapeJsonString(str); });
    }
    
    // NTP specific fields (only output if NTP is present)
    if (metadata.has_ntp) {
        oss << "\"HAS_NTP\":" << (metadata.has_ntp ? "true" : "false") << ",";
        oss << "\"NTP_LI\":" << static_cast<int>(metadata.ntp.li) << ",";
        oss << "\"NTP_LI_STR\":\"" << escapeJsonString(metadata.ntp.li_str) << "\",";
        oss << "\"NTP_VN\":" << static_cast<int>(metadata.ntp.vn) << ",";
        oss << "\"NTP_VN_STR\":\"" << escapeJsonString(metadata.ntp.vn_str) << "\",";
        oss << "\"NTP_MODE\":" << static_cast<int>(metadata.ntp.mode) << ",";
        oss << "\"NTP_MODE_STR\":\"" << escapeJsonString(metadata.ntp.mode_str) << "\",";
        oss << "\"NTP_STRATUM\":" << static_cast<int>(metadata.ntp.stratum) << ",";
        oss << "\"NTP_STRATUM_STR\":\"" << escapeJsonString(metadata.ntp.stratum_str) << "\",";
        oss << "\"NTP_POLL\":" << static_cast<int>(metadata.ntp.poll) << ",";
        oss << "\"NTP_PRECISION\":" << static_cast<int>(metadata.ntp.precision) << ",";
        oss << "\"NTP_ROOT_DELAY\":" << metadata.ntp.root_delay << ",";
        oss << "\"NTP_ROOT_DISPERSION\":" << metadata.ntp.root_dispersion << ",";
        oss << "\"NTP_REFERENCE_ID\":" << metadata.ntp.reference_id << ",";
        oss << "\"NTP_REFERENCE_ID_STR\":\"" << escapeJsonString(metadata.ntp.reference_id_str) << "\",";
        oss << "\"NTP_REFERENCE_TIMESTAMP\":" << metadata.ntp.reference_timestamp << ",";
        oss << "\"NTP_ORIGINATE_TIMESTAMP\":" << metadata.ntp.originate_timestamp << ",";
        oss << "\"NTP_RECEIVE_TIMESTAMP\":" << metadata.ntp.receive_timestamp << ",";
        oss << "\"NTP_TRANSMIT_TIMESTAMP\":" << metadata.ntp.transmit_timestamp << ",";
        oss << "\"NTP_TIME_OFFSET\":" << std::fixed << std::setprecision(3) << metadata.ntp.time_offset << ",";
        oss << "\"NTP_ROUND_TRIP_DELAY\":" << std::fixed << std::setprecision(3) << metadata.ntp.round_trip_delay << ",";
    }
    
    // ARP specific fields (only output if ARP is present)
    if (metadata.has_arp) {
        oss << "\"HAS_ARP\":" << (metadata.has_arp ? "true" : "false") << ",";
        oss << "\"ARP_HARDWARE_TYPE\":" << metadata.arp.hardware_type << ",";
        oss << "\"ARP_PROTOCOL_TYPE\":" << std::hex << metadata.arp.protocol_type << std::dec << ",";
        
        // Convert ARP operation to string
        std::string arpOpStr;
        switch (metadata.arp.operation) {
            case 1: arpOpStr = "REQUEST"; break;
            case 2: arpOpStr = "REPLY"; break;
            case 3: arpOpStr = "RARP_REQUEST"; break;
            case 4: arpOpStr = "RARP_REPLY"; break;
            case 5: arpOpStr = "DRARP_REQUEST"; break;
            case 6: arpOpStr = "DRARP_REPLY"; break;
            case 7: arpOpStr = "DRARP_ERROR"; break;
            case 8: arpOpStr = "INARP_REQUEST"; break;
            case 9: arpOpStr = "INARP_REPLY"; break;
            default: arpOpStr = "UNKNOWN(" + std::to_string(metadata.arp.operation) + ")"; break;
        }
        oss << "\"ARP_OPERATION\":\"" << arpOpStr << "\",";
        
        oss << "\"ARP_SENDER_MAC\":\"" << metadata.arp.sender_mac_str << "\",";
        oss << "\"ARP_SENDER_IP\":\"" << metadata.arp.sender_ip_str << "\",";
        oss << "\"ARP_TARGET_MAC\":\"" << metadata.arp.target_mac_str << "\",";
        oss << "\"ARP_TARGET_IP\":\"" << metadata.arp.target_ip_str << "\",";
    }
    
    // ICMP specific fields (only output if ICMP is present)
    if (metadata.has_icmp) {
        // Convert ICMP type to string
        std::string icmpTypeStr;
        switch (metadata.icmp.type) {
            case 0: icmpTypeStr = "ECHO_REPLY"; break;
            case 3: icmpTypeStr = "DEST_UNREACHABLE"; break;
            case 4: icmpTypeStr = "SOURCE_QUENCH"; break;
            case 5: icmpTypeStr = "REDIRECT"; break;
            case 8: icmpTypeStr = "ECHO_REQUEST"; break;
            case 11: icmpTypeStr = "TIME_EXCEEDED"; break;
            case 12: icmpTypeStr = "PARAM_PROBLEM"; break;
            case 13: icmpTypeStr = "TIMESTAMP_REQUEST"; break;
            case 14: icmpTypeStr = "TIMESTAMP_REPLY"; break;
            case 15: icmpTypeStr = "INFO_REQUEST"; break;
            case 16: icmpTypeStr = "INFO_REPLY"; break;
            default: icmpTypeStr = "TYPE_" + std::to_string(metadata.icmp.type); break;
        }
        oss << "\"ICMP_TYPE\":\"" << icmpTypeStr << "\",";
        oss << "\"ICMP_CODE\":" << (int)metadata.icmp.code << ",";
        oss << "\"ICMP_CHECKSUM\":" << metadata.icmp.checksum << ",";
        
        // For echo request/reply
        if (metadata.icmp.type == 0 || metadata.icmp.type == 8) {
            oss << "\"ICMP_IDENTIFIER\":" << metadata.icmp.identifier << ",";
            oss << "\"ICMP_SEQUENCE\":" << metadata.icmp.sequence << ",";
        }
        
        // For destination unreachable
        if (metadata.icmp.type == 3) {
            oss << "\"ICMP_ORIGINAL_IP\":\"" << 
                ((metadata.icmp.original_ip >> 24) & 0xFF) << "." <<
                ((metadata.icmp.original_ip >> 16) & 0xFF) << "." <<
                ((metadata.icmp.original_ip >> 8) & 0xFF) << "." <<
                (metadata.icmp.original_ip & 0xFF) << "\",";
            oss << "\"ICMP_ORIGINAL_PROTOCOL\":" << (int)metadata.icmp.original_protocol << ",";
            oss << "\"ICMP_ORIGINAL_PORT\":" << metadata.icmp.original_port << ",";
        }
        
        // For redirect messages
        if (metadata.icmp.type == 5) {
            oss << "\"ICMP_GATEWAY_IP\":\"" << 
                ((metadata.icmp.gateway_ip >> 24) & 0xFF) << "." <<
                ((metadata.icmp.gateway_ip >> 16) & 0xFF) << "." <<
                ((metadata.icmp.gateway_ip >> 8) & 0xFF) << "." <<
                (metadata.icmp.gateway_ip & 0xFF) << "\",";
        }
    }
    
    // FTP specific fields - only output for FTP packets
    if (metadata.has_ftp) {
        oss << "\"HAS_FTP\":true,";
        oss << "\"FTP_TYPE\":\"" << escapeJsonString(metadata.ftp.type) << "\",";
        
        if (metadata.ftp.is_control) {
            if (metadata.ftp.is_request && !metadata.ftp.command.empty()) {
                oss << "\"FTP_COMMAND\":\"" << escapeJsonString(metadata.ftp.command) << "\",";
                if (!metadata.ftp.arguments.empty()) {
                    oss << "\"FTP_ARGUMENTS\":\"" << escapeJsonString(metadata.ftp.arguments) << "\",";
                } else {
                    oss << "\"FTP_ARGUMENTS\":\"\",";
                }
            } else {
                oss << "\"FTP_COMMAND\":\"\",";
                oss << "\"FTP_ARGUMENTS\":\"\",";
            }
            
            if (metadata.ftp.is_response && metadata.ftp.response_code != 0) {
                oss << "\"FTP_RESPONSE_CODE\":" << metadata.ftp.response_code << ",";
                if (!metadata.ftp.response_text.empty()) {
                    oss << "\"FTP_RESPONSE_TEXT\":\"" << escapeJsonString(metadata.ftp.response_text) << "\",";
                } else {
                    oss << "\"FTP_RESPONSE_TEXT\":\"\",";
                }
            } else {
                oss << "\"FTP_RESPONSE_CODE\":0,";
                oss << "\"FTP_RESPONSE_TEXT\":\"\",";
            }
        } else {
            oss << "\"FTP_COMMAND\":\"\",";
            oss << "\"FTP_ARGUMENTS\":\"\",";
            oss << "\"FTP_RESPONSE_CODE\":0,";
            oss << "\"FTP_RESPONSE_TEXT\":\"\",";
        }
        
        if (metadata.ftp.is_data) {
            oss << "\"FTP_DATA_LENGTH\":" << metadata.ftp.data_length << ",";
            if (!metadata.ftp.transfer_mode.empty()) {
                oss << "\"FTP_TRANSFER_MODE\":\"" << escapeJsonString(metadata.ftp.transfer_mode) << "\",";
            } else {
                oss << "\"FTP_TRANSFER_MODE\":\"\",";
            }
            if (!metadata.ftp.data_preview.empty()) {
                oss << "\"FTP_DATA_PREVIEW\":\"" << escapeJsonString(metadata.ftp.data_preview) << "\",";
            } else {
                oss << "\"FTP_DATA_PREVIEW\":\"\",";
            }
        } else {
            oss << "\"FTP_DATA_LENGTH\":0,";
            oss << "\"FTP_TRANSFER_MODE\":\"\",";
            oss << "\"FTP_DATA_PREVIEW\":\"\",";
        }
    }
    
    // SMTP metadata (only output for SMTP packets)
    if (metadata.has_smtp) {
        oss << "\"HAS_SMTP\":true,";
        oss << "\"SMTP_TYPE\":\"" << escapeJsonString(metadata.smtp.type) << "\",";
        
        if (metadata.smtp.is_request) {
            if (!metadata.smtp.command.empty()) {
                oss << "\"SMTP_COMMAND\":\"" << escapeJsonString(metadata.smtp.command) << "\",";
            } else {
                oss << "\"SMTP_COMMAND\":\"\",";
            }
            if (!metadata.smtp.arguments.empty()) {
                oss << "\"SMTP_ARGUMENTS\":\"" << escapeJsonString(metadata.smtp.arguments) << "\",";
            } else {
                oss << "\"SMTP_ARGUMENTS\":\"\",";
            }
            oss << "\"SMTP_STATUS_CODE\":0,";
            oss << "\"SMTP_STATUS_TEXT\":\"\",";
        } else if (metadata.smtp.is_response) {
            oss << "\"SMTP_COMMAND\":\"\",";
            oss << "\"SMTP_ARGUMENTS\":\"\",";
            oss << "\"SMTP_STATUS_CODE\":" << metadata.smtp.status_code << ",";
            if (!metadata.smtp.status_text.empty()) {
                oss << "\"SMTP_STATUS_TEXT\":\"" << escapeJsonString(metadata.smtp.status_text) << "\",";
            } else {
                oss << "\"SMTP_STATUS_TEXT\":\"\",";
            }
        } else {
            oss << "\"SMTP_COMMAND\":\"\",";
            oss << "\"SMTP_ARGUMENTS\":\"\",";
            oss << "\"SMTP_STATUS_CODE\":0,";
            oss << "\"SMTP_STATUS_TEXT\":\"\",";
        }
        
        oss << "\"SMTP_MESSAGE_LENGTH\":" << metadata.smtp.message_length << ",";
        if (!metadata.smtp.message_preview.empty()) {
            oss << "\"SMTP_MESSAGE_PREVIEW\":\"" << escapeJsonString(metadata.smtp.message_preview) << "\",";
        } else {
            oss << "\"SMTP_MESSAGE_PREVIEW\":\"\",";
        }
    }
    
    // SSL/TLS metadata (only output for SSL/TLS packets)
    if (metadata.has_ssl) {
        oss << "\"HAS_SSL\":true,";
        oss << "\"SSL_TYPE\":\"" << escapeJsonString(SSLParser::getRecordTypeString(metadata.ssl.record_type)) << "\",";
        oss << "\"SSL_VERSION\":\"" << escapeJsonString(SSLParser::getVersionString(metadata.ssl.record_version)) << "\",";
        oss << "\"SSL_LENGTH\":" << metadata.ssl.record_length << ",";
        // Output different fields based on SSL layer type
        if (metadata.ssl.is_handshake_layer) {
            oss << "\"SSL_HANDSHAKE_TYPE\":\"" << escapeJsonString(SSLParser::getHandshakeTypeString(metadata.ssl.handshake_data.handshake_type)) << "\",";
            oss << "\"SSL_HANDSHAKE_VERSION\":\"" << escapeJsonString(SSLParser::getVersionString(metadata.ssl.handshake_data.handshake_version)) << "\",";
            oss << "\"SSL_HANDSHAKE_LENGTH\":" << metadata.ssl.handshake_data.handshake_length << ",";
            
            // Client/Server Hello specific fields
            oss << "\"SSL_IS_CLIENT_HELLO\":" << (metadata.ssl.handshake_data.is_client_hello ? "true" : "false") << ",";
            oss << "\"SSL_IS_SERVER_HELLO\":" << (metadata.ssl.handshake_data.is_server_hello ? "true" : "false") << ",";
            oss << "\"SSL_SESSION_ID_LENGTH\":" << static_cast<int>(metadata.ssl.handshake_data.session_id_length) << ",";
            oss << "\"SSL_SESSION_ID\":\"" << escapeJsonString(SSLParser::bytesToHexString(metadata.ssl.handshake_data.session_id.data(), metadata.ssl.handshake_data.session_id.size(), 16)) << "\",";
            
            // Cipher suite information
            oss << "\"SSL_CIPHER_SUITES_COUNT\":" << metadata.ssl.handshake_data.cipher_suites.size() << ",";
            oss << "\"SSL_CIPHER_SUITES\":\"" << escapeJsonString(SSLParser::bytesToHexString(
                reinterpret_cast<const uint8_t*>(metadata.ssl.handshake_data.cipher_suites.data()), 
                metadata.ssl.handshake_data.cipher_suites.size() * 2, 32)) << "\",";
            oss << "\"SSL_SELECTED_CIPHER_SUITE\":\"" << escapeJsonString(metadata.ssl.handshake_data.selected_cipher_suite) << "\",";
            oss << "\"SSL_SELECTED_CIPHER_SUITE_ID\":\"0x" << std::hex << metadata.ssl.handshake_data.selected_cipher_suite_id << std::dec << "\",";
        }
        
        // Compression methods (only for handshake layer)
        if (metadata.ssl.is_handshake_layer) {
            oss << "\"SSL_COMPRESSION_METHODS_COUNT\":" << static_cast<int>(metadata.ssl.handshake_data.compression_methods_count) << ",";
            oss << "\"SSL_COMPRESSION_METHODS\":\"" << escapeJsonString(SSLParser::bytesToHexString(
                metadata.ssl.handshake_data.compression_methods.data(), metadata.ssl.handshake_data.compression_methods.size(), 16)) << "\",";
            
            // Extensions
            oss << "\"SSL_EXTENSIONS_COUNT\":" << metadata.ssl.handshake_data.extension_types.size() << ",";
            oss << "\"SSL_EXTENSIONS\":\"" << escapeJsonString(SSLParser::bytesToHexString(
                reinterpret_cast<const uint8_t*>(metadata.ssl.handshake_data.extension_types.data()), 
                metadata.ssl.handshake_data.extension_types.size() * 2, 32)) << "\",";
            
            // Supported groups (elliptic curves)
            oss << "\"SSL_SUPPORTED_GROUPS_COUNT\":" << metadata.ssl.handshake_data.supported_groups.size() << ",";
            oss << "\"SSL_SUPPORTED_GROUPS\":\"" << escapeJsonString(SSLParser::bytesToHexString(
                reinterpret_cast<const uint8_t*>(metadata.ssl.handshake_data.supported_groups.data()), 
                metadata.ssl.handshake_data.supported_groups.size() * 2, 32)) << "\",";
            oss << "\"SSL_SUPPORTED_GROUP_NAMES\":\"" << escapeJsonString(metadata.ssl.getSupportedGroupsString()) << "\",";
            
            // EC point formats
            oss << "\"SSL_EC_POINT_FORMATS_COUNT\":" << metadata.ssl.handshake_data.ec_point_formats.size() << ",";
            oss << "\"SSL_EC_POINT_FORMATS\":\"" << escapeJsonString(SSLParser::bytesToHexString(
                metadata.ssl.handshake_data.ec_point_formats.data(), metadata.ssl.handshake_data.ec_point_formats.size(), 16)) << "\",";
            
            // Server name indication
            oss << "\"SSL_SERVER_NAMES_COUNT\":" << metadata.ssl.handshake_data.server_names.size() << ",";
            if (!metadata.ssl.handshake_data.server_names.empty()) {
                oss << "\"SSL_SERVER_NAMES\":\"" << escapeJsonString(metadata.ssl.handshake_data.server_names[0]) << "\",";
            } else {
                oss << "\"SSL_SERVER_NAMES\":\"\",";
            }
            
            // Supported versions
            oss << "\"SSL_SUPPORTED_VERSIONS_COUNT\":" << metadata.ssl.handshake_data.supported_versions.size() << ",";
            oss << "\"SSL_SUPPORTED_VERSIONS\":\"" << escapeJsonString(SSLParser::bytesToHexString(
                reinterpret_cast<const uint8_t*>(metadata.ssl.handshake_data.supported_versions.data()), 
                metadata.ssl.handshake_data.supported_versions.size() * 2, 32)) << "\",";
            
            // Random data
            oss << "\"SSL_RANDOM_DATA\":\"" << escapeJsonString(SSLParser::bytesToHexString(metadata.ssl.handshake_data.random_data.data(), metadata.ssl.handshake_data.random_data.size(), 32)) << "\",";
        }
        
        // Certificate information (only for handshake layer)
        if (metadata.ssl.is_handshake_layer) {
            oss << "\"SSL_HAS_CERTIFICATE\":" << (metadata.ssl.handshake_data.has_certificate ? "true" : "false") << ",";
            oss << "\"SSL_CERTIFICATE_COUNT\":" << metadata.ssl.handshake_data.certificate_count << ",";
            if (!metadata.ssl.handshake_data.certificate_subjects.empty()) {
                oss << "\"SSL_CERTIFICATE_SUBJECTS\":\"" << escapeJsonString(metadata.ssl.handshake_data.certificate_subjects[0]) << "\",";
            } else {
                oss << "\"SSL_CERTIFICATE_SUBJECTS\":\"\",";
            }
        }
        
        // X.509 Certificate metadata (parsed from ASN.1) - only for handshake layer
        if (metadata.ssl.is_handshake_layer && !metadata.ssl.handshake_data.certificates.empty()) {
            const auto& cert = metadata.ssl.handshake_data.certificates[0]; // Use first certificate for now
            
            // Basic certificate information
            oss << "\"CERTIFICATE.VERSION\":" << cert.version << ",";
            oss << "\"CERTIFICATE.SERIAL\":\"" << escapeJsonString(cert.serial_number) << "\",";
            oss << "\"CERTIFICATE.SIGNATURE_ALGORITHM_OID\":\"" << escapeJsonString(cert.signature_algorithm_oid) << "\",";
            oss << "\"CERTIFICATE.SIGNATURE_ALGORITHM_NAME\":\"" << escapeJsonString(cert.signature_algorithm_name) << "\",";
            
            // Issuer information
            oss << "\"CERTIFICATE.ISSUER\":\"" << escapeJsonString(cert.getIssuerString()) << "\",";
            oss << "\"CERTIFICATE.ISSUER_COUNTRY\":\"" << escapeJsonString(cert.issuer_country) << "\",";
            oss << "\"CERTIFICATE.ISSUER_ORGANIZATION\":\"" << escapeJsonString(cert.issuer_organization) << "\",";
            oss << "\"CERTIFICATE.ISSUER_ORGANIZATIONAL_UNIT\":\"" << escapeJsonString(cert.issuer_organizational_unit) << "\",";
            oss << "\"CERTIFICATE.ISSUER_COMMON_NAME\":\"" << escapeJsonString(cert.issuer_common_name) << "\",";
            oss << "\"CERTIFICATE.ISSUER_STATE\":\"" << escapeJsonString(cert.issuer_state) << "\",";
            oss << "\"CERTIFICATE.ISSUER_LOCALITY\":\"" << escapeJsonString(cert.issuer_locality) << "\",";
            oss << "\"CERTIFICATE.ISSUER_EMAIL\":\"" << escapeJsonString(cert.issuer_email) << "\",";
            
            // Validity period
            oss << "\"CERTIFICATE.NOT_VALID_BEFORE\":" << cert.not_valid_before << ",";
            oss << "\"CERTIFICATE.NOT_VALID_AFTER\":" << cert.not_valid_after << ",";
            oss << "\"CERTIFICATE.NOT_VALID_BEFORE_STR\":\"" << escapeJsonString(cert.not_valid_before_str) << "\",";
            oss << "\"CERTIFICATE.NOT_VALID_AFTER_STR\":\"" << escapeJsonString(cert.not_valid_after_str) << "\",";
            
            // Subject information
            oss << "\"CERTIFICATE.SUBJECT\":\"" << escapeJsonString(cert.getSubjectString()) << "\",";
            oss << "\"CERTIFICATE.SUBJECT_COUNTRY\":\"" << escapeJsonString(cert.subject_country) << "\",";
            oss << "\"CERTIFICATE.SUBJECT_ORGANIZATION\":\"" << escapeJsonString(cert.subject_organization) << "\",";
            oss << "\"CERTIFICATE.SUBJECT_ORGANIZATIONAL_UNIT\":\"" << escapeJsonString(cert.subject_organizational_unit) << "\",";
            oss << "\"CERTIFICATE.SUBJECT_COMMON_NAME\":\"" << escapeJsonString(cert.subject_common_name) << "\",";
            oss << "\"CERTIFICATE.SUBJECT_STATE\":\"" << escapeJsonString(cert.subject_state) << "\",";
            oss << "\"CERTIFICATE.SUBJECT_LOCALITY\":\"" << escapeJsonString(cert.subject_locality) << "\",";
            oss << "\"CERTIFICATE.SUBJECT_EMAIL\":\"" << escapeJsonString(cert.subject_email) << "\",";
            
            // Subject Public Key Info
            oss << "\"CERTIFICATE.KEY_ALGORITHM_OID\":\"" << escapeJsonString(cert.key_algorithm_oid) << "\",";
            oss << "\"CERTIFICATE.KEY_ALGORITHM_NAME\":\"" << escapeJsonString(cert.key_algorithm_name) << "\",";
            oss << "\"CERTIFICATE.KEY_TYPE\":\"" << escapeJsonString(cert.key_type) << "\",";
            oss << "\"CERTIFICATE.KEY_LENGTH\":" << cert.key_length << ",";
            oss << "\"CERTIFICATE.EXPONENT\":\"" << escapeJsonString(cert.exponent) << "\",";
            oss << "\"CERTIFICATE.PUBLIC_KEY_HEX\":\"" << escapeJsonString(cert.public_key_hex) << "\",";
            oss << "\"CERTIFICATE.PUBLIC_KEY_MODULUS\":\"" << escapeJsonString(cert.public_key_modulus) << "\",";
            oss << "\"CERTIFICATE.PUBLIC_KEY_EXPONENT\":\"" << escapeJsonString(cert.public_key_exponent) << "\",";
            
            // Extensions
            oss << "\"CERTIFICATE.HAS_EXTENSIONS\":" << (cert.has_extensions ? "true" : "false") << ",";
            
            // Subject Alternative Name (SAN) extension
            if (!cert.dns_names.empty()) {
                oss << "\"SAN.DNS\":[";
                for (size_t i = 0; i < cert.dns_names.size(); ++i) {
                    if (i > 0) oss << ",";
                    oss << "\"" << escapeJsonString(cert.dns_names[i]) << "\"";
                }
                oss << "],";
            } else {
                oss << "\"SAN.DNS\":[],";
            }
            
            if (!cert.email_addresses.empty()) {
                oss << "\"SAN.EMAIL\":[";
                for (size_t i = 0; i < cert.email_addresses.size(); ++i) {
                    if (i > 0) oss << ",";
                    oss << "\"" << escapeJsonString(cert.email_addresses[i]) << "\"";
                }
                oss << "],";
            } else {
                oss << "\"SAN.EMAIL\":[],";
            }
            
            if (!cert.ip_addresses.empty()) {
                oss << "\"SAN.IP\":[";
                for (size_t i = 0; i < cert.ip_addresses.size(); ++i) {
                    if (i > 0) oss << ",";
                    oss << "\"" << escapeJsonString(cert.ip_addresses[i]) << "\"";
                }
                oss << "],";
            } else {
                oss << "\"SAN.IP\":[],";
            }
            
            if (!cert.uris.empty()) {
                oss << "\"SAN.URI\":[";
                for (size_t i = 0; i < cert.uris.size(); ++i) {
                    if (i > 0) oss << ",";
                    oss << "\"" << escapeJsonString(cert.uris[i]) << "\"";
                }
                oss << "],";
            } else {
                oss << "\"SAN.URI\":[],";
            }
            
            // Key Usage extension
            oss << "\"CERTIFICATE.KEY_USAGE_DIGITAL_SIGNATURE\":" << (cert.key_usage_digital_signature ? "true" : "false") << ",";
            oss << "\"CERTIFICATE.KEY_USAGE_NON_REPUDIATION\":" << (cert.key_usage_non_repudiation ? "true" : "false") << ",";
            oss << "\"CERTIFICATE.KEY_USAGE_KEY_ENCIPHERMENT\":" << (cert.key_usage_key_encipherment ? "true" : "false") << ",";
            oss << "\"CERTIFICATE.KEY_USAGE_DATA_ENCIPHERMENT\":" << (cert.key_usage_data_encipherment ? "true" : "false") << ",";
            oss << "\"CERTIFICATE.KEY_USAGE_KEY_AGREEMENT\":" << (cert.key_usage_key_agreement ? "true" : "false") << ",";
            oss << "\"CERTIFICATE.KEY_USAGE_KEY_CERT_SIGN\":" << (cert.key_usage_key_cert_sign ? "true" : "false") << ",";
            oss << "\"CERTIFICATE.KEY_USAGE_CRL_SIGN\":" << (cert.key_usage_crl_sign ? "true" : "false") << ",";
            oss << "\"CERTIFICATE.KEY_USAGE_ENCIPHER_ONLY\":" << (cert.key_usage_encipher_only ? "true" : "false") << ",";
            oss << "\"CERTIFICATE.KEY_USAGE_DECIPHER_ONLY\":" << (cert.key_usage_decipher_only ? "true" : "false") << ",";
            
            // Extended Key Usage extension
            if (!cert.extended_key_usage.empty()) {
                oss << "\"CERTIFICATE.EXTENDED_KEY_USAGE\":[";
                for (size_t i = 0; i < cert.extended_key_usage.size(); ++i) {
                    if (i > 0) oss << ",";
                    oss << "\"" << escapeJsonString(cert.extended_key_usage[i]) << "\"";
                }
                oss << "],";
            } else {
                oss << "\"CERTIFICATE.EXTENDED_KEY_USAGE\":[],";
            }
            
            oss << "\"CERTIFICATE.EXT_KEY_USAGE_SERVER_AUTH\":" << (cert.ext_key_usage_server_auth ? "true" : "false") << ",";
            oss << "\"CERTIFICATE.EXT_KEY_USAGE_CLIENT_AUTH\":" << (cert.ext_key_usage_client_auth ? "true" : "false") << ",";
            oss << "\"CERTIFICATE.EXT_KEY_USAGE_CODE_SIGNING\":" << (cert.ext_key_usage_code_signing ? "true" : "false") << ",";
            oss << "\"CERTIFICATE.EXT_KEY_USAGE_EMAIL_PROTECTION\":" << (cert.ext_key_usage_email_protection ? "true" : "false") << ",";
            oss << "\"CERTIFICATE.EXT_KEY_USAGE_TIME_STAMPING\":" << (cert.ext_key_usage_time_stamping ? "true" : "false") << ",";
            oss << "\"CERTIFICATE.EXT_KEY_USAGE_OCSP_SIGNING\":" << (cert.ext_key_usage_ocsp_signing ? "true" : "false") << ",";
            
            // Basic Constraints extension
            oss << "\"BASIC_CONSTRAINTS.CA\":" << (cert.is_ca ? "true" : "false") << ",";
            oss << "\"BASIC_CONSTRAINTS.PATH_LENGTH_CONSTRAINT\":" << cert.path_length_constraint << ",";
            
            // Authority Key Identifier extension
            oss << "\"CERTIFICATE.AUTHORITY_KEY_ID\":\"" << escapeJsonString(cert.authority_key_id) << "\",";
            oss << "\"CERTIFICATE.AUTHORITY_CERT_ISSUER\":\"" << escapeJsonString(cert.authority_cert_issuer) << "\",";
            oss << "\"CERTIFICATE.AUTHORITY_CERT_SERIAL\":\"" << escapeJsonString(cert.authority_cert_serial) << "\",";
            
            // Subject Key Identifier extension
            oss << "\"CERTIFICATE.SUBJECT_KEY_ID\":\"" << escapeJsonString(cert.subject_key_id) << "\",";
            
            // CRL Distribution Points extension
            if (!cert.crl_distribution_points.empty()) {
                oss << "\"CERTIFICATE.CRL_DISTRIBUTION_POINTS\":[";
                for (size_t i = 0; i < cert.crl_distribution_points.size(); ++i) {
                    if (i > 0) oss << ",";
                    oss << "\"" << escapeJsonString(cert.crl_distribution_points[i]) << "\"";
                }
                oss << "],";
            } else {
                oss << "\"CERTIFICATE.CRL_DISTRIBUTION_POINTS\":[],";
            }
            
            // Authority Information Access extension
            if (!cert.ocsp_responders.empty()) {
                oss << "\"CERTIFICATE.OCSP_RESPONDERS\":[";
                for (size_t i = 0; i < cert.ocsp_responders.size(); ++i) {
                    if (i > 0) oss << ",";
                    oss << "\"" << escapeJsonString(cert.ocsp_responders[i]) << "\"";
                }
                oss << "],";
            } else {
                oss << "\"CERTIFICATE.OCSP_RESPONDERS\":[],";
            }
            
            if (!cert.ca_issuers.empty()) {
                oss << "\"CERTIFICATE.CA_ISSUERS\":[";
                for (size_t i = 0; i < cert.ca_issuers.size(); ++i) {
                    if (i > 0) oss << ",";
                    oss << "\"" << escapeJsonString(cert.ca_issuers[i]) << "\"";
                }
                oss << "],";
            } else {
                oss << "\"CERTIFICATE.CA_ISSUERS\":[],";
            }
            
            // Certificate Policies extension
            if (!cert.certificate_policies.empty()) {
                oss << "\"CERTIFICATE.CERTIFICATE_POLICIES\":[";
                for (size_t i = 0; i < cert.certificate_policies.size(); ++i) {
                    if (i > 0) oss << ",";
                    oss << "\"" << escapeJsonString(cert.certificate_policies[i]) << "\"";
                }
                oss << "],";
            } else {
                oss << "\"CERTIFICATE.CERTIFICATE_POLICIES\":[],";
            }
            
            // Certificate fingerprinting
            oss << "\"CERTIFICATE.FINGERPRINT_SHA1\":\"" << escapeJsonString(cert.fingerprint_sha1) << "\",";
            oss << "\"CERTIFICATE.FINGERPRINT_SHA256\":\"" << escapeJsonString(cert.fingerprint_sha256) << "\",";
            oss << "\"CERTIFICATE.FINGERPRINT_MD5\":\"" << escapeJsonString(cert.fingerprint_md5) << "\",";
            
            // Certificate validation
            oss << "\"CERTIFICATE.IS_SELF_SIGNED\":" << (cert.is_self_signed ? "true" : "false") << ",";
            oss << "\"CERTIFICATE.IS_VALID\":" << (cert.is_valid ? "true" : "false") << ",";
            oss << "\"CERTIFICATE.VALIDATION_ERROR\":\"" << escapeJsonString(cert.validation_error) << "\",";
            
            // Raw ASN.1 data
            oss << "\"CERTIFICATE.ASN1_DER_HEX\":\"" << escapeJsonString(cert.asn1_der_hex) << "\",";
        }
        
        // Alert information (only for alert layer)
        if (metadata.ssl.is_alert_layer) {
            oss << "\"SSL_ALERT_LEVEL\":" << static_cast<int>(metadata.ssl.alert_data.alert_level) << ",";
            oss << "\"SSL_ALERT_DESCRIPTION\":" << static_cast<int>(metadata.ssl.alert_data.alert_description) << ",";
        }
        
        // Change cipher spec (only for change cipher spec layer)
        if (metadata.ssl.is_change_cipher_spec_layer) {
            oss << "\"SSL_IS_CHANGE_CIPHER_SPEC\":" << (metadata.ssl.change_cipher_spec_data.is_change_cipher_spec ? "true" : "false") << ",";
        }
        
        // Application data (only for application data layer)
        if (metadata.ssl.is_application_data_layer) {
            oss << "\"SSL_IS_APPLICATION_DATA\":true,";
            oss << "\"SSL_APPLICATION_DATA_LENGTH\":" << metadata.ssl.application_data_info.application_data_length << ",";
            oss << "\"SSL_IS_ENCRYPTED\":" << (metadata.ssl.application_data_info.is_encrypted ? "true" : "false") << ",";
        }
        
        // SSL state
        if (!metadata.ssl.ssl_state.empty()) {
            oss << "\"SSL_STATE\":\"" << escapeJsonString(metadata.ssl.ssl_state) << "\",";
        } else {
            oss << "\"SSL_STATE\":\"\",";
        }
    }
    
    // SSH metadata (only output for SSH packets)
    if (metadata.has_ssh) {
        oss << "\"HAS_SSH\":true,";
        oss << "\"SSH_MESSAGE_TYPE\":\"" << escapeJsonString(metadata.ssh.message_type) << "\",";
        
        if (metadata.ssh.is_identification) {
            oss << "\"SSH_IDENTIFICATION_STRING\":\"" << escapeJsonString(metadata.ssh.identification_string) << "\",";
            oss << "\"SSH_SOFTWARE_VERSION\":\"" << escapeJsonString(metadata.ssh.software_version) << "\",";
            oss << "\"SSH_PROTOCOL_VERSION\":\"" << escapeJsonString(metadata.ssh.protocol_version) << "\",";
        } else {
            oss << "\"SSH_IDENTIFICATION_STRING\":\"\",";
            oss << "\"SSH_SOFTWARE_VERSION\":\"\",";
            oss << "\"SSH_PROTOCOL_VERSION\":\"\",";
        }
        
        if (metadata.ssh.is_handshake) {
            oss << "\"SSH_HANDSHAKE_MESSAGE_TYPE\":" << static_cast<int>(metadata.ssh.handshake_message_type) << ",";
            oss << "\"SSH_HANDSHAKE_TYPE_STR\":\"" << escapeJsonString(metadata.ssh.handshake_type_str) << "\",";
            oss << "\"SSH_PACKET_LENGTH\":" << metadata.ssh.packet_length << ",";
            oss << "\"SSH_PADDING_LENGTH\":" << metadata.ssh.padding_length << ",";
            oss << "\"SSH_MESSAGE_CONTENT_LENGTH\":" << metadata.ssh.message_content_length << ",";
        } else {
            oss << "\"SSH_HANDSHAKE_MESSAGE_TYPE\":0,";
            oss << "\"SSH_HANDSHAKE_TYPE_STR\":\"\",";
            oss << "\"SSH_PACKET_LENGTH\":0,";
            oss << "\"SSH_PADDING_LENGTH\":0,";
            oss << "\"SSH_MESSAGE_CONTENT_LENGTH\":0,";
        }
        
        if (metadata.ssh.is_key_exchange) {
            oss << "\"SSH_COOKIE_HEX\":\"" << escapeJsonString(metadata.ssh.cookie_hex) << "\",";
            oss << "\"SSH_KEY_EXCHANGE_ALGORITHMS\":\"" << escapeJsonString(metadata.ssh.key_exchange_algorithms) << "\",";
            oss << "\"SSH_SERVER_HOST_KEY_ALGORITHMS\":\"" << escapeJsonString(metadata.ssh.server_host_key_algorithms) << "\",";
            oss << "\"SSH_ENCRYPTION_ALGORITHMS_CLIENT_TO_SERVER\":\"" << escapeJsonString(metadata.ssh.encryption_algorithms_client_to_server) << "\",";
            oss << "\"SSH_ENCRYPTION_ALGORITHMS_SERVER_TO_CLIENT\":\"" << escapeJsonString(metadata.ssh.encryption_algorithms_server_to_client) << "\",";
            oss << "\"SSH_MAC_ALGORITHMS_CLIENT_TO_SERVER\":\"" << escapeJsonString(metadata.ssh.mac_algorithms_client_to_server) << "\",";
            oss << "\"SSH_MAC_ALGORITHMS_SERVER_TO_CLIENT\":\"" << escapeJsonString(metadata.ssh.mac_algorithms_server_to_client) << "\",";
            oss << "\"SSH_COMPRESSION_ALGORITHMS_CLIENT_TO_SERVER\":\"" << escapeJsonString(metadata.ssh.compression_algorithms_client_to_server) << "\",";
            oss << "\"SSH_COMPRESSION_ALGORITHMS_SERVER_TO_CLIENT\":\"" << escapeJsonString(metadata.ssh.compression_algorithms_server_to_client) << "\",";
            oss << "\"SSH_LANGUAGES_CLIENT_TO_SERVER\":\"" << escapeJsonString(metadata.ssh.languages_client_to_server) << "\",";
            oss << "\"SSH_LANGUAGES_SERVER_TO_CLIENT\":\"" << escapeJsonString(metadata.ssh.languages_server_to_client) << "\",";
            oss << "\"SSH_FIRST_KEX_PACKET_FOLLOWS\":" << (metadata.ssh.first_kex_packet_follows ? "true" : "false") << ",";
        } else {
            oss << "\"SSH_COOKIE_HEX\":\"\",";
            oss << "\"SSH_KEY_EXCHANGE_ALGORITHMS\":\"\",";
            oss << "\"SSH_SERVER_HOST_KEY_ALGORITHMS\":\"\",";
            oss << "\"SSH_ENCRYPTION_ALGORITHMS_CLIENT_TO_SERVER\":\"\",";
            oss << "\"SSH_ENCRYPTION_ALGORITHMS_SERVER_TO_CLIENT\":\"\",";
            oss << "\"SSH_MAC_ALGORITHMS_CLIENT_TO_SERVER\":\"\",";
            oss << "\"SSH_MAC_ALGORITHMS_SERVER_TO_CLIENT\":\"\",";
            oss << "\"SSH_COMPRESSION_ALGORITHMS_CLIENT_TO_SERVER\":\"\",";
            oss << "\"SSH_COMPRESSION_ALGORITHMS_SERVER_TO_CLIENT\":\"\",";
            oss << "\"SSH_LANGUAGES_CLIENT_TO_SERVER\":\"\",";
            oss << "\"SSH_LANGUAGES_SERVER_TO_CLIENT\":\"\",";
            oss << "\"SSH_FIRST_KEX_PACKET_FOLLOWS\":false,";
        }
        
        oss << "\"SSH_TOTAL_MESSAGE_LENGTH\":" << metadata.ssh.total_message_length << ",";
        if (!metadata.ssh.message_preview.empty()) {
            oss << "\"SSH_MESSAGE_PREVIEW\":\"" << escapeJsonString(metadata.ssh.message_preview) << "\",";
        } else {
            oss << "\"SSH_MESSAGE_PREVIEW\":\"\",";
        }
        oss << "\"SSH_SESSION_INFO\":\"" << escapeJsonString(metadata.ssh.session_info) << "\",";
    }
    
    // Telnet metadata (only output for Telnet packets)
    if (metadata.has_telnet) {
        oss << "\"HAS_TELNET\":true,";
        oss << "\"TELNET_TYPE\":\"" << escapeJsonString(metadata.telnet.type) << "\",";
        oss << "\"TELNET_SESSION_TYPE\":\"" << escapeJsonString(metadata.telnet.session_type) << "\",";
        oss << "\"TELNET_IS_CONTROL\":" << (metadata.telnet.is_control ? "true" : "false") << ",";
        oss << "\"TELNET_IS_TEXT\":" << (metadata.telnet.is_text ? "true" : "false") << ",";
        oss << "\"TELNET_COMMAND_COUNT\":" << metadata.telnet.command_count << ",";
        oss << "\"TELNET_IAC_SEQUENCES\":" << metadata.telnet.iac_sequences << ",";
        oss << "\"TELNET_TEXT_SEQUENCES\":" << metadata.telnet.text_sequences << ",";
        oss << "\"TELNET_TOTAL_DATA_LENGTH\":" << metadata.telnet.total_data_length << ",";
        
        if (metadata.telnet.hasCommands()) {
            oss << "\"TELNET_COMMAND_SUMMARY\":\"" << escapeJsonString(metadata.telnet.getCommandSummary()) << "\",";
        } else {
            oss << "\"TELNET_COMMAND_SUMMARY\":\"No commands\",";
        }
        
        if (metadata.telnet.hasText()) {
            oss << "\"TELNET_TEXT_LENGTH\":" << metadata.telnet.text_length << ",";
            oss << "\"TELNET_TEXT_PREVIEW\":\"" << escapeJsonString(metadata.telnet.getTextPreview()) << "\",";
            if (!metadata.telnet.filtered_text.empty()) {
                oss << "\"TELNET_FILTERED_TEXT\":\"" << escapeJsonString(metadata.telnet.filtered_text) << "\",";
            } else {
                oss << "\"TELNET_FILTERED_TEXT\":\"\",";
            }
        } else {
            oss << "\"TELNET_TEXT_LENGTH\":0,";
            oss << "\"TELNET_TEXT_PREVIEW\":\"\",";
            oss << "\"TELNET_FILTERED_TEXT\":\"\",";
        }
    }
    
    // BGP metadata (only output for BGP packets)
    if (metadata.has_bgp) {
        oss << "\"HAS_BGP\":true,";
        oss << "\"BGP_MARKER\":\"" << escapeJsonString(metadata.bgp.marker) << "\",";
        oss << "\"BGP_LENGTH\":" << metadata.bgp.length << ",";
        oss << "\"BGP_TYPE\":" << static_cast<int>(metadata.bgp.type) << ",";
        oss << "\"BGP_TYPE_STR\":\"" << escapeJsonString(metadata.bgp.type_str) << "\",";
        
        // BGP OPEN message fields
        if (metadata.bgp.type == BGPMetadata::OPEN) {
            oss << "\"BGP_VERSION\":" << static_cast<int>(metadata.bgp.version) << ",";
            oss << "\"BGP_MY_AS\":" << metadata.bgp.my_as << ",";
            oss << "\"BGP_HOLD_TIME\":" << metadata.bgp.hold_time << ",";
            oss << "\"BGP_IDENTIFIER\":\"" << escapeJsonString(metadata.bgp.bgp_identifier) << "\",";
            
            // Optional parameters
            if (!metadata.bgp.optional_parameters.empty()) {
                oss << "\"BGP_OPTIONAL_PARAMETERS\":[";
                for (size_t i = 0; i < metadata.bgp.optional_parameters.size(); i++) {
                    if (i > 0) oss << ",";
                    oss << "\"" << escapeJsonString(metadata.bgp.optional_parameters[i]) << "\"";
                }
                oss << "],";
            } else {
                oss << "\"BGP_OPTIONAL_PARAMETERS\":[],";
            }
        }
        
        // BGP UPDATE message fields
        if (metadata.bgp.type == BGPMetadata::UPDATE) {
            // Withdrawn routes
            if (!metadata.bgp.withdrawn_routes.empty()) {
                oss << "\"BGP_WITHDRAWN_ROUTES\":[";
                for (size_t i = 0; i < metadata.bgp.withdrawn_routes.size(); i++) {
                    if (i > 0) oss << ",";
                    oss << "\"" << escapeJsonString(metadata.bgp.withdrawn_routes[i]) << "\"";
                }
                oss << "],";
            } else {
                oss << "\"BGP_WITHDRAWN_ROUTES\":[],";
            }
            
            // Path attributes
            if (!metadata.bgp.path_attributes.empty()) {
                oss << "\"BGP_PATH_ATTRIBUTES\":[";
                for (size_t i = 0; i < metadata.bgp.path_attributes.size(); i++) {
                    if (i > 0) oss << ",";
                    oss << "\"" << escapeJsonString(metadata.bgp.path_attributes[i]) << "\"";
                }
                oss << "],";
            } else {
                oss << "\"BGP_PATH_ATTRIBUTES\":[],";
            }
            
            // Specific path attributes
            if (!metadata.bgp.origin.empty()) oss << "\"BGP_ORIGIN\":\"" << escapeJsonString(metadata.bgp.origin) << "\",";
            else oss << "\"BGP_ORIGIN\":\"\",";
            
            if (!metadata.bgp.as_path.empty()) oss << "\"BGP_AS_PATH\":\"" << escapeJsonString(metadata.bgp.as_path) << "\",";
            else oss << "\"BGP_AS_PATH\":\"\",";
            
            if (!metadata.bgp.next_hop.empty()) oss << "\"BGP_NEXT_HOP\":\"" << escapeJsonString(metadata.bgp.next_hop) << "\",";
            else oss << "\"BGP_NEXT_HOP\":\"\",";
            
            if (metadata.bgp.local_pref > 0) oss << "\"BGP_LOCAL_PREF\":" << metadata.bgp.local_pref << ",";
            else oss << "\"BGP_LOCAL_PREF\":0,";
            
            if (metadata.bgp.med > 0) oss << "\"BGP_MED\":" << metadata.bgp.med << ",";
            else oss << "\"BGP_MED\":0,";
            
            if (!metadata.bgp.community.empty()) oss << "\"BGP_COMMUNITY\":\"" << escapeJsonString(metadata.bgp.community) << "\",";
            else oss << "\"BGP_COMMUNITY\":\"\",";
            
            if (!metadata.bgp.mp_reach_nlri.empty()) oss << "\"BGP_MP_REACH_NLRI\":\"" << escapeJsonString(metadata.bgp.mp_reach_nlri) << "\",";
            else oss << "\"BGP_MP_REACH_NLRI\":\"\",";
            
            if (!metadata.bgp.mp_unreach_nlri.empty()) oss << "\"BGP_MP_UNREACH_NLRI\":\"" << escapeJsonString(metadata.bgp.mp_unreach_nlri) << "\",";
            else oss << "\"BGP_MP_UNREACH_NLRI\":\"\",";
            
            // NLRI
            if (!metadata.bgp.nlri.empty()) {
                oss << "\"BGP_NLRI\":[";
                for (size_t i = 0; i < metadata.bgp.nlri.size(); i++) {
                    if (i > 0) oss << ",";
                    oss << "\"" << escapeJsonString(metadata.bgp.nlri[i]) << "\"";
                }
                oss << "],";
            } else {
                oss << "\"BGP_NLRI\":[],";
            }
        }
        
        // BGP NOTIFICATION message fields
        if (metadata.bgp.type == BGPMetadata::NOTIFICATION) {
            oss << "\"BGP_ERROR_CODE\":" << static_cast<int>(metadata.bgp.error_code) << ",";
            oss << "\"BGP_ERROR_SUBCODE\":" << static_cast<int>(metadata.bgp.error_subcode) << ",";
            if (!metadata.bgp.error_data.empty()) oss << "\"BGP_ERROR_DATA\":\"" << escapeJsonString(metadata.bgp.error_data) << "\",";
            else oss << "\"BGP_ERROR_DATA\":\"\",";
        }
        
        // BGP ROUTE-REFRESH message fields
        if (metadata.bgp.type == BGPMetadata::ROUTE_REFRESH) {
            oss << "\"BGP_AFI\":" << metadata.bgp.afi << ",";
            oss << "\"BGP_SAFI\":" << static_cast<int>(metadata.bgp.safi) << ",";
            oss << "\"BGP_RESERVED\":" << static_cast<int>(metadata.bgp.reserved) << ",";
        }
    }
    // Note: BGP fields are only output when has_bgp = true
    
    oss << "\"PACKET_LENGTH\":" << metadata.packet_length << ",";
    oss << "\"PAYLOAD_LENGTH\":" << metadata.payload_length << ",";
    oss << "\"CONTROL_FIELD_SIZE\":" << (metadata.packet_length - metadata.payload_length);

    oss << "}";

    const std::string text = oss.str();
    std::ostream* out = nullptr;
    if (category == "ethernet" && ethernetLogFile.is_open()) out = &ethernetLogFile;
    else if (category == "wifi" && wifiLogFile.is_open()) out = &wifiLogFile;
    else if (category == "error" && errorLogFile.is_open()) out = &errorLogFile;

    if (out) {
        (*out) << text << std::endl;
    } else if (logFile.is_open()) {
        logFile << text << std::endl;
    } else {
        std::cout << text << std::endl;
    }
}

void LoggerManager::logConnFlow(const PacketMetadata& metadata) {
    // Process packet to connection tracker
    connectionTracker.processPacket(metadata);
}

void LoggerManager::flushCompletedConnections() {
    std::lock_guard<std::mutex> lock(logMutex);
    
    // Get completed connections
    std::vector<ConnectionStats> completed_connections = connectionTracker.getCompletedConnections();
    
    // Log each completed connection
    for (const auto& conn : completed_connections) {
        logConnFlowJSON(conn);
    }
}

void LoggerManager::flushCompletedConnectionsRealtime() {
    std::lock_guard<std::mutex> lock(logMutex);
    
    // Get and remove completed connections from tracker
    std::vector<ConnectionStats> completed_connections = connectionTracker.getAndRemoveCompletedConnections();
    
    // Log each completed connection
    for (const auto& conn : completed_connections) {
        logConnFlowJSON(conn);
    }
}

void LoggerManager::forceFlushAllConnections() {
    std::lock_guard<std::mutex> lock(logMutex);
    
    // Force cleanup all connections with timeout 0 (immediately flush all)
    connectionTracker.cleanupTimeoutConnections(0.0);
    
    // Get all completed connections and log them
    std::vector<ConnectionStats> completed_connections = connectionTracker.getAndRemoveCompletedConnections();
    
    // Log each completed connection
    for (const auto& conn : completed_connections) {
        logConnFlowJSON(conn);
    }
}

void LoggerManager::logConnFlowJSON(const ConnectionStats& conn) {
    std::ostringstream oss;
    oss << "{";
    
    // Basic connection information - following Zeek conn.log format
    oss << "\"ts\":" << std::fixed << std::setprecision(6) << conn.start_time << ",";
    oss << "\"uid\":\"" << conn.uid << "\",";
    oss << "\"up_ip\":\"" << conn.upstream_h << "\",";
    oss << "\"up_port\":" << conn.upstream_p << ",";
    oss << "\"down_ip\":\"" << conn.downstream_h << "\",";
    oss << "\"down_port\":" << conn.downstream_p << ",";
    oss << "\"proto\":\"" << conn.proto << "\",";
    
    // Service type
    if (!conn.service.empty()) {
        oss << "\"service\":\"" << conn.service << "\",";
    } else {
        oss << "\"service\":\"-\",";
    }
    
    // Connection statistics
    oss << "\"duration\":" << std::fixed << std::setprecision(6) << conn.duration << ",";
    oss << "\"up_bytes\":" << conn.upstream_bytes << ",";
    oss << "\"down_bytes\":" << conn.downstream_bytes << ",";
    oss << "\"conn_state\":\"" << ConnectionTracker::connectionStateToString(conn.conn_state) << "\",";
    oss << "\"missed_bytes\":" << conn.missed_bytes << ",";
    
    // Connection history
    if (!conn.history.history.empty()) {
        oss << "\"history\":\"" << conn.history.history << "\",";
    } else {
        oss << "\"history\":\"-\",";
    }
    
    // Packet statistics
    oss << "\"up_pkts\":" << conn.upstream_pkts << ",";
    oss << "\"up_ip_bytes\":" << conn.upstream_ip_bytes << ",";
    oss << "\"down_pkts\":" << conn.downstream_pkts << ",";
    oss << "\"down_ip_bytes\":" << conn.downstream_ip_bytes << ",";
    oss << "\"ip_proto\":" << static_cast<int>(conn.ip_proto) << ",";
    
    // Upstream packet size statistics
    oss << "\"up_pkt_count\":" << conn.upstream_stats.packet_count << ",";
    oss << "\"up_total_bytes\":" << conn.upstream_stats.total_bytes << ",";
    oss << "\"up_min_size\":" << conn.upstream_stats.min_size << ",";
    oss << "\"up_max_size\":" << conn.upstream_stats.max_size << ",";
    oss << "\"up_avg_size\":" << std::fixed << std::setprecision(2) << conn.upstream_stats.avg_size << ",";
    oss << "\"up_median_size\":" << std::fixed << std::setprecision(2) << conn.upstream_stats.median_size << ",";
    oss << "\"up_first_quartile\":" << std::fixed << std::setprecision(2) << conn.upstream_stats.first_quartile << ",";
    oss << "\"up_third_quartile\":" << std::fixed << std::setprecision(2) << conn.upstream_stats.third_quartile << ",";
    oss << "\"up_size_skewness\":" << std::fixed << std::setprecision(4) << conn.upstream_stats.size_skewness << ",";
    oss << "\"up_size_kurtosis\":" << std::fixed << std::setprecision(4) << conn.upstream_stats.size_kurtosis << ",";
    
    // Upstream inter-arrival time statistics
    oss << "\"up_min_iat\":" << std::fixed << std::setprecision(6) << conn.upstream_iat_stats.min_iat << ",";
    oss << "\"up_max_iat\":" << std::fixed << std::setprecision(6) << conn.upstream_iat_stats.max_iat << ",";
    oss << "\"up_avg_iat\":" << std::fixed << std::setprecision(6) << conn.upstream_iat_stats.avg_iat << ",";
    oss << "\"up_median_iat\":" << std::fixed << std::setprecision(6) << conn.upstream_iat_stats.median_iat << ",";
    oss << "\"up_first_quartile_iat\":" << std::fixed << std::setprecision(6) << conn.upstream_iat_stats.first_quartile_iat << ",";
    oss << "\"up_third_quartile_iat\":" << std::fixed << std::setprecision(6) << conn.upstream_iat_stats.third_quartile_iat << ",";
    oss << "\"up_iat_skewness\":" << std::fixed << std::setprecision(6) << conn.upstream_iat_stats.iat_skewness << ",";
    oss << "\"up_iat_kurtosis\":" << std::fixed << std::setprecision(6) << conn.upstream_iat_stats.iat_kurtosis << ",";
    
    // Upstream FFT features (top 10 frequency components)
    oss << "\"up_iat_fft_features\":[";
    for (size_t i = 0; i < conn.upstream_iat_stats.iat_fft_top_ten_features.size(); ++i) {
        if (i > 0) oss << ",";
        oss << std::fixed << std::setprecision(6) << conn.upstream_iat_stats.iat_fft_top_ten_features[i];
    }
    oss << "],";
    
    // Downstream packet size statistics
    oss << "\"down_pkt_count\":" << conn.downstream_stats.packet_count << ",";
    oss << "\"down_total_bytes\":" << conn.downstream_stats.total_bytes << ",";
    oss << "\"down_min_size\":" << conn.downstream_stats.min_size << ",";
    oss << "\"down_max_size\":" << conn.downstream_stats.max_size << ",";
    oss << "\"down_avg_size\":" << std::fixed << std::setprecision(2) << conn.downstream_stats.avg_size << ",";
    oss << "\"down_median_size\":" << std::fixed << std::setprecision(2) << conn.downstream_stats.median_size << ",";
    oss << "\"down_first_quartile\":" << std::fixed << std::setprecision(2) << conn.downstream_stats.first_quartile << ",";
    oss << "\"down_third_quartile\":" << std::fixed << std::setprecision(2) << conn.downstream_stats.third_quartile << ",";
    oss << "\"down_size_skewness\":" << std::fixed << std::setprecision(4) << conn.downstream_stats.size_skewness << ",";
    oss << "\"down_size_kurtosis\":" << std::fixed << std::setprecision(4) << conn.downstream_stats.size_kurtosis << ",";
    
    // Downstream inter-arrival time statistics
    oss << "\"down_min_iat\":" << std::fixed << std::setprecision(6) << conn.downstream_iat_stats.min_iat << ",";
    oss << "\"down_max_iat\":" << std::fixed << std::setprecision(6) << conn.downstream_iat_stats.max_iat << ",";
    oss << "\"down_avg_iat\":" << std::fixed << std::setprecision(6) << conn.downstream_iat_stats.avg_iat << ",";
    oss << "\"down_median_iat\":" << std::fixed << std::setprecision(6) << conn.downstream_iat_stats.median_iat << ",";
    oss << "\"down_first_quartile_iat\":" << std::fixed << std::setprecision(6) << conn.downstream_iat_stats.first_quartile_iat << ",";
    oss << "\"down_third_quartile_iat\":" << std::fixed << std::setprecision(6) << conn.downstream_iat_stats.third_quartile_iat << ",";
    oss << "\"down_iat_skewness\":" << std::fixed << std::setprecision(6) << conn.downstream_iat_stats.iat_skewness << ",";
    oss << "\"down_iat_kurtosis\":" << std::fixed << std::setprecision(6) << conn.downstream_iat_stats.iat_kurtosis << ",";
    
    // Downstream FFT features (top 10 frequency components)
    oss << "\"down_iat_fft_features\":[";
    for (size_t i = 0; i < conn.downstream_iat_stats.iat_fft_top_ten_features.size(); ++i) {
        if (i > 0) oss << ",";
        oss << std::fixed << std::setprecision(6) << conn.downstream_iat_stats.iat_fft_top_ten_features[i];
    }
    oss << "],";
    
    // Upstream control field statistics
    oss << "\"up_control_pkt_count\":" << conn.upstream_control_stats.packet_count << ",";
    oss << "\"up_control_total_bytes\":" << conn.upstream_control_stats.total_control_bytes << ",";
    oss << "\"up_control_min_size\":" << conn.upstream_control_stats.min_control_size << ",";
    oss << "\"up_control_max_size\":" << conn.upstream_control_stats.max_control_size << ",";
    oss << "\"up_control_avg_size\":" << std::fixed << std::setprecision(2) << conn.upstream_control_stats.avg_control_size << ",";
    oss << "\"up_control_median_size\":" << std::fixed << std::setprecision(2) << conn.upstream_control_stats.median_control_size << ",";
    oss << "\"up_control_first_quartile\":" << std::fixed << std::setprecision(2) << conn.upstream_control_stats.first_quartile << ",";
    oss << "\"up_control_third_quartile\":" << std::fixed << std::setprecision(2) << conn.upstream_control_stats.third_quartile << ",";
    oss << "\"up_control_skewness\":" << std::fixed << std::setprecision(4) << conn.upstream_control_stats.control_skewness << ",";
    oss << "\"up_control_kurtosis\":" << std::fixed << std::setprecision(4) << conn.upstream_control_stats.control_kurtosis << ",";
    
    // Downstream control field statistics
    oss << "\"down_control_pkt_count\":" << conn.downstream_control_stats.packet_count << ",";
    oss << "\"down_control_total_bytes\":" << conn.downstream_control_stats.total_control_bytes << ",";
    oss << "\"down_control_min_size\":" << conn.downstream_control_stats.min_control_size << ",";
    oss << "\"down_control_max_size\":" << conn.downstream_control_stats.max_control_size << ",";
    oss << "\"down_control_avg_size\":" << std::fixed << std::setprecision(2) << conn.downstream_control_stats.avg_control_size << ",";
    oss << "\"down_control_median_size\":" << std::fixed << std::setprecision(2) << conn.downstream_control_stats.median_control_size << ",";
    oss << "\"down_control_first_quartile\":" << std::fixed << std::setprecision(2) << conn.downstream_control_stats.first_quartile << ",";
    oss << "\"down_control_third_quartile\":" << std::fixed << std::setprecision(2) << conn.downstream_control_stats.third_quartile << ",";
    oss << "\"down_control_skewness\":" << std::fixed << std::setprecision(4) << conn.downstream_control_stats.control_skewness << ",";
    oss << "\"down_control_kurtosis\":" << std::fixed << std::setprecision(4) << conn.downstream_control_stats.control_kurtosis << ",";
    
    // Upstream RTT statistics (client->server)
    oss << "\"up_rtt_samples\":" << conn.upstream_rtt_stats.rtt_count << ",";
    oss << "\"up_rtt_min\":" << std::fixed << std::setprecision(6) << conn.upstream_rtt_stats.min_rtt << ",";
    oss << "\"up_rtt_max\":" << std::fixed << std::setprecision(6) << conn.upstream_rtt_stats.max_rtt << ",";
    oss << "\"up_rtt_avg\":" << std::fixed << std::setprecision(6) << conn.upstream_rtt_stats.avg_rtt << ",";
    oss << "\"up_rtt_median\":" << std::fixed << std::setprecision(6) << conn.upstream_rtt_stats.median_rtt << ",";
    oss << "\"up_rtt_first_quartile\":" << std::fixed << std::setprecision(6) << conn.upstream_rtt_stats.first_quartile_rtt << ",";
    oss << "\"up_rtt_third_quartile\":" << std::fixed << std::setprecision(6) << conn.upstream_rtt_stats.third_quartile_rtt << ",";
    oss << "\"up_rtt_skewness\":" << std::fixed << std::setprecision(6) << conn.upstream_rtt_stats.rtt_skewness << ",";
    oss << "\"up_rtt_kurtosis\":" << std::fixed << std::setprecision(6) << conn.upstream_rtt_stats.rtt_kurtosis << ",";
    
    // Downstream RTT statistics (server->client)
    oss << "\"down_rtt_samples\":" << conn.downstream_rtt_stats.rtt_count << ",";
    oss << "\"down_rtt_min\":" << std::fixed << std::setprecision(6) << conn.downstream_rtt_stats.min_rtt << ",";
    oss << "\"down_rtt_max\":" << std::fixed << std::setprecision(6) << conn.downstream_rtt_stats.max_rtt << ",";
    oss << "\"down_rtt_avg\":" << std::fixed << std::setprecision(6) << conn.downstream_rtt_stats.avg_rtt << ",";
    oss << "\"down_rtt_median\":" << std::fixed << std::setprecision(6) << conn.downstream_rtt_stats.median_rtt << ",";
    oss << "\"down_rtt_first_quartile\":" << std::fixed << std::setprecision(6) << conn.downstream_rtt_stats.first_quartile_rtt << ",";
    oss << "\"down_rtt_third_quartile\":" << std::fixed << std::setprecision(6) << conn.downstream_rtt_stats.third_quartile_rtt << ",";
    oss << "\"down_rtt_skewness\":" << std::fixed << std::setprecision(6) << conn.downstream_rtt_stats.rtt_skewness << ",";
    oss << "\"down_rtt_kurtosis\":" << std::fixed << std::setprecision(6) << conn.downstream_rtt_stats.rtt_kurtosis << ",";
    
    // TCP features from updateTCPFeatures function
    // ACK packet statistics
    oss << "\"up_ack_pkts\":" << conn.up_ack_pkts << ",";
    oss << "\"down_ack_pkts\":" << conn.down_ack_pkts << ",";
    oss << "\"up_pure_acks\":" << conn.up_pure_acks << ",";
    oss << "\"down_pure_acks\":" << conn.down_pure_acks << ",";
    
    // SACK packet statistics
    oss << "\"up_sack_pkts\":" << conn.up_sack_pkts << ",";
    oss << "\"down_sack_pkts\":" << conn.down_sack_pkts << ",";
    oss << "\"up_dsack_pkts\":" << conn.up_dsack_pkts << ",";
    oss << "\"down_dsack_pkts\":" << conn.down_dsack_pkts << ",";
    oss << "\"up_max_sack_blks\":" << conn.up_max_sack_blks << ",";
    oss << "\"down_max_sack_blks\":" << conn.down_max_sack_blks << ",";
    
    // Data packet statistics
    oss << "\"up_actual_data_pkts\":" << conn.up_actual_data_pkts << ",";
    oss << "\"down_actual_data_pkts\":" << conn.down_actual_data_pkts << ",";
    oss << "\"up_actual_data_bytes\":" << conn.up_actual_data_bytes << ",";
    oss << "\"down_actual_data_bytes\":" << conn.down_actual_data_bytes << ",";
    oss << "\"up_unique_bytes\":" << conn.up_unique_bytes << ",";
    oss << "\"down_unique_bytes\":" << conn.down_unique_bytes << ",";
    
    // Retransmission statistics
    oss << "\"up_rexmt_data_pkts\":" << conn.up_rexmt_data_pkts << ",";
    oss << "\"down_rexmt_data_pkts\":" << conn.down_rexmt_data_pkts << ",";
    oss << "\"up_rexmt_data_bytes\":" << conn.up_rexmt_data_bytes << ",";
    oss << "\"down_rexmt_data_bytes\":" << conn.down_rexmt_data_bytes << ",";
    
    // Zero window probe statistics
    oss << "\"up_zwnd_probe_pkts\":" << conn.up_zwnd_probe_pkts << ",";
    oss << "\"down_zwnd_probe_pkts\":" << conn.down_zwnd_probe_pkts << ",";
    oss << "\"up_zwnd_probe_bytes\":" << conn.up_zwnd_probe_bytes << ",";
    oss << "\"down_zwnd_probe_bytes\":" << conn.down_zwnd_probe_bytes << ",";
    
    // PUSH bit statistics
    oss << "\"up_pushed_data_pkts\":" << conn.up_pushed_data_pkts << ",";
    oss << "\"down_pushed_data_pkts\":" << conn.down_pushed_data_pkts << ",";
    
    // SYN bit statistics
    oss << "\"up_syn_pkts\":" << conn.up_syn_pkts << ",";
    oss << "\"down_syn_pkts\":" << conn.down_syn_pkts << ",";
    
    // FIN bit statistics
    oss << "\"up_fin_pkts\":" << conn.up_fin_pkts << ",";
    oss << "\"down_fin_pkts\":" << conn.down_fin_pkts << ",";

    // Out-of-order packet statistics
    oss << "\"up_out_of_order_pkts\":" << conn.up_out_of_order_pkts << ",";
    oss << "\"down_out_of_order_pkts\":" << conn.down_out_of_order_pkts << ",";
    
    // Flow features for traffic analysis
    oss << "\"time_since_last_conn\":" << std::fixed << std::setprecision(6) << conn.time_since_last_conn << ",";
    oss << "\"bulk_trans_transitions\":" << conn.bulk_trans_transitions << ",";
    oss << "\"time_spent_in_bulk\":" << std::fixed << std::setprecision(6) << conn.time_spent_in_bulk << ",";
    
    // Overall flow FFT features (combining all packets chronologically)
    oss << "\"flow_iat_fft_features\":[";
    for (size_t i = 0; i < conn.flow_iat_fft_top_ten_features.size(); ++i) {
        if (i > 0) oss << ",";
        oss << std::fixed << std::setprecision(6) << conn.flow_iat_fft_top_ten_features[i];
    }
    oss << "]";
    
    oss << "}";
    
    // Write to connection log file
    if (connLogFile.is_open()) {
        connLogFile << oss.str() << std::endl;
    } else {
        std::cout << oss.str() << std::endl;
    }
}