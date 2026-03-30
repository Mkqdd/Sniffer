#include "parsers/TCPParser.h"
#include "parsers/HttpParser.h"
#include "parsers/FTPParser.h"
#include "parsers/SMTPParser.h"
#include "parsers/TelnetParser.h"
#include "parsers/SSHParser.h"
#include "parsers/BGPParser.h"
#include "parsers/SSLParser.h"
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/SSLLayer.h>
#include <iostream>

bool TCPParser::parse(pcpp::Packet& packet, PacketMetadata& metadata) {
    auto* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
    if (!tcpLayer) {
        return false;
    }

    // Set TCP presence flag and parse TCP information
    metadata.has_tcp = true;
    
    // Basic port information
    metadata.tcp.src_port = tcpLayer->getSrcPort();
    metadata.tcp.dst_port = tcpLayer->getDstPort();
    
    // Legacy fields for backward compatibility
    metadata.srcPort = metadata.tcp.src_port;
    metadata.dstPort = metadata.tcp.dst_port;
    metadata.protocol = "TCP";
    
    // TCP specific fields using PcapPlusPlus methods
    auto* tcpHeader = tcpLayer->getTcpHeader();
    metadata.tcp.seq = ntohl(tcpHeader->sequenceNumber);
    metadata.tcp.ack = ntohl(tcpHeader->ackNumber);
    metadata.tcp.window = ntohs(tcpHeader->windowSize);
    metadata.tcp.urgent_pointer = ntohs(tcpHeader->urgentPointer);
    
    // Parse TCP flags
    metadata.tcp.flags = 0;
    metadata.tcp.syn = tcpHeader->synFlag;
    metadata.tcp.ack_flag = tcpHeader->ackFlag;
    metadata.tcp.fin = tcpHeader->finFlag;
    metadata.tcp.rst = tcpHeader->rstFlag;
    metadata.tcp.psh = tcpHeader->pshFlag;
    metadata.tcp.urg = tcpHeader->urgFlag;
    
    // Set flags field for backward compatibility
    if (metadata.tcp.syn) metadata.tcp.flags |= 0x002;
    if (metadata.tcp.ack_flag) metadata.tcp.flags |= 0x010;
    if (metadata.tcp.fin) metadata.tcp.flags |= 0x001;
    if (metadata.tcp.rst) metadata.tcp.flags |= 0x004;
    if (metadata.tcp.psh) metadata.tcp.flags |= 0x008;
    if (metadata.tcp.urg) metadata.tcp.flags |= 0x020;
    
    // Packet size information
    metadata.packet_length = packet.getRawPacket()->getRawDataLen();
    metadata.payload_length = tcpLayer->getLayerPayloadSize();
    
    // Check for HTTP traffic on common ports (80, 8080, 443 for HTTPS)
    if (metadata.tcp.dst_port == 80 || metadata.tcp.dst_port == 8080 || 
        metadata.tcp.src_port == 80 || metadata.tcp.src_port == 8080) {
        // Try to parse HTTP
        if (HttpParser::parse(packet, metadata)) {
            // HTTP parsing successful, update protocol
            metadata.protocol = "TCP";
            metadata.application_protocol = "http";
        }
    }
    
    // Check for FTP traffic on ports 20 (data) and 21 (control)
    if (metadata.tcp.dst_port == 20 || metadata.tcp.dst_port == 21 || 
        metadata.tcp.src_port == 20 || metadata.tcp.src_port == 21) {
        // Try to parse FTP
        if (FTPParser::parse(packet, metadata)) {
            // FTP parsing successful, update protocol
            metadata.protocol = "TCP";
            metadata.application_protocol = "ftp";
        }
    }
    
    // Check for SMTP traffic on ports 25 (standard), 465 (SMTPS), and 587 (submission)
    if (metadata.tcp.dst_port == 25 || metadata.tcp.dst_port == 465 || metadata.tcp.dst_port == 587 ||
        metadata.tcp.src_port == 25 || metadata.tcp.src_port == 465 || metadata.tcp.src_port == 587) {
        // Try to parse SMTP
        if (SMTPParser::parse(packet, metadata)) {
            // SMTP parsing successful, update protocol
            metadata.protocol = "TCP";
            metadata.application_protocol = "smtp";
        }
    }
    
    // Check for Telnet traffic on port 23
    if (metadata.tcp.dst_port == 23 || metadata.tcp.src_port == 23) {
        // Try to parse Telnet
        if (TelnetParser::parse(packet, metadata)) {
            // Telnet parsing successful, update protocol
            metadata.protocol = "TCP";
            metadata.application_protocol = "telnet";
        }
    }
    
    // Check for SSH traffic on port 22
    auto *sshLayer = packet.getLayerOfType<pcpp::SSHLayer>();
    if (sshLayer) {
        // Try to parse SSH
        if (SSHParser::parse(packet, metadata)) {
            // SSH parsing successful, update protocol
            metadata.protocol = "TCP";
            metadata.application_protocol = "ssh";
        }
    }
    
    // Check for BGP traffic on port 179
    auto* bgpLayer = packet.getLayerOfType<pcpp::BgpLayer>();
    if (bgpLayer) {
        // Try to parse BGP
        if (BGPParser::parse(packet, metadata)) {
            // BGP parsing successful, update protocol
            metadata.protocol = "TCP";
            metadata.application_protocol = "bgp";
        }
    }

    // Check for SSL/TLS traffic
    if (isSSLTraffic(packet, metadata)) {
        // Try to parse SSL/TLS
        if (SSLParser::parse(packet, metadata)) {
            // SSL/TLS parsing successful, update protocol
            metadata.protocol = "TCP";
            metadata.application_protocol = "ssl";
        }
    }
    return true;
}

std::string TCPParser::flagsToString(uint16_t flags) {
    std::string result;
    if (flags & 0x001) result += "F";  // FIN
    if (flags & 0x002) result += "S";  // SYN
    if (flags & 0x004) result += "R";  // RST
    if (flags & 0x008) result += "P";  // PSH
    if (flags & 0x010) result += "A";  // ACK
    if (flags & 0x020) result += "U";  // URG
    return result.empty() ? "." : result;
}

bool TCPParser::isSSLTraffic(pcpp::Packet& packet, PacketMetadata& metadata) {
    // According to PcapPlusPlus documentation, SSLLayer is abstract and cannot be instantiated
    // We need to check for specific SSL layer types instead
    // auto* handshakeLayer = packet.getLayerOfType<pcpp::SSLHandshakeLayer>();
    // auto* changeCipherLayer = packet.getLayerOfType<pcpp::SSLChangeCipherSpecLayer>();
    // auto* alertLayer = packet.getLayerOfType<pcpp::SSLAlertLayer>();
    // auto* appDataLayer = packet.getLayerOfType<pcpp::SSLApplicationDataLayer>();
    
    // Check for SSL/TLS ports (common SSL/TLS ports)
    // bool isSSLPort = (metadata.tcp.dst_port == 443 || metadata.tcp.src_port == 443 ||  // HTTPS
    //                  metadata.tcp.dst_port == 465 || metadata.tcp.src_port == 465 ||  // SMTPS
    //                  metadata.tcp.dst_port == 636 || metadata.tcp.src_port == 636 ||  // LDAPS
    //                  metadata.tcp.dst_port == 993 || metadata.tcp.src_port == 993 ||  // IMAPS
    //                  metadata.tcp.dst_port == 995 || metadata.tcp.src_port == 995 ||  // POP3S
    //                  metadata.tcp.dst_port == 563 || metadata.tcp.src_port == 563 ||  // NNTPS
    //                  metadata.tcp.dst_port == 989 || metadata.tcp.src_port == 989 ||  // FTPS-data
    //                  metadata.tcp.dst_port == 990 || metadata.tcp.src_port == 990 ||  // FTPS-control
    //                  metadata.tcp.dst_port == 992 || metadata.tcp.src_port == 992 ||  // Telnet over TLS/SSL
    //                  metadata.tcp.dst_port == 994 || metadata.tcp.src_port == 994 ||  // IRCS
    //                  metadata.tcp.dst_port == 261 || metadata.tcp.src_port == 261 ||  // NSIIOPS
    //                  metadata.tcp.dst_port == 448 || metadata.tcp.src_port == 448 ||  // DDM-SSL
    //                  metadata.tcp.dst_port == 614 || metadata.tcp.src_port == 614);   // SSHELL
    
    // Check TCP payload for SSL/TLS content (fallback detection)
    bool isSSLPayload = false;
    auto* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
    if (tcpLayer && tcpLayer->getLayerPayloadSize() > 0) {
        const uint8_t* payload = tcpLayer->getLayerPayload();
        size_t payloadSize = tcpLayer->getLayerPayloadSize();
        
        // Check for SSL/TLS record header patterns
        if (payloadSize >= 5) {
            uint8_t contentType = payload[0];
            uint16_t version = (payload[1] << 8) | payload[2];
            uint16_t length = (payload[3] << 8) | payload[4];
            
            // SSL/TLS content types: 20=ChangeCipherSpec, 21=Alert, 22=Handshake, 23=ApplicationData
            if ((contentType >= 20 && contentType <= 23) &&
                (version == 0x0300 || version == 0x0301 || version == 0x0302 || 
                 version == 0x0303 || version == 0x0304) &&
                length <= payloadSize - 5) {
                isSSLPayload = true;
            }
        }
    }
    
    return isSSLPayload;
}