#include "PacketDispatcher.h"
#include "parsers/TCPParser.h"
#include "parsers/UDPParser.h"
#include "parsers/EthernetParser.h"
#include "parsers/VLANParser.h"
#include "parsers/GREParser.h"
#include "parsers/IPv4Parser.h"
#include "parsers/IPv6Parser.h"
#include "parsers/WiFiParser.h"
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>
#include <pcapplusplus/VlanLayer.h>
#include <pcapplusplus/GreLayer.h>
#include <iostream>

PacketDispatcher::PacketDispatcher(LoggerManager &logger)
    : m_logger(logger)
{}

void PacketDispatcher::dispatch(pcpp::Packet &packet, double timestamp)
{
    PacketMetadata metadata;
    metadata.timestamp = timestamp;
    metadata.protocol = "Unknown";  // Initialize protocol field
    metadata.srcIP = "";            // Initialize srcIP field
    metadata.dstIP = "";            // Initialize dstIP field
    
    // Try WiFi (802.11) first
    if (WiFiParser::parse(packet, metadata)) {
        m_logger.logConn(metadata, "wifi");
        return;
    }

    // Parse the entire packet stack starting from Ethernet layer
    // This will handle all protocol layers including VLAN and GRE
    if (EthernetParser::parse(packet, metadata)) {
        // Log the parsed packet
        m_logger.logConn(metadata, "ethernet");
        
        // Process flow feature statistics (only for TCP/UDP/ICMP connections)
        if (metadata.protocol == "TCP" || metadata.protocol == "UDP" || metadata.protocol == "ICMP") {
            m_logger.logConnFlow(metadata);
            // Flush completed connections in real-time
            m_logger.flushCompletedConnectionsRealtime();
        }
    } else {
        // Handle parsing failure
        metadata.protocol = "ParseError";
        metadata.packet_length = packet.getRawPacket()->getRawDataLen();
        m_logger.logConn(metadata, "error");
    }
}