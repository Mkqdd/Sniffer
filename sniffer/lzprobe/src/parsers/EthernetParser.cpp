#include "parsers/EthernetParser.h"
#include "parsers/VLANParser.h"
#include "parsers/GREParser.h"
#include "parsers/IPv4Parser.h"
#include "parsers/IPv6Parser.h"
#include "parsers/TCPParser.h"
#include "parsers/UDPParser.h"
#include "parsers/ARPParser.h"
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/VlanLayer.h>
#include <pcapplusplus/GreLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>
#include <netinet/in.h>

bool EthernetParser::parse(pcpp::Packet& packet, PacketMetadata& metadata) {
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
            {
                // Parse IPv4 layer
                if (IPv4Parser::parse(packet, metadata)) {
                    // Parse transport layer
                    if (packet.isPacketOfType(pcpp::TCP)) {
                        TCPParser::parse(packet, metadata);
                    } else if (packet.isPacketOfType(pcpp::UDP)) {
                        UDPParser::parse(packet, metadata);
                    }
                }
            }
            break;

        case 0x86DD: // IPv6
            {
                // Parse IPv6 layer
                if (IPv6Parser::parse(packet, metadata)) {
                    // Parse transport layer
                    if (packet.isPacketOfType(pcpp::TCP)) {
                        TCPParser::parse(packet, metadata);
                    } else if (packet.isPacketOfType(pcpp::UDP)) {
                        UDPParser::parse(packet, metadata);
                    }
                }
            }
            break;

        case 0x8100: // VLAN (IEEE 802.1Q)
        case 0x88A8: // VLAN (IEEE 802.1ad)
            {
                // Parse VLAN layer
                if (VLANParser::parse(packet, metadata)) {
                    // After VLAN parsing, check the inner EtherType
                    auto* vlanLayer = packet.getLayerOfType<pcpp::VlanLayer>();
                    if (vlanLayer) {
                        uint16_t innerEtherType = ntohs(vlanLayer->getVlanHeader()->etherType);
                        
                        // Recursively parse the inner protocol
                        switch (innerEtherType) {
                            case 0x0800: // IPv4
                                if (IPv4Parser::parse(packet, metadata)) {
                                    if (packet.isPacketOfType(pcpp::TCP)) {
                                        TCPParser::parse(packet, metadata);
                                    } else if (packet.isPacketOfType(pcpp::UDP)) {
                                        UDPParser::parse(packet, metadata);
                                    }
                                }
                                break;
                                
                            case 0x86DD: // IPv6
                                if (IPv6Parser::parse(packet, metadata)) {
                                    if (packet.isPacketOfType(pcpp::TCP)) {
                                        TCPParser::parse(packet, metadata);
                                    } else if (packet.isPacketOfType(pcpp::UDP)) {
                                        UDPParser::parse(packet, metadata);
                                    }
                                }
                                break;
                                
                            default:
                                metadata.protocol = "VLAN/Unknown";
                                break;
                        }
                    }
                }
            }
            break;

        case 0x0806: // ARP
            if (ARPParser::parse(packet, metadata)) {
                metadata.protocol = "ARP";
            }
            break;

        case 0x8035: // RARP
            metadata.protocol = "RARP";
            break;

        case 0x6558: // GRE over Ethernet
            {
                // Parse GRE layer directly over Ethernet
                if (GREParser::parse(packet, metadata)) {
                    metadata.protocol = "GRE";
                }
            }
            break;

        default:
            metadata.protocol = "Unknown";
            break;
    }

    // Set packet length information
    metadata.packet_length = packet.getRawPacket()->getRawDataLen();
    
    return true;
}