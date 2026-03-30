#include "parsers/MPLSParser.h"
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/MplsLayer.h>
#include <arpa/inet.h>
#include <cstring>

bool MPLSParser::parse(pcpp::Packet& packet, PacketMetadata& metadata) {
    // check ethernet layer
    auto* ethLayer = packet.getLayerOfType<pcpp::EthLayer>();
    if (!ethLayer) {
        return false;
    }
    
    uint16_t etherType = ntohs(ethLayer->getEthHeader()->etherType);
    if (etherType != 0x8847 && etherType != 0x8848) {
        return false;
    }
    
    // set MPLS metadata
    metadata.has_mpls = true;
    metadata.mpls.ethertype = etherType;
    metadata.mpls.unicast = (etherType == 0x8847);
    metadata.protocol = metadata.mpls.unicast ? "MPLS/Unicast" : "MPLS/Multicast";
    
    // get raw data for manual parsing
    const uint8_t* packetData = packet.getRawPacket()->getRawData();
    size_t packetLen = packet.getRawPacket()->getRawDataLen();
    
    // calculate MPLS data start position (after ethernet header 14 bytes)
    size_t mplsOffset = 14;
    
    // check if there is a VLAN tag
    if (metadata.has_vlan) {
        mplsOffset += 4; // VLAN tag 4 bytes
    }
    
    if (packetLen <= mplsOffset) {
        return false;
    }
    
    // parse MPLS label stack
    size_t consumedBytes = parseLabelStack(packetData, packetLen, mplsOffset, metadata);
    if (consumedBytes == 0) {
        return false;
    }
    
    // calculate payload data position
    size_t payloadOffset = mplsOffset + consumedBytes;
    if (payloadOffset < packetLen) {
        // infer payload protocol type
        metadata.mpls.payload_protocol = guessPayloadProtocol(
            packetData + payloadOffset, 
            packetLen - payloadOffset
        );
        
        // update protocol description
        switch (metadata.mpls.payload_protocol) {
            case 0x0800:
                metadata.protocol = metadata.mpls.unicast ? "MPLS/Unicast/IPv4" : "MPLS/Multicast/IPv4";
                break;
            case 0x86DD:
                metadata.protocol = metadata.mpls.unicast ? "MPLS/Unicast/IPv6" : "MPLS/Multicast/IPv6";
                break;
            default:
                // keep original protocol description
                break;
        }
    }
    
    // set packet length information
    metadata.packet_length = packet.getRawPacket()->getRawDataLen();
    metadata.payload_length = packetLen - payloadOffset;
    
    return true;
}

size_t MPLSParser::parseLabelStack(const uint8_t* data, size_t dataLen, 
                                  size_t offset, PacketMetadata& metadata) {
    size_t currentOffset = offset;
    size_t totalConsumed = 0;
    metadata.mpls.label_stack.clear();
    
    while (currentOffset + 4 <= dataLen) {
        // read 4 bytes of MPLS label header (big endian)
        uint32_t labelHeader = ntohl(*reinterpret_cast<const uint32_t*>(data + currentOffset));
        
        // parse label header fields
        MPLSMetadata::Label label;
        label.label = (labelHeader >> 12) & 0xFFFFF;  // label value (20 bits)
        label.tc = (labelHeader >> 9) & 0x7;          // traffic class (3 bits)
        label.bos = (labelHeader >> 8) & 0x1;         // bottom of stack flag (1 bit)
        label.ttl = labelHeader & 0xFF;               // TTL (8 bits)
        
        metadata.mpls.label_stack.push_back(label);
        metadata.mpls.stack_depth++;
        
        currentOffset += 4;
        totalConsumed += 4;
        
        // if bottom of stack flag is set, stop parsing
        if (label.bos) {
            break;
        }
        
        // prevent infinite loop, limit maximum label stack depth
        if (metadata.mpls.stack_depth >= 10) {
            break;
        }
    }
    
    // if bottom of stack flag is not found, consider parsing failed
    if (!metadata.mpls.label_stack.empty() && 
        !metadata.mpls.label_stack.back().bos) {
        return 0;
    }
    
    return totalConsumed;
}

uint16_t MPLSParser::guessPayloadProtocol(const uint8_t* data, size_t dataLen) {
    if (!data || dataLen < 1) {
        return 0;
    }
    
    // check version field of the first byte
    uint8_t version = (data[0] >> 4) & 0xF;
    
    if (version == 4) {
        // IPv4 packet
        return 0x0800;
    } else if (version == 6) {
        // IPv6 packet
        return 0x86DD;
    }
    
    // if there is enough data, try other heuristic methods
    if (dataLen >= 14) {
        // check if it might be an Ethernet frame (nested Ethernet)
        uint16_t possibleEtherType = ntohs(*reinterpret_cast<const uint16_t*>(data + 12));
        if (possibleEtherType == 0x0800 || possibleEtherType == 0x86DD || 
            possibleEtherType == 0x0806 || possibleEtherType == 0x8100) {
            return 0; // might be an Ethernet frame, return 0 to indicate further parsing is needed
        }
    }
    
    // if data length is small and the first byte looks like a control message
    if (dataLen >= 4) {
        // check if it might be an MPLS control protocol
        uint32_t firstWord = ntohl(*reinterpret_cast<const uint32_t*>(data));
        if ((firstWord & 0xFF000000) == 0x01000000) {
            // might be LDP or other MPLS control protocol
            return 0;
        }
    }
    
    // default assumption is IPv4
    return 0x0800;
}

std::string MPLSParser::getLabelDescription(uint32_t label) {
    // MPLS special label values (RFC 3032)
    switch (label) {
        case 0:
            return "IPv4 Explicit Null";
        case 1:
            return "Router Alert";
        case 2:
            return "IPv6 Explicit Null";
        case 3:
            return "Implicit Null";
        case 4:
        case 5:
        case 6:
        case 7:
        case 8:
        case 9:
        case 10:
        case 11:
        case 12:
        case 13:
        case 14:
        case 15:
            return "Reserved";
        default:
            if (label >= 16 && label <= 1048575) {
                return ""; // normal label, no special description needed
            } else {
                return "Reserved";
            }
    }
}
