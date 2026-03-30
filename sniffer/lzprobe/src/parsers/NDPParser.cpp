#include "parsers/NDPParser.h"
#include <pcapplusplus/IPv6Layer.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sstream>
#include <iomanip>
#include <cstring>

bool NDPParser::parse(pcpp::Packet& packet, PacketMetadata& metadata) {
    auto* icmpv6Layer = packet.getLayerOfType<pcpp::IcmpV6Layer>();
    if (!icmpv6Layer) {
        return false;
    }

    uint8_t icmpType = static_cast<uint8_t>(icmpv6Layer->getMessageType());
    
    // check if the icmp type is NDP message type
    if (icmpType != 133 && icmpType != 134 && icmpType != 135 && icmpType != 136 && icmpType != 137) {
        return false;
    }

    // set the NDP flag
    metadata.has_ndp = true;
    metadata.ndp.message_type = icmpType;
    
    // get the IPv6 layer information for DAD detection
    auto* ipv6Layer = packet.getLayerOfType<pcpp::IPv6Layer>();
    if (ipv6Layer) {
        // check if the packet is a DAD packet (source address is ::)
        pcpp::IPv6Address srcAddr = ipv6Layer->getSrcIPv6Address();
        if (srcAddr == pcpp::IPv6Address::Zero) {
            metadata.ndp.is_dad_packet = true;
        }
        
        // check if the destination address is a solicited node multicast address
        pcpp::IPv6Address dstAddr = ipv6Layer->getDstIPv6Address();
        uint8_t dstBytes[16];
        dstAddr.copyTo(dstBytes);
        metadata.ndp.is_solicited_node_multicast = isSolicitedNodeMulticast(dstBytes);
    }
    
    // parse the NDP message based on the message type
    switch (icmpType) {
        case 133: // Router Solicitation
            parseRouterSolicitation(icmpv6Layer, metadata);
            metadata.ndp.message_description = "Router Solicitation (RS)";
            break;
            
        case 134: // Router Advertisement
            parseRouterAdvertisement(icmpv6Layer, metadata);
            metadata.ndp.message_description = "Router Advertisement (RA)";
            break;
            
        case 135: // Neighbor Solicitation
            parseNeighborSolicitation(icmpv6Layer, metadata);
            metadata.ndp.message_description = "Neighbor Solicitation (NS)";
            break;
            
        case 136: // Neighbor Advertisement
            parseNeighborAdvertisement(icmpv6Layer, metadata);
            metadata.ndp.message_description = "Neighbor Advertisement (NA)";
            break;
            
        case 137: // Redirect
            parseRedirect(icmpv6Layer, metadata);
            metadata.ndp.message_description = "Redirect";
            break;
            
        default:
            return false;
    }
    
    return true;
}

void NDPParser::parseRouterSolicitation(pcpp::IcmpV6Layer* icmpv6Layer, PacketMetadata& metadata) {
    const uint8_t* payload = icmpv6Layer->getLayerPayload();
    size_t payloadLen = icmpv6Layer->getLayerPayloadSize();
    
    if (payloadLen >= 4) {
        // RS message format: 4 bytes reserved field + options
        // skip the 4 bytes reserved field, parse the options
        if (payloadLen > 4) {
            parseNDPOptions(payload + 4, payloadLen - 4, metadata);
        }
    }
}

void NDPParser::parseRouterAdvertisement(pcpp::IcmpV6Layer* icmpv6Layer, PacketMetadata& metadata) {
    const uint8_t* payload = icmpv6Layer->getLayerPayload();
    size_t payloadLen = icmpv6Layer->getLayerPayloadSize();
    
    if (payloadLen >= 12) {
        // RA message format:
        // 0: Cur Hop Limit (1 byte)
        // 1: Flags (1 byte) - M, O, H, Prf, Reserved
        // 2-3: Router Lifetime (2 bytes)
        // 4-7: Reachable Time (4 bytes)
        // 8-11: Retrans Timer (4 bytes)
        // 12+: Options
        
        metadata.ndp.cur_hop_limit = payload[0];
        metadata.ndp.flags = payload[1];
        metadata.ndp.router_lifetime = ntohs(*reinterpret_cast<const uint16_t*>(payload + 2));
        metadata.ndp.reachable_time = ntohl(*reinterpret_cast<const uint32_t*>(payload + 4));
        metadata.ndp.retrans_timer = ntohl(*reinterpret_cast<const uint32_t*>(payload + 8));
        
        // parse the flags
        metadata.ndp.managed_addr_config = (payload[1] & 0x80) != 0;  // M flag
        metadata.ndp.other_config = (payload[1] & 0x40) != 0;         // O flag
        metadata.ndp.home_agent = (payload[1] & 0x20) != 0;           // H flag
        metadata.ndp.router_preference = (payload[1] >> 3) & 0x03;    // Prf (2 bits)
        
        // parse the options
        if (payloadLen > 12) {
            parseNDPOptions(payload + 12, payloadLen - 12, metadata);
        }
    }
}

void NDPParser::parseNeighborSolicitation(pcpp::IcmpV6Layer* icmpv6Layer, PacketMetadata& metadata) {
    const uint8_t* payload = icmpv6Layer->getLayerPayload();
    size_t payloadLen = icmpv6Layer->getLayerPayloadSize();
    
    if (payloadLen >= 20) {
        // NS message format:
        // 0-3: Reserved (4 bytes)
        // 4-19: Target Address (16 bytes)
        // 20+: Options
        
        // extract the target address
        memcpy(metadata.ndp.target_address, payload + 4, 16);
        metadata.ndp.target_address_str = ipv6ToString(metadata.ndp.target_address);
        
        // parse the options
        if (payloadLen > 20) {
            parseNDPOptions(payload + 20, payloadLen - 20, metadata);
        }
    }
}

void NDPParser::parseNeighborAdvertisement(pcpp::IcmpV6Layer* icmpv6Layer, PacketMetadata& metadata) {
    const uint8_t* payload = icmpv6Layer->getLayerPayload();
    size_t payloadLen = icmpv6Layer->getLayerPayloadSize();
    
    if (payloadLen >= 20) {
        // NA message format:
        // 0: Flags (1 byte) - R, S, O, Reserved
        // 1-3: Reserved (3 bytes)
        // 4-19: Target Address (16 bytes)
        // 20+: Options
        
        uint8_t flags = payload[0];
        metadata.ndp.router_flag = (flags & 0x80) != 0;     // R flag
        metadata.ndp.solicited_flag = (flags & 0x40) != 0;  // S flag
        metadata.ndp.override_flag = (flags & 0x20) != 0;   // O flag
        
        // extract the target address
        memcpy(metadata.ndp.target_address, payload + 4, 16);
        metadata.ndp.target_address_str = ipv6ToString(metadata.ndp.target_address);
        
        // parse the options
        if (payloadLen > 20) {
            parseNDPOptions(payload + 20, payloadLen - 20, metadata);
        }
    }
}

void NDPParser::parseRedirect(pcpp::IcmpV6Layer* icmpv6Layer, PacketMetadata& metadata) {
    const uint8_t* payload = icmpv6Layer->getLayerPayload();
    size_t payloadLen = icmpv6Layer->getLayerPayloadSize();
    
    if (payloadLen >= 36) {
        // Redirect message format:
        // 0-3: Reserved (4 bytes)
        // 4-19: Target Address (16 bytes)
        // 20-35: Destination Address (16 bytes)
        // 36+: Options
        
        // extract the redirect target address and destination address
        memcpy(metadata.ndp.redirect_target, payload + 4, 16);
        memcpy(metadata.ndp.redirect_destination, payload + 20, 16);
        
        metadata.ndp.redirect_target_str = ipv6ToString(metadata.ndp.redirect_target);
        metadata.ndp.redirect_destination_str = ipv6ToString(metadata.ndp.redirect_destination);
        
        // parse the options
        if (payloadLen > 36) {
            parseNDPOptions(payload + 36, payloadLen - 36, metadata);
        }
    }
}

void NDPParser::parseNDPOptions(const uint8_t* optionsData, size_t optionsLen, PacketMetadata& metadata) {
    size_t offset = 0;
    
    while (offset + 2 <= optionsLen) {
        uint8_t optionType = optionsData[offset];
        uint8_t optionLength = optionsData[offset + 1];
        
        // if the option length is 0 or out of boundary, stop parsing
        if (optionLength == 0 || offset + optionLength * 8 > optionsLen) {
            break;
        }
        
        switch (optionType) {
            case 1: // Source Link-Layer Address
                parseSourceLinkLayerOption(optionsData + offset, optionLength, metadata);
                break;
                
            case 2: // Target Link-Layer Address
                parseTargetLinkLayerOption(optionsData + offset, optionLength, metadata);
                break;
                
            case 3: // Prefix Information
                parsePrefixInformationOption(optionsData + offset, optionLength, metadata);
                break;
                
            case 4: // Redirected Header
                parseRedirectedHeaderOption(optionsData + offset, optionLength, metadata);
                break;
                
            case 5: // MTU
                parseMTUOption(optionsData + offset, optionLength, metadata);
                break;
                
            default:
                // unknown option type, skip
                break;
        }
        
        offset += optionLength * 8;
    }
}

void NDPParser::parseSourceLinkLayerOption(const uint8_t* optionData, uint8_t optionLen, PacketMetadata& metadata) {
    if (optionLen >= 1 && optionLen * 8 >= 8) {
        // source link-layer address option format:
        // 0: Type (1)
        // 1: Length
        // 2-7: Link-Layer Address (6 bytes, for Ethernet)
        
        metadata.ndp.has_source_link_layer = true;
        memcpy(metadata.ndp.source_link_layer, optionData + 2, 6);
        metadata.ndp.source_link_layer_str = macToString(metadata.ndp.source_link_layer);
    }
}

void NDPParser::parseTargetLinkLayerOption(const uint8_t* optionData, uint8_t optionLen, PacketMetadata& metadata) {
    if (optionLen >= 1 && optionLen * 8 >= 8) {
        // target link-layer address option format:
        // 0: Type (2)
        // 1: Length
        // 2-7: Link-Layer Address (6 bytes, for Ethernet)
        
        metadata.ndp.has_target_link_layer = true;
        memcpy(metadata.ndp.target_link_layer, optionData + 2, 6);
        metadata.ndp.target_link_layer_str = macToString(metadata.ndp.target_link_layer);
    }
}

void NDPParser::parsePrefixInformationOption(const uint8_t* optionData, uint8_t optionLen, PacketMetadata& metadata) {
    if (optionLen >= 4 && optionLen * 8 >= 32) {
        // prefix information option format:
        // 0: Type (3)
        // 1: Length (4)
        // 2: Prefix Length
        // 3: Flags (L, A, Reserved)
        // 4-7: Valid Lifetime
        // 8-11: Preferred Lifetime
        // 12-15: Reserved
        // 16-31: Prefix
        
        metadata.ndp.has_prefix_info = true;
        metadata.ndp.prefix_length = optionData[2];
        
        uint8_t flags = optionData[3];
        metadata.ndp.on_link_flag = (flags & 0x80) != 0;      // L flag
        metadata.ndp.autonomous_flag = (flags & 0x40) != 0;   // A flag
        
        metadata.ndp.valid_lifetime = ntohl(*reinterpret_cast<const uint32_t*>(optionData + 4));
        metadata.ndp.preferred_lifetime = ntohl(*reinterpret_cast<const uint32_t*>(optionData + 8));
        
        memcpy(metadata.ndp.prefix, optionData + 16, 16);
        metadata.ndp.prefix_str = ipv6ToString(metadata.ndp.prefix);
    }
}

void NDPParser::parseRedirectedHeaderOption(const uint8_t* optionData, uint8_t optionLen, PacketMetadata& metadata) {
    if (optionLen >= 1) {
        // redirected header option format:
        // 0: Type (4)
        // 1: Length
        // 2-7: Reserved
        // 8+: IP header + data
        
        metadata.ndp.has_redirected_header = true;
        // here we can further parse the redirected IP header, but currently only mark the existence
    }
}

void NDPParser::parseMTUOption(const uint8_t* optionData, uint8_t optionLen, PacketMetadata& metadata) {
    if (optionLen >= 1 && optionLen * 8 >= 8) {
        // MTU option format:
        // 0: Type (5)
        // 1: Length (1)
        // 2-3: Reserved
        // 4-7: MTU
        
        metadata.ndp.has_mtu = true;
        metadata.ndp.mtu = ntohl(*reinterpret_cast<const uint32_t*>(optionData + 4));
    }
}

bool NDPParser::isSolicitedNodeMulticast(const uint8_t* address) {
    // solicited node multicast address format: FF02::1:FFXX:XXXX
    // the first 96 bits are fixed to FF02:0000:0000:0000:0000:0001:FF
    static const uint8_t prefix[13] = {
        0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01
    };
    
    return memcmp(address, prefix, 13) == 0;
}

void NDPParser::generateSolicitedNodeMulticast(const uint8_t* unicastAddr, uint8_t* multicastAddr) {
    // solicited node multicast address: FF02::1:FFXX:XXXX
    // the last 24 bits are the low 24 bits of the unicast address
    memset(multicastAddr, 0, 16);
    multicastAddr[0] = 0xFF;
    multicastAddr[1] = 0x02;
    multicastAddr[11] = 0x00;  // Fixed: should be 0x00, not 0x01
    multicastAddr[12] = 0x01;  // Fixed: should be 0x01, not 0xFF
    multicastAddr[13] = 0xFF;  // Fixed: should be 0xFF
    
    // copy the low 24 bits of the unicast address (last 3 bytes)
    // Note: unicastAddr[13] = 0x00, unicastAddr[14] = 0x00, unicastAddr[15] = 0x01
    multicastAddr[14] = unicastAddr[14];  // 0x00
    multicastAddr[15] = unicastAddr[15];  // 0x01
}

std::string NDPParser::ipv6ToString(const uint8_t* address) {
    char str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, address, str, INET6_ADDRSTRLEN);
    return std::string(str);
}

std::string NDPParser::macToString(const uint8_t* macAddr) {
    std::ostringstream oss;
    for (int i = 0; i < 6; i++) {
        if (i > 0) oss << ":";
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(macAddr[i]);
    }
    return oss.str();
}

std::string NDPParser::getNDPOptionDescription(uint8_t optionType) {
    switch (optionType) {
        case 1: return "Source Link-Layer Address";
        case 2: return "Target Link-Layer Address";
        case 3: return "Prefix Information";
        case 4: return "Redirected Header";
        case 5: return "MTU";
        case 6: return "NSSA Redirect";
        case 7: return "Advertisement Interval";
        case 8: return "Home Agent Information";
        case 9: return "Source Address List";
        case 10: return "Target Address List";
        case 11: return "CGA";
        case 12: return "RSA Signature";
        case 13: return "Timestamp";
        case 14: return "Nonce";
        case 15: return "Trust Anchor";
        case 16: return "Certificate";
        case 17: return "IP Address/Prefix";
        case 18: return "New Router Prefix Information";
        case 19: return "Link-layer Address";
        case 20: return "Neighbor Advertisement Acknowledgment";
        case 23: return "RA Flags Extension";
        case 24: return "RDNSS";
        case 25: return "DNSSL";
        case 26: return "Proxy Signature";
        case 27: return "Address Registration";
        case 28: return "6LoWPAN Context";
        case 29: return "Authoritative Border Router";
        case 30: return "6CIO";
        case 31: return "Destination Address List";
        case 32: return "Redirected Path";
        case 33: return "Prefix64";
        case 34: return "Captive Portal";
        case 35: return "Extended DNS Search List";
        default: return "Unknown(" + std::to_string(optionType) + ")";
    }
}
