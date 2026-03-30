#include "parsers/WiFiParser.h"
#include <cstring>
#include <sstream>
#include <iomanip>

bool WiFiParser::parse(pcpp::Packet& packet, PacketMetadata& metadata) {
    // Check if the packet is a WiFi packet
    auto linkType = packet.getRawPacket()->getLinkLayerType();
    if (linkType != pcpp::LINKTYPE_IEEE802_11 &&
        linkType != pcpp::LINKTYPE_IEEE802_11_RADIOTAP)
        return false;

    const uint8_t* packetData = packet.getRawPacket()->getRawData();
    size_t dataLen = packet.getRawPacket()->getRawDataLen();

    // If the packet is a Radiotap packet, get the offset to the 802.11 frame
    size_t offset = 0;
    if (linkType == pcpp::LINKTYPE_IEEE802_11_RADIOTAP) {
        if (dataLen < 8) return false; // Radiotap header too short
        offset = *(uint16_t*)(packetData + 2); // Radiotap length
        if (offset >= dataLen) return false;
    }

    // WiFi frame minimum length
    if (dataLen - offset < 24) return false;

    // Parse Frame Control
    uint16_t frameControl = (packetData[offset + 1] << 8) | packetData[offset];
    uint8_t protocolVersion = frameControl & 0x03;
    if (protocolVersion != 0) return false;

    uint8_t frameType = (frameControl >> 2) & 0x03;
    if (frameType > 2) return false;

    uint8_t frameSubtype = (frameControl >> 4) & 0x0F;
    if (!isValidFrameSubtype(frameType, frameSubtype)) return false;

    metadata.has_wifi = true;
    
    // Parse Frame Control field
    parseFrameControl(frameControl, metadata.wifi);
    
    // Parse Duration/ID field (next 2 bytes)
    metadata.wifi.duration = (packetData[3] << 8) | packetData[2];
    
    // Parse address fields based on frame type and ToDS/FromDS flags
    parseAddressFields(packetData, dataLen, metadata.wifi);
    
    // Parse Sequence Control field (2 bytes after addresses)
    size_t seqOffset = 24; // Basic frame: 2 bytes FC + 2 bytes Duration + 6*3 bytes addresses
    if (dataLen >= seqOffset + 2) {
        uint16_t sequenceControl = (packetData[seqOffset + 1] << 8) | packetData[seqOffset];
        metadata.wifi.sequence_number = sequenceControl & 0x0FFF; // 12 bits
    }
    
    // Parse frame body based on frame type
    switch (metadata.wifi.frame_type) {
        case FRAME_TYPE_MANAGEMENT:
            parseManagementFrame(packetData, dataLen, metadata.wifi);
            break;
        case FRAME_TYPE_CONTROL:
            parseControlFrame(packetData, dataLen, metadata.wifi);
            break;
        case FRAME_TYPE_DATA:
            parseDataFrame(packetData, dataLen, metadata.wifi);
            break;
    }
    
    // Set packet length information
    metadata.packet_length = dataLen;
    metadata.payload_length = dataLen - 24; // Basic frame header size
    
    // Set protocol string
    metadata.protocol = getFrameTypeString(metadata.wifi.frame_type, metadata.wifi.frame_subtype);
    
    // Copy MAC addresses to legacy fields for backward compatibility
    copyMacAddress(metadata.ethernet.src_mac, metadata.wifi.src_mac);
    copyMacAddress(metadata.ethernet.dst_mac, metadata.wifi.dst_mac);
    
    return true;
}

void WiFiParser::parseFrameControl(uint16_t frameControl, WiFiMetadata& wifi) {
    // Extract subfields from Frame Control
    wifi.protocol_version = (frameControl >> 0) & 0x03;   // Bits 0-1
    wifi.frame_type = (frameControl >> 2) & 0x03;         // Bits 2-3
    wifi.frame_subtype = (frameControl >> 4) & 0x0F;      // Bits 4-7
    wifi.to_ds = (frameControl >> 8) & 0x01;              // Bit 8
    wifi.from_ds = (frameControl >> 9) & 0x01;            // Bit 9
    wifi.more_frag = (frameControl >> 10) & 0x01;         // Bit 10
    wifi.retry = (frameControl >> 11) & 0x01;             // Bit 11
    wifi.power_mgmt = (frameControl >> 12) & 0x01;        // Bit 12
    wifi.more_data = (frameControl >> 13) & 0x01;         // Bit 13
    wifi.wep = (frameControl >> 14) & 0x01;               // Bit 14
    wifi.order = (frameControl >> 15) & 0x01;             // Bit 15
    
    wifi.frame_control = frameControl;
}

void WiFiParser::parseAddressFields(const uint8_t* packetData, size_t dataLen, WiFiMetadata& wifi) {
    // Address fields start at offset 4 (after FC and Duration)
    const uint8_t* addrStart = packetData + 4;
    
    // Always copy first two addresses (Address 1 and Address 2)
    if (dataLen >= 16) {
        copyMacAddress(wifi.receiver_mac, addrStart);      // Address 1 (Receiver)
        copyMacAddress(wifi.transmitter_mac, addrStart + 6); // Address 2 (Transmitter)
    }
    
    // Parse addresses based on ToDS and FromDS flags
    if (dataLen >= 22) {
        if (!wifi.to_ds && !wifi.from_ds) {
            // Ad-hoc mode
            copyMacAddress(wifi.dst_mac, addrStart);       // Address 1
            copyMacAddress(wifi.src_mac, addrStart + 6);   // Address 2
            copyMacAddress(wifi.bssid, addrStart + 12);    // Address 3
        } else if (wifi.to_ds && !wifi.from_ds) {
            // To DS mode (station to AP)
            copyMacAddress(wifi.dst_mac, addrStart + 12);  // Address 3
            copyMacAddress(wifi.src_mac, addrStart + 6);   // Address 2
            copyMacAddress(wifi.bssid, addrStart);         // Address 1
        } else if (!wifi.to_ds && wifi.from_ds) {
            // From DS mode (AP to station)
            copyMacAddress(wifi.dst_mac, addrStart);       // Address 1
            copyMacAddress(wifi.src_mac, addrStart + 12);  // Address 3
            copyMacAddress(wifi.bssid, addrStart + 6);     // Address 2
        } else if (wifi.to_ds && wifi.from_ds) {
            // WDS mode (AP to AP)
            copyMacAddress(wifi.dst_mac, addrStart + 12);  // Address 3
            copyMacAddress(wifi.src_mac, addrStart + 6);   // Address 2
            copyMacAddress(wifi.bssid, addrStart);         // Address 1
        }
    }
}

void WiFiParser::parseManagementFrame(const uint8_t* packetData, size_t dataLen, WiFiMetadata& wifi) {
    // Management frame body starts after basic header (24 bytes)
    size_t bodyOffset = 24;
    
    if (dataLen < bodyOffset + 8) {
        return; // Not enough data for management frame body
    }
    
    // Parse Timestamp (8 bytes)
    if (dataLen >= bodyOffset + 8) {
        uint64_t timestamp = 0;
        for (int i = 0; i < 8; i++) {
            timestamp |= (static_cast<uint64_t>(packetData[bodyOffset + i]) << (i * 8));
        }
        wifi.timestamp = timestamp;
    }
    
    // Parse Beacon Interval (2 bytes)
    if (dataLen >= bodyOffset + 10) {
        wifi.beacon_interval = (packetData[bodyOffset + 9] << 8) | packetData[bodyOffset + 8];
    }
    
    // Parse Capability Information (2 bytes)
    if (dataLen >= bodyOffset + 12) {
        wifi.capability_info = (packetData[bodyOffset + 11] << 8) | packetData[bodyOffset + 10];
    }
    
    // Parse additional management frame elements based on subtype
    switch (wifi.frame_subtype) {
        case SUBTYPE_BEACON:
            // Beacon frames may have additional elements
            break;
        case SUBTYPE_PROBE_REQUEST:
        case SUBTYPE_PROBE_RESPONSE:
            // Probe frames may have additional elements
            break;
        case SUBTYPE_ASSOCIATION_REQUEST:
        case SUBTYPE_ASSOCIATION_RESPONSE:
            // Association frames may have additional elements
            break;
    }
}

void WiFiParser::parseDataFrame(const uint8_t* packetData, size_t dataLen, WiFiMetadata& wifi) {
    // Data frame body starts after basic header (24 bytes)
    size_t bodyOffset = 24;
    
    // Check if QoS Control field is present
    if (wifi.frame_subtype == SUBTYPE_QOS_DATA && dataLen >= bodyOffset + 2) {
        wifi.qos_control = (packetData[bodyOffset + 1] << 8) | packetData[bodyOffset];
        bodyOffset += 2;
    }
    
    // Check if WEP is enabled
    if (wifi.wep && dataLen >= bodyOffset + 4) {
        // Skip WEP header (4 bytes)
        bodyOffset += 4;
    }
    
    // Note: payload length is set in the main parse method
}

void WiFiParser::parseControlFrame(const uint8_t* packetData, size_t dataLen, WiFiMetadata& wifi) {
    // Control frames are typically short, just basic header
    // No additional parsing needed for most control frames
}

std::string WiFiParser::getFrameTypeString(uint8_t frameType, uint8_t frameSubtype) {
    std::ostringstream oss;
    
    switch (frameType) {
        case FRAME_TYPE_MANAGEMENT:
            oss << "802.11-Management";
            switch (frameSubtype) {
                case SUBTYPE_ASSOCIATION_REQUEST: oss << "-AssocReq"; break;
                case SUBTYPE_ASSOCIATION_RESPONSE: oss << "-AssocResp"; break;
                case SUBTYPE_REASSOCIATION_REQUEST: oss << "-ReassocReq"; break;
                case SUBTYPE_REASSOCIATION_RESPONSE: oss << "-ReassocResp"; break;
                case SUBTYPE_PROBE_REQUEST: oss << "-ProbeReq"; break;
                case SUBTYPE_PROBE_RESPONSE: oss << "-ProbeResp"; break;
                case SUBTYPE_BEACON: oss << "-Beacon"; break;
                case SUBTYPE_ATIM: oss << "-ATIM"; break;
                case SUBTYPE_DISASSOCIATION: oss << "-Disassoc"; break;
                case SUBTYPE_AUTHENTICATION: oss << "-Auth"; break;
                case SUBTYPE_DEAUTHENTICATION: oss << "-Deauth"; break;
                default: oss << "-Unknown(" << static_cast<int>(frameSubtype) << ")"; break;
            }
            break;
            
        case FRAME_TYPE_CONTROL:
            oss << "802.11-Control";
            switch (frameSubtype) {
                case SUBTYPE_RTS: oss << "-RTS"; break;
                case SUBTYPE_CTS: oss << "-CTS"; break;
                case SUBTYPE_ACK: oss << "-ACK"; break;
                default: oss << "-Unknown(" << static_cast<int>(frameSubtype) << ")"; break;
            }
            break;
            
        case FRAME_TYPE_DATA:
            oss << "802.11-Data";
            switch (frameSubtype) {
                case SUBTYPE_DATA: oss << "-Data"; break;
                case SUBTYPE_DATA_CF_ACK: oss << "-DataCFAck"; break;
                case SUBTYPE_DATA_CF_POLL: oss << "-DataCFPoll"; break;
                case SUBTYPE_DATA_CF_ACK_CF_POLL: oss << "-DataCFAckCFPoll"; break;
                case SUBTYPE_NULL: oss << "-Null"; break;
                case SUBTYPE_CF_ACK: oss << "-CFAck"; break;
                case SUBTYPE_CF_POLL: oss << "-CFPoll"; break;
                case SUBTYPE_CF_ACK_CF_POLL: oss << "-CFAckCFPoll"; break;
                case SUBTYPE_QOS_DATA: oss << "-QoSData"; break;
                default: oss << "-Unknown(" << static_cast<int>(frameSubtype) << ")"; break;
            }
            break;
            
        default:
            oss << "802.11-Unknown(" << static_cast<int>(frameType) << ")";
            break;
    }
    
    return oss.str();
}

bool WiFiParser::isValidFrameSubtype(uint8_t frameType, uint8_t frameSubtype) {
    switch (frameType) {
        case FRAME_TYPE_MANAGEMENT:
            // Management frame subtypes: 0-12
            return frameSubtype <= 12;
            
        case FRAME_TYPE_CONTROL:
            // Control frame subtypes: 8-15
            return frameSubtype >= 8 && frameSubtype <= 15;
            
        case FRAME_TYPE_DATA:
            // Data frame subtypes: 0-8
            return frameSubtype <= 8;
            
        default:
            return false;
    }
}

void WiFiParser::copyMacAddress(uint8_t dst[6], const uint8_t* src) {
    std::memcpy(dst, src, 6);
} 