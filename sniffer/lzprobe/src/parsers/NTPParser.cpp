#include "parsers/NTPParser.h"
#include <pcapplusplus/NtpLayer.h>
#include <pcapplusplus/UdpLayer.h>
#include <netinet/in.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <cstring>

bool NTPParser::parse(pcpp::Packet& packet, PacketMetadata& metadata) {
    // Check if this is an NTP packet (UDP port 123)
    auto* udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
    if (!udpLayer) {
        return false;
    }
    
    // NTP uses UDP port 123
    if (udpLayer->getDstPort() != 123 && udpLayer->getSrcPort() != 123) {
        return false;
    }
    
    // Try to get NTP layer using PcapPlusPlus
    auto* ntpLayer = packet.getLayerOfType<pcpp::NtpLayer>();
    if (ntpLayer) {
        // Set NTP presence flag
        metadata.has_ntp = true;
        metadata.protocol = "UDP";
        metadata.application_protocol = "ntp";
        
        // Parse NTP header fields using PcapPlusPlus API
        metadata.ntp.li = static_cast<uint8_t>(ntpLayer->getLeapIndicator());
        metadata.ntp.vn = ntpLayer->getVersion();
        metadata.ntp.mode = static_cast<uint8_t>(ntpLayer->getMode());
        metadata.ntp.stratum = ntpLayer->getStratum();
        metadata.ntp.poll = static_cast<uint8_t>(ntpLayer->getPollInterval());
        metadata.ntp.precision = ntpLayer->getPrecision();
        metadata.ntp.root_delay = ntpLayer->getRootDelay();
        metadata.ntp.root_dispersion = ntpLayer->getRootDispersion();
        metadata.ntp.reference_id = ntpLayer->getReferenceIdentifier();
        
        // Parse timestamps (NTP timestamps are 64-bit, directly from PcapPlusPlus API)
        metadata.ntp.reference_timestamp = ntpLayer->getReferenceTimestamp();
        metadata.ntp.originate_timestamp = ntpLayer->getOriginTimestamp();
        metadata.ntp.receive_timestamp = ntpLayer->getReceiveTimestamp();
        metadata.ntp.transmit_timestamp = ntpLayer->getTransmitTimestamp();
        
        // Set human-readable strings
        metadata.ntp.li_str = leapIndicatorToString(metadata.ntp.li);
        metadata.ntp.vn_str = versionToString(metadata.ntp.vn);
        metadata.ntp.mode_str = modeToString(metadata.ntp.mode);
        metadata.ntp.stratum_str = stratumToString(metadata.ntp.stratum);
        metadata.ntp.reference_id_str = referenceIdToString(metadata.ntp.reference_id);
        
        // Calculate time metrics
        calculateTimeMetrics(metadata);
        
        // Set packet size information
        metadata.packet_length = packet.getRawPacket()->getRawDataLen();
        metadata.payload_length = ntpLayer->getLayerPayloadSize();
        
        return true;
    }
    
    // Fallback: manual parsing if PcapPlusPlus NTP layer is not available
    // This handles cases where the packet might not be recognized as NTP by PcapPlusPlus
    if (udpLayer->getLayerPayloadSize() >= 48) { // NTP header is 48 bytes
        const uint8_t* ntpData = udpLayer->getLayerPayload();
        
        // Set NTP presence flag
        metadata.has_ntp = true;
        metadata.protocol = "UDP";
        metadata.application_protocol = "ntp";
        
        // Parse NTP header manually
        parseNTPHeader(ntpData, metadata);
        
        // Set packet size information
        metadata.packet_length = packet.getRawPacket()->getRawDataLen();
        metadata.payload_length = udpLayer->getLayerPayloadSize();
        
        return true;
    }
    
    return false;
}

void NTPParser::parseNTPHeader(const uint8_t* data, PacketMetadata& metadata) {
    // Parse NTP header fields manually
    metadata.ntp.li = (data[0] >> 6) & 0x03;        // Leap Indicator (bits 7-6)
    metadata.ntp.vn = (data[0] >> 3) & 0x07;        // Version Number (bits 5-3)
    metadata.ntp.mode = data[0] & 0x07;              // Mode (bits 2-0)
    metadata.ntp.stratum = data[1];                   // Stratum
    metadata.ntp.poll = data[2];                      // Poll Interval
    metadata.ntp.precision = static_cast<int8_t>(data[3]); // Precision (signed)
    
    // Parse 32-bit fields (network byte order)
    metadata.ntp.root_delay = ntohl(*reinterpret_cast<const uint32_t*>(data + 4));
    metadata.ntp.root_dispersion = ntohl(*reinterpret_cast<const uint32_t*>(data + 8));
    metadata.ntp.reference_id = ntohl(*reinterpret_cast<const uint32_t*>(data + 12));
    
    // Parse 64-bit timestamps
    metadata.ntp.reference_timestamp = ntpTimestampToUint64(data + 16);
    metadata.ntp.originate_timestamp = ntpTimestampToUint64(data + 24);
    metadata.ntp.receive_timestamp = ntpTimestampToUint64(data + 32);
    metadata.ntp.transmit_timestamp = ntpTimestampToUint64(data + 40);
    
    // Set human-readable strings
    metadata.ntp.li_str = leapIndicatorToString(metadata.ntp.li);
    metadata.ntp.vn_str = versionToString(metadata.ntp.vn);
    metadata.ntp.mode_str = modeToString(metadata.ntp.mode);
    metadata.ntp.stratum_str = stratumToString(metadata.ntp.stratum);
    metadata.ntp.reference_id_str = referenceIdToString(metadata.ntp.reference_id);
    
    // Calculate time metrics
    calculateTimeMetrics(metadata);
}

uint64_t NTPParser::ntpTimestampToUint64(const uint8_t* data) {
    // NTP timestamp: 32-bit seconds + 32-bit fraction
    uint32_t seconds = ntohl(*reinterpret_cast<const uint32_t*>(data));
    uint32_t fraction = ntohl(*reinterpret_cast<const uint32_t*>(data + 4));
    
    // Combine into 64-bit timestamp
    return (static_cast<uint64_t>(seconds) << 32) | fraction;
}

std::string NTPParser::ntpTimestampToString(uint64_t timestamp) {
    uint32_t seconds = (timestamp >> 32) & 0xFFFFFFFF;
    uint32_t fraction = timestamp & 0xFFFFFFFF;
    
    // Convert NTP epoch (1900-01-01) to Unix epoch (1970-01-01)
    // NTP epoch starts 70 years and 17 leap days before Unix epoch
    const uint32_t NTP_EPOCH_OFFSET = 2208988800UL;
    
    if (seconds >= NTP_EPOCH_OFFSET) {
        uint32_t unixTime = seconds - NTP_EPOCH_OFFSET;
        time_t time = static_cast<time_t>(unixTime);
        struct tm* tm = gmtime(&time);
        
        std::ostringstream oss;
        oss << std::put_time(tm, "%Y-%m-%d %H:%M:%S");
        oss << "." << std::setfill('0') << std::setw(9) << fraction;
        return oss.str();
    } else {
        return "Invalid timestamp";
    }
}

std::string NTPParser::leapIndicatorToString(uint8_t li) {
    switch (li) {
        case 0: return "No warning";
        case 1: return "Last minute has 61 seconds";
        case 2: return "Last minute has 59 seconds";
        case 3: return "Alarm condition (clock not synchronized)";
        default: return "Unknown";
    }
}

std::string NTPParser::versionToString(uint8_t vn) {
    return "NTP v" + std::to_string(vn);
}

std::string NTPParser::modeToString(uint8_t mode) {
    switch (mode) {
        case 0: return "Reserved";
        case 1: return "Symmetric active";
        case 2: return "Symmetric passive";
        case 3: return "Client";
        case 4: return "Server";
        case 5: return "Broadcast";
        case 6: return "NTP control message";
        case 7: return "Reserved for private use";
        default: return "Unknown";
    }
}

std::string NTPParser::stratumToString(uint8_t stratum) {
    if (stratum == 0) return "Unspecified or invalid";
    if (stratum == 1) return "Primary reference (e.g., radio clock)";
    if (stratum >= 2 && stratum <= 15) return "Secondary reference (stratum " + std::to_string(stratum) + ")";
    if (stratum == 16) return "Unsynchronized";
    return "Reserved";
}

std::string NTPParser::referenceIdToString(uint32_t refId) {
    // Reference ID can be an IP address or ASCII string
    std::ostringstream oss;
    
    // Check if it looks like an IP address (first byte != 0)
    if ((refId & 0xFF000000) != 0) {
        // Format as IP address
        oss << ((refId >> 24) & 0xFF) << "."
            << ((refId >> 16) & 0xFF) << "."
            << ((refId >> 8) & 0xFF) << "."
            << (refId & 0xFF);
    } else {
        // Format as ASCII string
        oss << "'";
        for (int i = 0; i < 4; i++) {
            char c = (refId >> (24 - i * 8)) & 0xFF;
            if (c >= 32 && c <= 126) { // Printable ASCII
                oss << c;
            } else {
                oss << "\\x" << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(c);
            }
        }
        oss << "'";
    }
    
    return oss.str();
}

void NTPParser::calculateTimeMetrics(PacketMetadata& metadata) {
    // Calculate time offset and round trip delay for client-server mode
    if (metadata.ntp.mode == 3 && metadata.ntp.originate_timestamp != 0) { // Client mode
        // Time offset = ((T2 - T1) + (T3 - T4)) / 2
        // Round trip delay = (T4 - T1) - (T3 - T2)
        // Where: T1=originate, T2=receive, T3=transmit, T4=current time (we'll use 0 for now)
        
        if (metadata.ntp.receive_timestamp != 0 && metadata.ntp.transmit_timestamp != 0) {
            // Calculate round trip delay (simplified)
            uint64_t t1 = metadata.ntp.originate_timestamp;
            uint64_t t2 = metadata.ntp.receive_timestamp;
            uint64_t t3 = metadata.ntp.transmit_timestamp;
            
            // Convert NTP timestamps to seconds (simplified calculation)
            double t1_sec = static_cast<double>(t1 >> 32) + static_cast<double>(t1 & 0xFFFFFFFF) / 4294967296.0;
            double t2_sec = static_cast<double>(t2 >> 32) + static_cast<double>(t2 & 0xFFFFFFFF) / 4294967296.0;
            double t3_sec = static_cast<double>(t3 >> 32) + static_cast<double>(t3 & 0xFFFFFFFF) / 4294967296.0;
            
            // Round trip delay = (T3 - T1) - (T2 - T1) = T3 - T2
            metadata.ntp.round_trip_delay = (t3_sec - t2_sec) * 1000.0; // Convert to milliseconds
            
            // Time offset = ((T2 - T1) + (T3 - T1)) / 2 - (T3 - T1) = (T2 - T1) / 2
            metadata.ntp.time_offset = (t2_sec - t1_sec) * 1000.0 / 2.0; // Convert to milliseconds
        }
    }
}
