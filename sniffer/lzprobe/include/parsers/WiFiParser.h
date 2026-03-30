#pragma once
#include "PacketMetadata.h"
#include <pcapplusplus/Packet.h>
#include <cstdint>

class WiFiParser {
public:
    static bool parse(pcpp::Packet& packet, PacketMetadata& metadata);
    
private:
    // WiFi frame types
    static constexpr uint8_t FRAME_TYPE_MANAGEMENT = 0;
    static constexpr uint8_t FRAME_TYPE_CONTROL = 1;
    static constexpr uint8_t FRAME_TYPE_DATA = 2;
    
    // Management frame subtypes
    static constexpr uint8_t SUBTYPE_ASSOCIATION_REQUEST = 0;
    static constexpr uint8_t SUBTYPE_ASSOCIATION_RESPONSE = 1;
    static constexpr uint8_t SUBTYPE_REASSOCIATION_REQUEST = 2;
    static constexpr uint8_t SUBTYPE_REASSOCIATION_RESPONSE = 3;
    static constexpr uint8_t SUBTYPE_PROBE_REQUEST = 4;
    static constexpr uint8_t SUBTYPE_PROBE_RESPONSE = 5;
    static constexpr uint8_t SUBTYPE_BEACON = 8;
    static constexpr uint8_t SUBTYPE_ATIM = 9;
    static constexpr uint8_t SUBTYPE_DISASSOCIATION = 10;
    static constexpr uint8_t SUBTYPE_AUTHENTICATION = 11;
    static constexpr uint8_t SUBTYPE_DEAUTHENTICATION = 12;
    
    // Control frame subtypes
    static constexpr uint8_t SUBTYPE_RTS = 11;
    static constexpr uint8_t SUBTYPE_CTS = 12;
    static constexpr uint8_t SUBTYPE_ACK = 13;
    
    // Data frame subtypes
    static constexpr uint8_t SUBTYPE_DATA = 0;
    static constexpr uint8_t SUBTYPE_DATA_CF_ACK = 1;
    static constexpr uint8_t SUBTYPE_DATA_CF_POLL = 2;
    static constexpr uint8_t SUBTYPE_DATA_CF_ACK_CF_POLL = 3;
    static constexpr uint8_t SUBTYPE_NULL = 4;
    static constexpr uint8_t SUBTYPE_CF_ACK = 5;
    static constexpr uint8_t SUBTYPE_CF_POLL = 6;
    static constexpr uint8_t SUBTYPE_CF_ACK_CF_POLL = 7;
    static constexpr uint8_t SUBTYPE_QOS_DATA = 8;
    
    // Helper methods
    static void parseFrameControl(uint16_t frameControl, WiFiMetadata& wifi);
    static void parseAddressFields(const uint8_t* packetData, size_t dataLen, WiFiMetadata& wifi);
    static void parseManagementFrame(const uint8_t* packetData, size_t dataLen, WiFiMetadata& wifi);
    static void parseDataFrame(const uint8_t* packetData, size_t dataLen, WiFiMetadata& wifi);
    static void parseControlFrame(const uint8_t* packetData, size_t dataLen, WiFiMetadata& wifi);
    static std::string getFrameTypeString(uint8_t frameType, uint8_t frameSubtype);
    static void copyMacAddress(uint8_t dst[6], const uint8_t* src);
    static bool isValidFrameSubtype(uint8_t frameType, uint8_t frameSubtype);
}; 