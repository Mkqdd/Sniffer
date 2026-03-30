#ifndef MPLS_PARSER_H
#define MPLS_PARSER_H

#include "BaseParser.h"
#include <pcapplusplus/Packet.h>

/**
 * @brief Parser for MPLS (Multi-Protocol Label Switching) protocol
 * 
 * MPLS protocol parser implementation:
 * - Supports MPLS unicast (0x8847) and multicast (0x8848)
 * - Parses MPLS label stack, each label is 4 bytes
 * - Label format: Label(20bit) + TC(3bit) + S(1bit) + TTL(8bit)
 * - Continue parsing until encountering BOS (Bottom of Stack, S=1) label
 * - Infer inner protocol type based on context
 */
class MPLSParser : public BaseParser {
public:
    /**
     * @brief Parse MPLS layer from packet
     * @param packet The packet containing MPLS layer
     * @param metadata The metadata structure to populate
     * @return true if parsing was successful, false otherwise
     */
    static bool parse(pcpp::Packet& packet, PacketMetadata& metadata);

private:
    /**
     * @brief Parse MPLS label stack from raw data
     * @param data Raw packet data
     * @param dataLen Length of data
     * @param offset Current offset in data
     * @param metadata Metadata to populate
     * @return Number of bytes consumed, 0 if error
     */
    static size_t parseLabelStack(const uint8_t* data, size_t dataLen, 
                                 size_t offset, PacketMetadata& metadata);
    
    /**
     * @brief Guess the payload protocol after MPLS headers
     * @param data Raw data after MPLS stack
     * @param dataLen Remaining data length
     * @return Guessed protocol ethertype (0x0800 for IPv4, 0x86DD for IPv6, etc.)
     */
    static uint16_t guessPayloadProtocol(const uint8_t* data, size_t dataLen);
    
    /**
     * @brief Convert MPLS label value to string for special labels
     * @param label MPLS label value
     * @return String description of special labels, or empty string for regular labels
     */
    static std::string getLabelDescription(uint32_t label);
};

#endif // MPLS_PARSER_H
