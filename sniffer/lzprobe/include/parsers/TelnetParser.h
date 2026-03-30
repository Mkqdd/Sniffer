#ifndef TELNET_PARSER_H
#define TELNET_PARSER_H

#include "PacketMetadata.h"
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/TcpLayer.h>
#include <string>
#include <vector>

/**
 * Telnet Protocol Parser
 * 
 * Telnet protocol is based on TCP (port 23), and its parsing process is:
 * 1. After reassembling TCP stream, distinguish between plain character stream and control commands
 * 2. If it's a control command, it starts with IAC (0xFF), followed by command byte and possible option number
 * 3. If it doesn't start with IAC, the data is directly used as ASCII text interaction
 * 4. The core of parsing is to identify and process IAC command sequences while restoring plain text stream
 */
class TelnetParser {
public:
    /**
     * Parse Telnet packet
     * @param packet Packet to parse
     * @param metadata Output metadata structure
     * @return Returns true if parsing successful, false otherwise
     */
    static bool parse(pcpp::Packet& packet, PacketMetadata& metadata);

private:
    /**
     * Check if this is a Telnet packet (port 23)
     * @param packet Packet to check
     * @return Returns true if it's a Telnet packet, false otherwise
     */
    static bool isTelnetPacket(pcpp::Packet& packet);

    /**
     * Parse Telnet data content
     * @param tcpLayer TCP layer
     * @param metadata Output metadata structure
     * @return Returns true if parsing successful, false otherwise
     */
    static bool parseTelnetData(pcpp::TcpLayer* tcpLayer, PacketMetadata& metadata);

    /**
     * Parse IAC command sequences
     * @param data Data pointer
     * @param dataLen Data length
     * @param metadata Output metadata structure
     * @return Number of parsed commands
     */
    static size_t parseIACCommands(const uint8_t* data, size_t dataLen, PacketMetadata& metadata);

    /**
     * Parse plain text data
     * @param data Data pointer
     * @param dataLen Data length
     * @param metadata Output metadata structure
     */
    static void parseTextData(const uint8_t* data, size_t dataLen, PacketMetadata& metadata);

    /**
     * Convert command byte to readable string
     * @param cmd Command byte
     * @return Command string
     */
    static std::string commandToString(uint8_t cmd);

    /**
     * Convert option byte to readable string
     * @param option Option byte
     * @return Option string
     */
    static std::string optionToString(uint8_t option);

    /**
     * Convert data to string, filtering control characters
     * @param data Data pointer
     * @param dataLen Data length
     * @return Filtered string
     */
    static std::string dataToString(const uint8_t* data, size_t dataLen);

    /**
     * Extract data preview
     * @param data Data pointer
     * @param dataLen Data length
     * @param maxLen Maximum preview length
     * @return Data preview string
     */
    static std::string extractDataPreview(const uint8_t* data, size_t dataLen, size_t maxLen = 100);
};

#endif // TELNET_PARSER_H

