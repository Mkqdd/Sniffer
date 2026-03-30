#ifndef TCP_PARSER_H
#define TCP_PARSER_H

#include "BaseParser.h"

class TCPParser : public BaseParser {
public:
    /**
     * @brief Parse TCP packet and fill metadata
     * @param packet The packet to parse
     * @param metadata The metadata structure to fill
     * @return true if parsing was successful
     */
    static bool parse(pcpp::Packet& packet, PacketMetadata& metadata);
    
private:
    static std::string flagsToString(uint16_t flags);
    
    /**
     * @brief Check if packet contains SSL/TLS traffic
     * @param packet The packet to check
     * @param metadata The metadata containing port information
     * @return true if packet contains SSL/TLS traffic
     */
    static bool isSSLTraffic(pcpp::Packet& packet, PacketMetadata& metadata);
};

#endif