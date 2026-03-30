#ifndef UDP_PARSER_H
#define UDP_PARSER_H

#include "BaseParser.h"

class UDPParser : public BaseParser {
public:
    /**
     * @brief Parse UDP packet and fill metadata
     * @param packet The packet to parse
     * @param metadata The metadata structure to fill
     * @return true if parsing was successful
     */
    static bool parse(pcpp::Packet& packet, PacketMetadata& metadata);
};

#endif