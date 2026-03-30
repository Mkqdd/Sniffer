#ifndef IPV4_PARSER_H
#define IPV4_PARSER_H

#include "BaseParser.h"
#include "PacketMetadata.h"
#include <pcapplusplus/Packet.h>

class IPv4Parser : public BaseParser {
public:
    static bool parse(pcpp::Packet& packet, PacketMetadata& metadata);

private:
    static std::string ipToString(uint32_t ip);
};

#endif // IPV4_PARSER_H