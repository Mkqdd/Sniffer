#ifndef IPV6_PARSER_H
#define IPV6_PARSER_H

#include "BaseParser.h"
#include "PacketMetadata.h"
#include <pcapplusplus/Packet.h>

class IPv6Parser : public BaseParser {
public:
    static bool parse(pcpp::Packet& packet, PacketMetadata& metadata);

private:
    static std::string ipv6ToString(const uint8_t* ipv6);
    static void parseExtensionHeaders(pcpp::Packet& packet, PacketMetadata& metadata);
    static bool isExtensionHeader(uint8_t nextHeader);
};

#endif // IPV6_PARSER_H
