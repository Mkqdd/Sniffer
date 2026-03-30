#ifndef ARP_PARSER_H
#define ARP_PARSER_H

#include "BaseParser.h"
#include "PacketMetadata.h"
#include <pcapplusplus/Packet.h>

class ARPParser : public BaseParser {
public:
    static bool parse(pcpp::Packet& packet, PacketMetadata& metadata);

private:
    static std::string arpOpToString(uint16_t op);
};

#endif // ARP_PARSER_H 