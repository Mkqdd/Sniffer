#ifndef VLAN_PARSER_H
#define VLAN_PARSER_H

#include "BaseParser.h"
#include "PacketMetadata.h"
#include <pcapplusplus/Packet.h>

class VLANParser : public BaseParser {
public:
    static bool parse(pcpp::Packet& packet, PacketMetadata& metadata);
};

#endif // VLAN_PARSER_H 