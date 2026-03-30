#ifndef ETHERNET_PARSER_H
#define ETHERNET_PARSER_H

#include "PacketMetadata.h"
#include "LoggerManager.h"
#include <pcapplusplus/Packet.h>

class EthernetParser {
public:
    static bool parse(pcpp::Packet& packet, PacketMetadata& metadata);
};

#endif