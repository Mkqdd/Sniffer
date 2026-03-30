#ifndef GRE_PARSER_H
#define GRE_PARSER_H

#include "BaseParser.h"
#include "PacketMetadata.h"
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/GreLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>
#include <pcapplusplus/VlanLayer.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>
#include <sstream>

class GREParser : public BaseParser {
public:
    static bool parse(pcpp::Packet& packet, PacketMetadata& metadata);

private:
    static bool parseGREv0(pcpp::GREv0Layer* grev0Layer, pcpp::Packet& packet, PacketMetadata& metadata);
    static bool parseGREv1(pcpp::GREv1Layer* grev1Layer, pcpp::Packet& packet, PacketMetadata& metadata);
    static bool parseGenericGRE(pcpp::GreLayer* greLayer, pcpp::Packet& packet, PacketMetadata& metadata);
    static bool parseEncapsulatedProtocol(pcpp::Packet& packet, PacketMetadata& metadata);
};

#endif // GRE_PARSER_H 