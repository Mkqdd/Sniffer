#ifndef PACKET_DISPATCHER_H
#define PACKET_DISPATCHER_H

#include "PacketMetadata.h"
#include "LoggerManager.h"
#include <pcapplusplus/Packet.h>

class PacketDispatcher
{
public:
    PacketDispatcher(LoggerManager &logger);
    void dispatch(pcpp::Packet &packet, double timestamp);

private:
    LoggerManager &m_logger;
};

#endif