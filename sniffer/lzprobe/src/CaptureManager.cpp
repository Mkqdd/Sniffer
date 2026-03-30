#include "CaptureManager.h"
#include <pcapplusplus/PcapFileDevice.h>
#include <iostream>

CaptureManager::CaptureManager(const std::string &pcapFile, PacketDispatcher &dispatcher)
    : m_pcapFile(pcapFile), m_dispatcher(dispatcher)
{
}

CaptureManager::~CaptureManager() = default;

void CaptureManager::run()
{
    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(m_pcapFile);
    if (!reader->open())
    {
        std::cerr << "Error opening the pcap file" << std::endl;
        delete reader;
        return;
    }

    pcpp::RawPacket rawPacket;

    while (reader->getNextPacket(rawPacket))
    {
        // Timespec
        timespec ts_spec = rawPacket.getPacketTimeStamp();
        double ts_sec = ts_spec.tv_sec + ts_spec.tv_nsec / 1e9;

        // RawPacket to Packet
        pcpp::Packet parsedPacket(&rawPacket);
        m_dispatcher.dispatch(parsedPacket, ts_sec);
    }

    reader->close();
    delete reader;
}