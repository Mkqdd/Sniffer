#ifndef CAPTUREMANAGER_H
#define CAPTUREMANAGER_H

#include <string>
#include "PacketDispatcher.h"

class CaptureManager {
public:
    CaptureManager(const std::string &pcapFile, PacketDispatcher &dispatcher);
    ~CaptureManager();

    void run();

private:
    std::string m_pcapFile;
    PacketDispatcher &m_dispatcher;
};

#endif // CAPTUREMANAGER_H