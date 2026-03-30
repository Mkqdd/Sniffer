#pragma once
#include <string>
#include <fstream>
#include <mutex>
#include "PacketMetadata.h"
#include "parsers/SSLParser.h"
#include "ConnectionTracker.h"

class LoggerManager
{
public:
    LoggerManager();
    LoggerManager(const std::string& outputDir);
    ~LoggerManager();
    
    // Initialize log files (should be called after setting output directory)
    void initializeLogFiles();

    // Set output directory
    void setOutputDirectory(const std::string& outputDir);
    
    // Set output directory based on input file name (creates subdirectory)
    void setOutputDirectoryFromFile(const std::string& inputFile, const std::string& baseOutputDir = "logs");
    
    // Set output format (JSON or CSV)
    void setOutputFormat(bool useJson);

    // Log packet metadata
    void logPacket(const PacketMetadata& meta);

    // Log connection metadata to specific category file
    void logConn(const PacketMetadata& meta, const std::string& category);
    
    // Log connection flow statistics in Zeek conn.log format
    void logConnFlow(const PacketMetadata& meta);
    
    // Flush completed connections to log
    void flushCompletedConnections();
    
    // Flush completed connections in real-time (called after each packet)
    void flushCompletedConnectionsRealtime();
    
    // Force cleanup all remaining connections and flush them
    void forceFlushAllConnections();

private:
    std::string outputDirectory;
    bool useJsonFormat;
    std::ofstream logFile;
    std::mutex logMutex;

    // Separate files per category
    std::ofstream ethernetLogFile;
    std::ofstream wifiLogFile;
    std::ofstream errorLogFile;
    std::ofstream connLogFile;  // Connection flow log file
    
    // Connection tracker for flow statistics
    ConnectionTracker connectionTracker;
    
    // Helper methods for different output formats
    void logPacketCSV(const PacketMetadata& meta);
    void logPacketJSON(const PacketMetadata& meta);
    void logConnCSV(const PacketMetadata& meta, const std::string& category);
    void logConnJSON(const PacketMetadata& meta, const std::string& category);
    void logConnFlowJSON(const ConnectionStats& conn);
    
    // JSON formatting helpers
    std::string formatMACAddress(const uint8_t* mac) const;
    std::string escapeJsonString(const std::string& str);

};