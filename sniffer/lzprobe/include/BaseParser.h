#ifndef BASE_PARSER_H
#define BASE_PARSER_H

#include "PacketMetadata.h"
#include <pcapplusplus/Packet.h>
#include <string>
#include <memory>
#include <arpa/inet.h>
#include <sstream>
#include <iomanip>
#include <map>
#include <functional>
#include <cstring>

/**
 * @brief Base class for all protocol parsers
 */
class BaseParser {
public:
    virtual ~BaseParser() = default;

protected:
    /**
     * @brief Convert IP address from uint32_t to string format
     * @param ip IP address in network byte order
     * @return IP address as string
     */
    static std::string ipToString(uint32_t ip);

    /**
     * @brief Convert MAC address from bytes to string format
     * @param mac MAC address bytes (6 bytes)
     * @return MAC address as string (XX:XX:XX:XX:XX:XX)
     */
    static std::string macToString(const uint8_t* mac);

    /**
     * @brief Convert port number to service name
     * @param port Port number
     * @param protocol Protocol name (TCP/UDP)
     * @return Service name or port number as string
     */
    static std::string portToService(uint16_t port, const std::string& protocol);

    /**
     * @brief Extract common network layer information
     * @param packet The packet to extract from
     * @param metadata The metadata to fill
     */
    static void extractNetworkInfo(pcpp::Packet& packet, PacketMetadata& metadata);

    /**
     * @brief Calculate packet size information
     * @param packet The packet to calculate
     * @param metadata The metadata to fill with size info
     */
    static void calculateSizes(pcpp::Packet& packet, PacketMetadata& metadata);

    /**
     * @brief Validate packet structure
     * @param packet The packet to validate
     * @return true if packet is valid, false otherwise
     */
    static bool validatePacket(pcpp::Packet& packet);

public:
    /**
     * @brief Convert EtherType to human-readable string
     * @param ethertype EtherType value
     * @return EtherType as string
     */
    static std::string etherTypeToString(uint16_t ethertype);

protected:
};

/**
 * @brief Factory class for creating parser instances
 */
class ParserFactory {
public:
    template<typename T>
    static void registerParser(const std::string& protocolName) {
        parsers_[protocolName] = []() -> std::shared_ptr<BaseParser> {
            return std::make_shared<T>();
        };
    }
    
    static std::shared_ptr<BaseParser> createParser(const std::string& protocolName);

private:
    static std::map<std::string, std::function<std::shared_ptr<BaseParser>()>> parsers_;
};

#endif // BASE_PARSER_H