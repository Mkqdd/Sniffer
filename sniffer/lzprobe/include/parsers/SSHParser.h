#ifndef SSH_PARSER_H
#define SSH_PARSER_H

#include "BaseParser.h"
#include "PacketMetadata.h"
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/SSHLayer.h>

/**
 * @brief Parser for SSH (Secure Shell) protocol
 * 
 * SSH protocol parser implementation:
 * - Supports SSH protocol version exchange message parsing
 * - Supports SSH handshake message parsing (including KEXINIT)
 * - Supports SSH key exchange and algorithm negotiation phase
 * - Extracts visible plaintext fields such as protocol version, supported algorithm lists, etc.
 * - Based on PcapPlusPlus SSHLayer for parsing
 */
class SSHParser : public BaseParser {
public:
    /**
     * @brief Parse SSH packet and fill metadata
     * @param packet The packet to parse
     * @param metadata The metadata structure to fill
     * @return true if parsing was successful
     */
    static bool parse(pcpp::Packet& packet, PacketMetadata& metadata);
    
private:
    /**
     * @brief Check if packet is SSH traffic (port 22)
     * @param packet The packet to check
     * @return true if packet appears to be SSH
     */
    static bool isSSHPacket(pcpp::Packet& packet);
    
    /**
     * @brief Parse SSH identification message
     * @param sshLayer SSH layer containing identification data
     * @param metadata The metadata structure to fill
     * @return true if parsing was successful
     */
    static bool parseIdentification(pcpp::SSHIdentificationMessage* sshLayer, PacketMetadata& metadata);
    
    /**
     * @brief Parse SSH handshake message
     * @param sshLayer SSH layer containing handshake data
     * @param metadata The metadata structure to fill
     * @return true if parsing was successful
     */
    static bool parseHandshake(pcpp::SSHHandshakeMessage* sshLayer, PacketMetadata& metadata);
    
    /**
     * @brief Parse SSH key exchange init message
     * @param sshLayer SSH layer containing key exchange data
     * @param metadata The metadata structure to fill
     * @return true if parsing was successful
     */
    static bool parseKeyExchange(pcpp::SSHKeyExchangeInitMessage* sshLayer, PacketMetadata& metadata);
    
    /**
     * @brief Parse SSH encrypted message
     * @param sshLayer SSH layer containing encrypted data
     * @param metadata The metadata structure to fill
     * @return true if parsing was successful
     */
    static bool parseEncrypted(pcpp::SSHEncryptedMessage* sshLayer, PacketMetadata& metadata);
    
    /**
     * @brief Extract software version from SSH identification string
     * @param identification SSH identification string
     * @return Extracted software version
     */
    static std::string extractSoftwareVersion(const std::string& identification);
    
    /**
     * @brief Extract protocol version from SSH identification string
     * @param identification SSH identification string
     * @return Extracted protocol version
     */
    static std::string extractProtocolVersion(const std::string& identification);
    
    /**
     * @brief Convert SSH handshake message type to string
     * @param messageType SSH handshake message type
     * @return Human-readable message type string
     */
    static std::string handshakeMessageTypeToString(uint8_t messageType);
    
    /**
     * @brief Extract message preview from SSH data
     * @param data The data to preview
     * @param dataLen Length of the data
     * @param maxPreviewLen Maximum length of preview
     * @return Preview string
     */
    static std::string extractMessagePreview(const uint8_t* data, size_t dataLen, size_t maxPreviewLen = 100);
    
    /**
     * @brief Clean message preview by removing sensitive information
     * @param preview The raw message preview
     * @return Cleaned preview string
     */
    static std::string cleanMessagePreview(const std::string& preview);
    
    /**
     * @brief Convert data to string with safe character handling
     * @param data The data to convert
     * @param dataLen Length of the data
     * @return String representation
     */
    static std::string dataToString(const uint8_t* data, size_t dataLen);
};

#endif // SSH_PARSER_H
