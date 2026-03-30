#ifndef SMTP_PARSER_H
#define SMTP_PARSER_H

#include "BaseParser.h"
#include "PacketMetadata.h"
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/SmtpLayer.h>

class SMTPParser : public BaseParser {
public:
    /**
     * @brief Parse SMTP packet and fill metadata
     * @param packet The packet to parse
     * @param metadata The metadata structure to fill
     * @return true if parsing was successful
     */
    static bool parse(pcpp::Packet& packet, PacketMetadata& metadata);
    
private:
    /**
     * @brief Check if packet is SMTP traffic (ports 25, 465, or 587)
     * @param packet The packet to check
     * @return true if packet appears to be SMTP
     */
    static bool isSMTPPacket(pcpp::Packet& packet);
    
    /**
     * @brief Parse SMTP request from client
     * @param smtpLayer SMTP layer containing request data
     * @param metadata The metadata structure to fill
     * @return true if parsing was successful
     */
    static bool parseRequest(pcpp::SmtpRequestLayer* smtpLayer, PacketMetadata& metadata);
    
    /**
     * @brief Parse SMTP response from server
     * @param smtpLayer SMTP layer containing response data
     * @param metadata The metadata structure to fill
     * @return true if parsing was successful
     */
    static bool parseResponse(pcpp::SmtpResponseLayer* smtpLayer, PacketMetadata& metadata);
    
    /**
     * @brief Extract message preview from SMTP data
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
     * @brief Convert SMTP command enum to string
     * @param command The SMTP command enum
     * @return Command as string
     */
    static std::string commandToString(pcpp::SmtpRequestLayer::SmtpCommand command);
    
    /**
     * @brief Convert SMTP status code enum to string
     * @param statusCode The SMTP status code enum
     * @return Status code as string
     */
    static std::string statusCodeToString(pcpp::SmtpResponseLayer::SmtpStatusCode statusCode);
    
    /**
     * @brief Convert data to string with safe character handling
     * @param data The data to convert
     * @param dataLen Length of the data
     * @return String representation
     */
    static std::string dataToString(const uint8_t* data, size_t dataLen);
};

#endif // SMTP_PARSER_H
