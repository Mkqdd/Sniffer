#ifndef FTP_PARSER_H
#define FTP_PARSER_H

#include "BaseParser.h"
#include "PacketMetadata.h"
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/TcpLayer.h>

class FTPParser : public BaseParser {
public:
    /**
     * @brief Parse FTP packet and fill metadata
     * @param packet The packet to parse
     * @param metadata The metadata structure to fill
     * @return true if parsing was successful
     */
    static bool parse(pcpp::Packet& packet, PacketMetadata& metadata);
    
private:
    /**
     * @brief Check if packet is FTP traffic (ports 20 or 21)
     * @param packet The packet to check
     * @return true if packet appears to be FTP
     */
    static bool isFTPPacket(pcpp::Packet& packet);
    
    /**
     * @brief Parse FTP control connection (port 21)
     * @param tcpLayer TCP layer containing FTP data
     * @param metadata The metadata structure to fill
     * @return true if parsing was successful
     */
    static bool parseControlConnection(pcpp::TcpLayer* tcpLayer, PacketMetadata& metadata);
    
    /**
     * @brief Parse FTP data connection (port 20)
     * @param tcpLayer TCP layer containing FTP data
     * @param metadata The metadata structure to fill
     * @return true if parsing was successful
     */
    static bool parseDataConnection(pcpp::TcpLayer* tcpLayer, PacketMetadata& metadata);
    
    /**
     * @brief Parse FTP command from client
     * @param data The TCP payload data
     * @param dataLen Length of the data
     * @param metadata The metadata structure to fill
     * @return true if parsing was successful
     */
    static bool parseCommand(const uint8_t* data, size_t dataLen, PacketMetadata& metadata);
    
    /**
     * @brief Parse FTP response from server
     * @param data The TCP payload data
     * @param dataLen Length of the data
     * @param metadata The metadata structure to fill
     * @return true if parsing was successful
     */
    static bool parseResponse(const uint8_t* data, size_t dataLen, PacketMetadata& metadata);
    
    /**
     * @brief Check if data looks like FTP command or response
     * @param data The data to check
     * @param dataLen Length of the data
     * @return true if data appears to be FTP control message
     */
    static bool isControlMessage(const uint8_t* data, size_t dataLen);
    
    /**
     * @brief Extract data preview for FTP data connection
     * @param data The data to preview
     * @param dataLen Length of the data
     * @param maxPreviewLen Maximum length of preview
     * @return Preview string
     */
    static std::string extractDataPreview(const uint8_t* data, size_t dataLen, size_t maxPreviewLen = 100);
    
    /**
     * @brief Clean data preview by removing non-printable characters
     * @param preview The raw data preview
     * @return Cleaned preview string
     */
    static std::string cleanDataPreview(const std::string& preview);
    
    /**
     * @brief Parse FTP command line
     * @param line The command line to parse
     * @param command Output command string
     * @param arguments Output arguments string
     * @return true if parsing was successful
     */
    static bool parseCommandLine(const std::string& line, std::string& command, std::string& arguments);
    
    /**
     * @brief Parse FTP response line
     * @param line The response line to parse
     * @param code Output response code
     * @param text Output response text
     * @return true if parsing was successful
     */
    static bool parseResponseLine(const std::string& line, uint16_t& code, std::string& text);
    
    /**
     * @brief Convert data to string with safe character handling
     * @param data The data to convert
     * @param dataLen Length of the data
     * @return String representation
     */
    static std::string dataToString(const uint8_t* data, size_t dataLen);
    
    /**
     * @brief Get FTP command description
     * @param command The FTP command
     * @return Description string
     */
    static std::string getCommandDescription(const std::string& command);
    
    /**
     * @brief Get FTP response code description
     * @param code The response code
     * @return Description string
     */
    static std::string getResponseCodeDescription(uint16_t code);

public:
    /**
     * @brief Format FTP command to string
     * @param ftp_meta The FTP metadata containing command
     * @return Formatted command string
     */
    static std::string getCommandString(const FTPMetadata& ftp_meta);

    /**
     * @brief Format FTP response to string
     * @param ftp_meta The FTP metadata containing response
     * @return Formatted response string
     */
    static std::string getResponseString(const FTPMetadata& ftp_meta);

    /**
     * @brief Get FTP type string
     * @param ftp_meta The FTP metadata containing type
     * @return FTP type string
     */
    static std::string getTypeString(const FTPMetadata& ftp_meta);

    /**
     * @brief Check if command is valid FTP command
     * @param cmd Command to check
     * @return true if valid FTP command
     */
    static bool isValidCommand(const std::string& cmd);

    /**
     * @brief Check if response code is valid FTP response code
     * @param code Response code to check
     * @return true if valid FTP response code
     */
    static bool isValidResponseCode(uint16_t code);
};

#endif // FTP_PARSER_H
