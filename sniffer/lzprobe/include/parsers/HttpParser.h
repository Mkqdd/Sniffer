#ifndef HTTP_PARSER_H
#define HTTP_PARSER_H

#include "BaseParser.h"
#include "PacketMetadata.h"
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/HttpLayer.h>

class HttpParser : public BaseParser {
public:
    /**
     * @brief Parse HTTP packet and fill metadata
     * @param packet The packet to parse
     * @param metadata The metadata structure to fill
     * @return true if parsing was successful
     */
    static bool parse(pcpp::Packet& packet, PacketMetadata& metadata);
    
    /**
     * @brief Parse HTTP header manually if PcapPlusPlus layer is not available
     * @param packet The packet to parse
     * @param metadata The metadata structure to fill
     * @return true if parsing was successful
     */
    static bool parseManually(pcpp::Packet& packet, PacketMetadata& metadata);
    
    /**
     * @brief Get human-readable description for HTTP method
     * @param method HTTP method string
     * @return Description string
     */
    static std::string getMethodDescription(const std::string& method);
    
    /**
     * @brief Get human-readable description for HTTP status code
     * @param statusCode HTTP status code
     * @return Description string
     */
    static std::string getStatusCodeDescription(uint16_t statusCode);
    
    /**
     * @brief Convert HTTP method enum to string
     * @param method HTTP method enum
     * @return HTTP method as string
     */
    static std::string httpMethodToString(pcpp::HttpRequestLayer::HttpMethod method);
    
    /**
     * @brief Convert HTTP version enum to string
     * @param version HTTP version enum
     * @return HTTP version as string
     */
    static std::string httpVersionToString(pcpp::HttpVersion version);
    
private:
    /**
     * @brief Parse HTTP request message
     * @param httpLayer The HTTP layer to parse
     * @param metadata The metadata structure to fill
     */
    static void parseHttpRequest(pcpp::HttpRequestLayer* httpLayer, PacketMetadata& metadata);
    
    /**
     * @brief Parse HTTP response message
     * @param httpLayer The HTTP layer to parse
     * @param metadata The metadata structure to fill
     */
    static void parseHttpResponse(pcpp::HttpResponseLayer* httpLayer, PacketMetadata& metadata);
    
    /**
     * @brief Parse HTTP headers
     * @param httpLayer The HTTP layer to parse
     * @param metadata The metadata structure to fill
     */
    static void parseHttpHeaders(pcpp::HttpRequestLayer* httpLayer, PacketMetadata& metadata);
    
    /**
     * @brief Parse HTTP headers
     * @param httpLayer The HTTP layer to parse
     * @param metadata The metadata structure to fill
     */
    static void parseHttpHeaders(pcpp::HttpResponseLayer* httpLayer, PacketMetadata& metadata);
    
    /**
     * @brief Parse HTTP body
     * @param httpLayer The HTTP layer to parse
     * @param metadata The metadata structure to fill
     */
    static void parseHttpBody(pcpp::HttpRequestLayer* httpLayer, PacketMetadata& metadata);
    
    /**
     * @brief Parse HTTP body
     * @param httpLayer The HTTP layer to parse
     * @param metadata The metadata structure to fill
     */
    static void parseHttpBody(pcpp::HttpResponseLayer* httpLayer, PacketMetadata& metadata);
    
    /**
     * @brief Extract common header fields to metadata
     * @param headers The HTTP headers map
     * @param metadata The metadata structure to fill
     */
    static void extractCommonHeaders(const std::map<std::string, std::string>& headers, PacketMetadata& metadata);
    
    /**
     * @brief Get TCP layer from packet for manual parsing
     * @param packet The packet to get TCP layer from
     * @return Pointer to TCP layer or nullptr if not found
     */
    static void* getTCPLayer(pcpp::Packet& packet);
    
    /**
     * @brief Clean HTTP body preview by removing non-printable characters and escaping special characters
     * @param preview The raw HTTP body preview
     * @return Cleaned preview string
     */
    static std::string cleanBodyPreview(const std::string& preview);
    
    /**
     * @brief Check if data looks like HTTP
     * @param data The data to check
     * @param dataLen The length of the data
     * @return true if data appears to be HTTP, false otherwise
     */
    static bool isHttpData(const uint8_t* data, size_t dataLen);
    
    /**
     * @brief Parse HTTP request line manually
     * @param data The HTTP data
     * @param dataLen The length of the data
     * @param metadata The metadata structure to fill
     * @return Number of bytes parsed, or -1 on error
     */
    static int parseRequestLine(const uint8_t* data, size_t dataLen, PacketMetadata& metadata);
    
    /**
     * @brief Parse HTTP response line manually
     * @param data The HTTP data
     * @param dataLen The length of the data
     * @param metadata The metadata structure to fill
     * @return Number of bytes parsed, or -1 on error
     */
    static int parseResponseLine(const uint8_t* data, size_t dataLen, PacketMetadata& metadata);
    
    /**
     * @brief Parse HTTP headers manually
     * @param data The HTTP data
     * @param dataLen The length of the data
     * @param metadata The metadata structure to fill
     * @return Number of bytes parsed, or -1 on error
     */
    static int parseHeaders(const uint8_t* data, size_t dataLen, PacketMetadata& metadata);
};

#endif // HTTP_PARSER_H
