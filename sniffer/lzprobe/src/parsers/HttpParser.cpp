#include "parsers/HttpParser.h"
#include "BaseParser.h"
#include <pcapplusplus/HttpLayer.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>
#include <netinet/in.h>
#include <cstring>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cctype>

// Helper function to clean HTTP body preview
std::string HttpParser::cleanBodyPreview(const std::string& preview) {
    std::string cleanPreview;
    for (char c : preview) {
        if (std::isprint(c) || c == '\n' || c == '\r' || c == '\t') {
            if (c == '\n') cleanPreview += "\\n";
            else if (c == '\r') cleanPreview += "\\r";
            else if (c == '\t') cleanPreview += "\\t";
            else cleanPreview += c;
        } else {
            cleanPreview += ".";
        }
    }
    return cleanPreview;
}

bool HttpParser::parse(pcpp::Packet& packet, PacketMetadata& metadata) {
    // First try to use PcapPlusPlus HTTP request layer
    auto* httpRequestLayer = packet.getLayerOfType<pcpp::HttpRequestLayer>();
    if (httpRequestLayer) {
        metadata.has_http = true;
        metadata.http.is_request = true;
        parseHttpRequest(httpRequestLayer, metadata);
        return true;
    }
    
    // Try HTTP response layer
    auto* httpResponseLayer = packet.getLayerOfType<pcpp::HttpResponseLayer>();
    if (httpResponseLayer) {
        metadata.has_http = true;
        metadata.http.is_response = true;
        parseHttpResponse(httpResponseLayer, metadata);
        return true;
    }
    
    // Fall back to manual parsing
    return parseManually(packet, metadata);
}

bool HttpParser::parseManually(pcpp::Packet& packet, PacketMetadata& metadata) {
    // Get TCP layer to find HTTP payload
    auto* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
    if (!tcpLayer) {
        return false;
    }
    
    // Get HTTP payload
    const uint8_t* httpData = tcpLayer->getLayerPayload();
    size_t httpDataLen = tcpLayer->getLayerPayloadSize();
    
    if (!httpData || httpDataLen < 4) {
        return false; // Minimum HTTP message size
    }
    
    // Check if this looks like HTTP data
    if (!isHttpData(httpData, httpDataLen)) {
        return false;
    }
    
    // Mark that HTTP is present
    metadata.has_http = true;
    
    // Determine if this is a request or response
    bool isRequest = false;
    bool isResponse = false;
    
    // Check for HTTP request methods
    if (httpDataLen >= 3) {
        std::string start(reinterpret_cast<const char*>(httpData), 3);
        if (start == "GET" || start == "POS" || start == "PUT" || start == "DEL" || 
            start == "HEA" || start == "OPT" || start == "PAT" || start == "TRA") {
            isRequest = true;
        }
    }
    
    // Check for HTTP response
    if (httpDataLen >= 4) {
        std::string start(reinterpret_cast<const char*>(httpData), 4);
        if (start == "HTTP") {
            isResponse = true;
        }
    }
    
    if (!isRequest && !isResponse) {
        return false; // Not a valid HTTP message
    }
    
    metadata.http.is_request = isRequest;
    metadata.http.is_response = isResponse;
    metadata.http.type = isRequest ? "REQUEST" : "RESPONSE";
    
    // Parse the first line (request line or status line)
    int bytesParsed = 0;
    if (isRequest) {
        bytesParsed = parseRequestLine(httpData, httpDataLen, metadata);
    } else {
        bytesParsed = parseResponseLine(httpData, httpDataLen, metadata);
    }
    
    if (bytesParsed < 0) {
        return false;
    }
    
    // Parse headers
    int headerBytesParsed = parseHeaders(httpData + bytesParsed, httpDataLen - bytesParsed, metadata);
    if (headerBytesParsed < 0) {
        return false;
    }
    
    // Parse body if present
    size_t totalParsed = bytesParsed + headerBytesParsed;
    if (totalParsed < httpDataLen) {
        metadata.http.body_length = httpDataLen - totalParsed;
        if (metadata.http.body_length > 0) {
            size_t previewSize = std::min(metadata.http.body_length, static_cast<size_t>(100));
            std::string preview = std::string(
                reinterpret_cast<const char*>(httpData + totalParsed), 
                previewSize
            );
            
            metadata.http.body_preview = cleanBodyPreview(preview);
        }
    }
    
    return true;
}

std::string HttpParser::httpMethodToString(pcpp::HttpRequestLayer::HttpMethod method) {
    switch (method) {
        case pcpp::HttpRequestLayer::HttpGET: return "GET";
        case pcpp::HttpRequestLayer::HttpHEAD: return "HEAD";
        case pcpp::HttpRequestLayer::HttpPOST: return "POST";
        case pcpp::HttpRequestLayer::HttpPUT: return "PUT";
        case pcpp::HttpRequestLayer::HttpDELETE: return "DELETE";
        case pcpp::HttpRequestLayer::HttpTRACE: return "TRACE";
        case pcpp::HttpRequestLayer::HttpOPTIONS: return "OPTIONS";
        case pcpp::HttpRequestLayer::HttpCONNECT: return "CONNECT";
        case pcpp::HttpRequestLayer::HttpPATCH: return "PATCH";
        case pcpp::HttpRequestLayer::HttpMethodUnknown:
        default: return "UNKNOWN";
    }
}

std::string HttpParser::httpVersionToString(pcpp::HttpVersion version) {
    switch (version) {
        case pcpp::HttpVersion::ZeroDotNine: return "HTTP/0.9";
        case pcpp::HttpVersion::OneDotZero: return "HTTP/1.0";
        case pcpp::HttpVersion::OneDotOne: return "HTTP/1.1";
        default: return "HTTP/UNKNOWN";
    }
}

void HttpParser::parseHttpRequest(pcpp::HttpRequestLayer* httpLayer, PacketMetadata& metadata) {
    if (!httpLayer) {
        return;
    }
    
    // Set HTTP type
    metadata.http.is_request = true;
    metadata.http.is_response = false;
    metadata.http.type = "REQUEST";
    
    // Parse request line
    metadata.http.method = httpMethodToString(httpLayer->getFirstLine()->getMethod());
    metadata.http.uri = httpLayer->getFirstLine()->getUri();
    metadata.http.version = httpVersionToString(httpLayer->getFirstLine()->getVersion());
    
    // Parse headers
    parseHttpHeaders(httpLayer, metadata);
    
    // Parse body
    parseHttpBody(httpLayer, metadata);
}

void HttpParser::parseHttpResponse(pcpp::HttpResponseLayer* httpLayer, PacketMetadata& metadata) {
    if (!httpLayer) {
        return;
    }
    
    // Set HTTP type
    metadata.http.is_request = false;
    metadata.http.is_response = true;
    metadata.http.type = "RESPONSE";
    
    // Parse status line
    metadata.http.status_code = httpLayer->getFirstLine()->getStatusCode();
    metadata.http.status_text = httpLayer->getFirstLine()->getStatusCodeString();
    metadata.http.version = httpVersionToString(httpLayer->getFirstLine()->getVersion());
    
    // Parse headers
    parseHttpHeaders(httpLayer, metadata);
    
    // Parse body
    parseHttpBody(httpLayer, metadata);
}

void HttpParser::parseHttpHeaders(pcpp::HttpRequestLayer* httpLayer, PacketMetadata& metadata) {
    if (!httpLayer) {
        return;
    }
    
    // Get all headers
    pcpp::HeaderField* headerField = httpLayer->getFirstField();
    while (headerField != nullptr) {
        std::string headerName = headerField->getFieldName();
        std::string headerValue = headerField->getFieldValue();
        
        // Convert to lowercase for case-insensitive comparison
        std::string lowerName = headerName;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
        
        // Store in headers map
        metadata.http.headers[lowerName] = headerValue;
        
        // Store in specific fields for common headers
        if (lowerName == "host") {
            metadata.http.host = headerValue;
        } else if (lowerName == "user-agent") {
            metadata.http.user_agent = headerValue;
        } else if (lowerName == "content-type") {
            metadata.http.content_type = headerValue;
        } else if (lowerName == "content-length") {
            metadata.http.content_length = headerValue;
        } else if (lowerName == "connection") {
            metadata.http.connection = headerValue;
        } else if (lowerName == "accept") {
            metadata.http.accept = headerValue;
        } else if (lowerName == "accept-encoding") {
            metadata.http.accept_encoding = headerValue;
        } else if (lowerName == "accept-language") {
            metadata.http.accept_language = headerValue;
        } else if (lowerName == "cache-control") {
            metadata.http.cache_control = headerValue;
        } else if (lowerName == "cookie") {
            metadata.http.cookie = headerValue;
        } else if (lowerName == "set-cookie") {
            metadata.http.set_cookie = headerValue;
        } else if (lowerName == "referer") {
            metadata.http.referer = headerValue;
        } else if (lowerName == "location") {
            metadata.http.location = headerValue;
        } else if (lowerName == "server") {
            metadata.http.server = headerValue;
        } else if (lowerName == "date") {
            metadata.http.date = headerValue;
        } else if (lowerName == "last-modified") {
            metadata.http.last_modified = headerValue;
        } else if (lowerName == "etag") {
            metadata.http.etag = headerValue;
        } else if (lowerName == "expires") {
            metadata.http.expires = headerValue;
        }
        
        headerField = httpLayer->getNextField(headerField);
    }
}

void HttpParser::parseHttpHeaders(pcpp::HttpResponseLayer* httpLayer, PacketMetadata& metadata) {
    if (!httpLayer) {
        return;
    }
    
    // Get all headers
    pcpp::HeaderField* headerField = httpLayer->getFirstField();
    while (headerField != nullptr) {
        std::string headerName = headerField->getFieldName();
        std::string headerValue = headerField->getFieldValue();
        
        // Convert to lowercase for case-insensitive comparison
        std::string lowerName = headerName;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
        
        // Store in headers map
        metadata.http.headers[lowerName] = headerValue;
        
        // Store in specific fields for common headers
        if (lowerName == "host") {
            metadata.http.host = headerValue;
        } else if (lowerName == "user-agent") {
            metadata.http.user_agent = headerValue;
        } else if (lowerName == "content-type") {
            metadata.http.content_type = headerValue;
        } else if (lowerName == "content-length") {
            metadata.http.content_length = headerValue;
        } else if (lowerName == "connection") {
            metadata.http.connection = headerValue;
        } else if (lowerName == "accept") {
            metadata.http.accept = headerValue;
        } else if (lowerName == "accept-encoding") {
            metadata.http.accept_encoding = headerValue;
        } else if (lowerName == "accept-language") {
            metadata.http.accept_language = headerValue;
        } else if (lowerName == "cache-control") {
            metadata.http.cache_control = headerValue;
        } else if (lowerName == "cookie") {
            metadata.http.cookie = headerValue;
        } else if (lowerName == "set-cookie") {
            metadata.http.set_cookie = headerValue;
        } else if (lowerName == "referer") {
            metadata.http.referer = headerValue;
        } else if (lowerName == "location") {
            metadata.http.location = headerValue;
        } else if (lowerName == "server") {
            metadata.http.server = headerValue;
        } else if (lowerName == "date") {
            metadata.http.date = headerValue;
        } else if (lowerName == "last-modified") {
            metadata.http.last_modified = headerValue;
        } else if (lowerName == "etag") {
            metadata.http.etag = headerValue;
        } else if (lowerName == "expires") {
            metadata.http.expires = headerValue;
        }
        
        headerField = httpLayer->getNextField(headerField);
    }
}

void HttpParser::parseHttpBody(pcpp::HttpRequestLayer* httpLayer, PacketMetadata& metadata) {
    if (!httpLayer) {
        return;
    }
    
    // Get body data
    const uint8_t* bodyData = httpLayer->getLayerPayload();
    size_t bodyLen = httpLayer->getLayerPayloadSize();
    
    if (bodyData && bodyLen > 0) {
        metadata.http.body_length = bodyLen;
        
        // Create preview (first 100 characters)
        size_t previewSize = std::min(bodyLen, static_cast<size_t>(100));
        std::string preview = std::string(
            reinterpret_cast<const char*>(bodyData), 
            previewSize
        );
        
        metadata.http.body_preview = cleanBodyPreview(preview);
    }
}

void HttpParser::parseHttpBody(pcpp::HttpResponseLayer* httpLayer, PacketMetadata& metadata) {
    if (!httpLayer) {
        return;
    }
    
    // Get body data
    const uint8_t* bodyData = httpLayer->getLayerPayload();
    size_t bodyLen = httpLayer->getLayerPayloadSize();
    
    if (bodyData && bodyLen > 0) {
        metadata.http.body_length = bodyLen;
        
        // Create preview (first 100 characters)
        size_t previewSize = std::min(bodyLen, static_cast<size_t>(100));
        std::string preview = std::string(
            reinterpret_cast<const char*>(bodyData), 
            previewSize
        );
        
        metadata.http.body_preview = cleanBodyPreview(preview);
    }
}

void HttpParser::extractCommonHeaders(const std::map<std::string, std::string>& headers, PacketMetadata& metadata) {
    for (const auto& header : headers) {
        std::string lowerName = header.first;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
        
        if (lowerName == "host") {
            metadata.http.host = header.second;
        } else if (lowerName == "user-agent") {
            metadata.http.user_agent = header.second;
        } else if (lowerName == "content-type") {
            metadata.http.content_type = header.second;
        } else if (lowerName == "content-length") {
            metadata.http.content_length = header.second;
        } else if (lowerName == "connection") {
            metadata.http.connection = header.second;
        } else if (lowerName == "accept") {
            metadata.http.accept = header.second;
        } else if (lowerName == "accept-encoding") {
            metadata.http.accept_encoding = header.second;
        } else if (lowerName == "accept-language") {
            metadata.http.accept_language = header.second;
        } else if (lowerName == "cache-control") {
            metadata.http.cache_control = header.second;
        } else if (lowerName == "cookie") {
            metadata.http.cookie = header.second;
        } else if (lowerName == "set-cookie") {
            metadata.http.set_cookie = header.second;
        } else if (lowerName == "referer") {
            metadata.http.referer = header.second;
        } else if (lowerName == "location") {
            metadata.http.location = header.second;
        } else if (lowerName == "server") {
            metadata.http.server = header.second;
        } else if (lowerName == "date") {
            metadata.http.date = header.second;
        } else if (lowerName == "last-modified") {
            metadata.http.last_modified = header.second;
        } else if (lowerName == "etag") {
            metadata.http.etag = header.second;
        } else if (lowerName == "expires") {
            metadata.http.expires = header.second;
        }
    }
}

void* HttpParser::getTCPLayer(pcpp::Packet& packet) {
    return packet.getLayerOfType<pcpp::TcpLayer>();
}

bool HttpParser::isHttpData(const uint8_t* data, size_t dataLen) {
    if (!data || dataLen < 4) {
        return false;
    }
    
    // Check for HTTP request methods
    if (dataLen >= 3) {
        std::string start(reinterpret_cast<const char*>(data), 3);
        if (start == "GET" || start == "POS" || start == "PUT" || start == "DEL" || 
            start == "HEA" || start == "OPT" || start == "PAT" || start == "TRA") {
            return true;
        }
    }
    
    // Check for HTTP response
    if (dataLen >= 4) {
        std::string start(reinterpret_cast<const char*>(data), 4);
        if (start == "HTTP") {
            return true;
        }
    }
    
    return false;
}

int HttpParser::parseRequestLine(const uint8_t* data, size_t dataLen, PacketMetadata& metadata) {
    if (!data || dataLen < 4) {
        return -1;
    }
    
    // Find the end of the first line
    const uint8_t* lineEnd = static_cast<const uint8_t*>(memchr(data, '\n', dataLen));
    if (!lineEnd) {
        return -1;
    }
    
    std::string requestLine(reinterpret_cast<const char*>(data), lineEnd - data);
    
    // Remove carriage return if present
    if (!requestLine.empty() && requestLine.back() == '\r') {
        requestLine.pop_back();
    }
    
    // Parse method, URI, and version
    std::istringstream iss(requestLine);
    std::string method, uri, version;
    
    if (!(iss >> method >> uri >> version)) {
        return -1;
    }
    
    metadata.http.method = method;
    metadata.http.uri = uri;
    metadata.http.version = version;
    
    return lineEnd - data + 1; // Include the newline
}

int HttpParser::parseResponseLine(const uint8_t* data, size_t dataLen, PacketMetadata& metadata) {
    if (!data || dataLen < 4) {
        return -1;
    }
    
    // Find the end of the first line
    const uint8_t* lineEnd = static_cast<const uint8_t*>(memchr(data, '\n', dataLen));
    if (!lineEnd) {
        return -1;
    }
    
    std::string responseLine(reinterpret_cast<const char*>(data), lineEnd - data);
    
    // Remove carriage return if present
    if (!responseLine.empty() && responseLine.back() == '\r') {
        responseLine.pop_back();
    }
    
    // Parse version, status code, and status text
    std::istringstream iss(responseLine);
    std::string version, statusCodeStr, statusText;
    
    if (!(iss >> version >> statusCodeStr)) {
        return -1;
    }
    
    // Get the rest as status text
    size_t pos = responseLine.find(statusCodeStr);
    if (pos != std::string::npos) {
        pos += statusCodeStr.length();
        while (pos < responseLine.length() && responseLine[pos] == ' ') {
            pos++;
        }
        statusText = responseLine.substr(pos);
    }
    
    metadata.http.version = version;
    metadata.http.status_code = static_cast<uint16_t>(std::stoi(statusCodeStr));
    metadata.http.status_text = statusText;
    
    return lineEnd - data + 1; // Include the newline
}

int HttpParser::parseHeaders(const uint8_t* data, size_t dataLen, PacketMetadata& metadata) {
    if (!data || dataLen < 2) {
        return -1;
    }
    
    const uint8_t* current = data;
    const uint8_t* end = data + dataLen;
    int totalParsed = 0;
    
    while (current < end) {
        // Find the end of the current line
        const uint8_t* lineEnd = static_cast<const uint8_t*>(memchr(current, '\n', end - current));
        if (!lineEnd) {
            break;
        }
        
        std::string line(reinterpret_cast<const char*>(current), lineEnd - current);
        
        // Remove carriage return if present
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        
        // Empty line indicates end of headers
        if (line.empty()) {
            totalParsed += lineEnd - current + 1;
            break;
        }
        
        // Parse header field
        size_t colonPos = line.find(':');
        if (colonPos != std::string::npos) {
            std::string headerName = line.substr(0, colonPos);
            std::string headerValue = line.substr(colonPos + 1);
            
            // Remove leading whitespace from value
            while (!headerValue.empty() && headerValue[0] == ' ') {
                headerValue = headerValue.substr(1);
            }
            
            // Convert to lowercase for case-insensitive comparison
            std::string lowerName = headerName;
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
            
            // Store in headers map
            metadata.http.headers[lowerName] = headerValue;
            
            // Store in specific fields for common headers
            if (lowerName == "host") {
                metadata.http.host = headerValue;
            } else if (lowerName == "user-agent") {
                metadata.http.user_agent = headerValue;
            } else if (lowerName == "content-type") {
                metadata.http.content_type = headerValue;
            } else if (lowerName == "content-length") {
                metadata.http.content_length = headerValue;
            } else if (lowerName == "connection") {
                metadata.http.connection = headerValue;
            } else if (lowerName == "accept") {
                metadata.http.accept = headerValue;
            } else if (lowerName == "accept-encoding") {
                metadata.http.accept_encoding = headerValue;
            } else if (lowerName == "accept-language") {
                metadata.http.accept_language = headerValue;
            } else if (lowerName == "cache-control") {
                metadata.http.cache_control = headerValue;
            } else if (lowerName == "cookie") {
                metadata.http.cookie = headerValue;
            } else if (lowerName == "set-cookie") {
                metadata.http.set_cookie = headerValue;
            } else if (lowerName == "referer") {
                metadata.http.referer = headerValue;
            } else if (lowerName == "location") {
                metadata.http.location = headerValue;
            } else if (lowerName == "server") {
                metadata.http.server = headerValue;
            } else if (lowerName == "date") {
                metadata.http.date = headerValue;
            } else if (lowerName == "last-modified") {
                metadata.http.last_modified = headerValue;
            } else if (lowerName == "etag") {
                metadata.http.etag = headerValue;
            } else if (lowerName == "expires") {
                metadata.http.expires = headerValue;
            }
        }
        
        totalParsed += lineEnd - current + 1;
        current = lineEnd + 1;
    }
    
    return totalParsed;
}

std::string HttpParser::getMethodDescription(const std::string& method) {
    if (method == "GET") return "GET - Retrieve resource";
    if (method == "POST") return "POST - Create resource";
    if (method == "PUT") return "PUT - Update resource";
    if (method == "DELETE") return "DELETE - Delete resource";
    if (method == "HEAD") return "HEAD - Get headers only";
    if (method == "OPTIONS") return "OPTIONS - Get allowed methods";
    if (method == "PATCH") return "PATCH - Partial update";
    if (method == "TRACE") return "TRACE - Echo request";
    return "Unknown method: " + method;
}

std::string HttpParser::getStatusCodeDescription(uint16_t statusCode) {
    switch (statusCode) {
        case 100: return "100 Continue";
        case 101: return "101 Switching Protocols";
        case 200: return "200 OK";
        case 201: return "201 Created";
        case 202: return "202 Accepted";
        case 204: return "204 No Content";
        case 301: return "301 Moved Permanently";
        case 302: return "302 Found";
        case 304: return "304 Not Modified";
        case 400: return "400 Bad Request";
        case 401: return "401 Unauthorized";
        case 403: return "403 Forbidden";
        case 404: return "404 Not Found";
        case 405: return "405 Method Not Allowed";
        case 500: return "500 Internal Server Error";
        case 501: return "501 Not Implemented";
        case 502: return "502 Bad Gateway";
        case 503: return "503 Service Unavailable";
        case 504: return "504 Gateway Timeout";
        default: return std::to_string(statusCode) + " Unknown";
    }
}
