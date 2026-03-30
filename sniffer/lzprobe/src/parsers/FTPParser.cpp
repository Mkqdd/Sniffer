#include "parsers/FTPParser.h"
#include <pcapplusplus/TcpLayer.h>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <regex>

bool FTPParser::parse(pcpp::Packet& packet, PacketMetadata& metadata) {
    auto* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
    if (!tcpLayer) {
        return false;
    }

    // Check if this is FTP traffic (ports 20 or 21)
    if (!isFTPPacket(packet)) {
        return false;
    }

    // Set FTP presence flag
    metadata.has_ftp = true;

    uint16_t srcPort = tcpLayer->getSrcPort();
    uint16_t dstPort = tcpLayer->getDstPort();

    // Determine if this is control (21) or data (20) connection
    if (srcPort == 21 || dstPort == 21) {
        // Control connection
        metadata.ftp.is_control = true;
        metadata.ftp.type = "CONTROL";
        return parseControlConnection(tcpLayer, metadata);
    } else if (srcPort == 20 || dstPort == 20) {
        // Data connection
        metadata.ftp.is_data = true;
        metadata.ftp.type = "DATA";
        return parseDataConnection(tcpLayer, metadata);
    }

    return false;
}

bool FTPParser::isFTPPacket(pcpp::Packet& packet) {
    auto* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
    if (!tcpLayer) {
        return false;
    }

    uint16_t srcPort = tcpLayer->getSrcPort();
    uint16_t dstPort = tcpLayer->getDstPort();

    // Check for FTP control (21) or data (20) ports
    return (srcPort == 21 || dstPort == 21 || srcPort == 20 || dstPort == 20);
}

bool FTPParser::parseControlConnection(pcpp::TcpLayer* tcpLayer, PacketMetadata& metadata) {
    if (!tcpLayer) {
        return false;
    }

    // Get TCP payload
    uint8_t* payload = tcpLayer->getLayerPayload();
    size_t payloadLen = tcpLayer->getLayerPayloadSize();

    if (!payload || payloadLen == 0) {
        return true; // Empty payload is valid for FTP (e.g., ACK packets)
    }

    // Check if this looks like FTP control message
    if (!isControlMessage(payload, payloadLen)) {
        return false;
    }

    // Convert payload to string for parsing
    std::string data = dataToString(payload, payloadLen);

    // Try to parse as command first (client to server)
    if (parseCommand(payload, payloadLen, metadata)) {
        metadata.ftp.is_request = true;
        return true;
    }

    // Try to parse as response (server to client)
    if (parseResponse(payload, payloadLen, metadata)) {
        metadata.ftp.is_response = true;
        return true;
    }

    return true; // Still valid FTP, just couldn't parse the specific content
}

bool FTPParser::parseDataConnection(pcpp::TcpLayer* tcpLayer, PacketMetadata& metadata) {
    if (!tcpLayer) {
        return false;
    }

    // Get TCP payload
    uint8_t* payload = tcpLayer->getLayerPayload();
    size_t payloadLen = tcpLayer->getLayerPayloadSize();

    metadata.ftp.data_length = payloadLen;

    if (payload && payloadLen > 0) {
        // Extract data preview
        metadata.ftp.data_preview = extractDataPreview(payload, payloadLen);
        
        // Try to determine transfer mode based on content
        bool isBinary = false;
        for (size_t i = 0; i < std::min(payloadLen, static_cast<size_t>(100)); ++i) {
            if (payload[i] == 0 || (payload[i] < 32 && payload[i] != '\r' && payload[i] != '\n' && payload[i] != '\t')) {
                isBinary = true;
                break;
            }
        }
        
        metadata.ftp.transfer_mode = isBinary ? "BINARY" : "ASCII";
    }

    return true;
}

bool FTPParser::parseCommand(const uint8_t* data, size_t dataLen, PacketMetadata& metadata) {
    if (!data || dataLen == 0) {
        return false;
    }

    std::string line = dataToString(data, dataLen);
    
    // Remove trailing CRLF
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) {
        line.pop_back();
    }

    if (line.empty()) {
        return false;
    }

    // Check if this looks like a command (starts with alphabetic characters)
    if (!std::isalpha(line[0])) {
        return false;
    }

    std::string command, arguments;
    if (parseCommandLine(line, command, arguments)) {
        // Validate command
        if (FTPParser::isValidCommand(command)) {
            metadata.ftp.command = command;
            metadata.ftp.arguments = arguments;
            return true;
        }
    }

    return false;
}

bool FTPParser::parseResponse(const uint8_t* data, size_t dataLen, PacketMetadata& metadata) {
    if (!data || dataLen == 0) {
        return false;
    }

    std::string line = dataToString(data, dataLen);
    
    // Remove trailing CRLF
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) {
        line.pop_back();
    }

    if (line.length() < 3) {
        return false;
    }

    // Check if this looks like a response (starts with 3 digits)
    if (!std::isdigit(line[0]) || !std::isdigit(line[1]) || !std::isdigit(line[2])) {
        return false;
    }

    uint16_t code;
    std::string text;
    if (parseResponseLine(line, code, text)) {
        // Validate response code
        if (FTPParser::isValidResponseCode(code)) {
            metadata.ftp.response_code = code;
            metadata.ftp.response_text = text;
            return true;
        }
    }

    return false;
}

bool FTPParser::isControlMessage(const uint8_t* data, size_t dataLen) {
    if (!data || dataLen == 0) {
        return false;
    }

    // Convert first part to string for analysis
    size_t checkLen = std::min(dataLen, static_cast<size_t>(20));
    std::string start = dataToString(data, checkLen);

    // Check for FTP command pattern (letters followed by space or end)
    if (start.length() >= 3 && std::isalpha(start[0])) {
        bool allAlpha = true;
        for (size_t i = 0; i < std::min(start.length(), static_cast<size_t>(8)); ++i) {
            if (start[i] == ' ' || start[i] == '\r' || start[i] == '\n') {
                break;
            }
            if (!std::isalpha(start[i])) {
                allAlpha = false;
                break;
            }
        }
        if (allAlpha) {
            return true;
        }
    }

    // Check for FTP response pattern (3 digits)
    if (start.length() >= 3 && std::isdigit(start[0]) && std::isdigit(start[1]) && std::isdigit(start[2])) {
        return true;
    }

    return false;
}

std::string FTPParser::extractDataPreview(const uint8_t* data, size_t dataLen, size_t maxPreviewLen) {
    if (!data || dataLen == 0) {
        return "";
    }

    size_t previewLen = std::min(dataLen, maxPreviewLen);
    std::string preview;
    preview.reserve(previewLen);

    for (size_t i = 0; i < previewLen; ++i) {
        uint8_t byte = data[i];
        if (byte >= 32 && byte <= 126) {
            // Printable ASCII
            preview += static_cast<char>(byte);
        } else if (byte == '\n') {
            preview += "\\n";
        } else if (byte == '\r') {
            preview += "\\r";
        } else if (byte == '\t') {
            preview += "\\t";
        } else {
            // Non-printable, show as hex
            preview += "\\x" + std::to_string(byte);
        }
    }

    return cleanDataPreview(preview);
}

std::string FTPParser::cleanDataPreview(const std::string& preview) {
    std::string cleaned = preview;
    
    // Remove excessive whitespace
    std::regex excessive_whitespace("\\s{3,}");
    cleaned = std::regex_replace(cleaned, excessive_whitespace, " ... ");
    
    // Truncate if too long
    if (cleaned.length() > 200) {
        cleaned = cleaned.substr(0, 197) + "...";
    }
    
    return cleaned;
}

bool FTPParser::parseCommandLine(const std::string& line, std::string& command, std::string& arguments) {
    if (line.empty()) {
        return false;
    }

    std::istringstream iss(line);
    if (!(iss >> command)) {
        return false;
    }

    // Convert command to uppercase
    std::transform(command.begin(), command.end(), command.begin(), ::toupper);

    // Get remaining part as arguments
    std::string remaining;
    if (std::getline(iss, remaining)) {
        // Remove leading whitespace
        remaining.erase(0, remaining.find_first_not_of(" \t"));
        arguments = remaining;
    }

    return true;
}

bool FTPParser::parseResponseLine(const std::string& line, uint16_t& code, std::string& text) {
    if (line.length() < 3) {
        return false;
    }

    // Extract 3-digit code
    std::string codeStr = line.substr(0, 3);
    try {
        code = static_cast<uint16_t>(std::stoi(codeStr));
    } catch (const std::exception&) {
        return false;
    }

    // Extract text part (after space or dash)
    if (line.length() > 3) {
        if (line[3] == ' ' || line[3] == '-') {
            text = line.substr(4);
        } else {
            text = line.substr(3);
        }
        
        // Remove trailing whitespace
        while (!text.empty() && std::isspace(text.back())) {
            text.pop_back();
        }
    }

    return true;
}

std::string FTPParser::dataToString(const uint8_t* data, size_t dataLen) {
    if (!data || dataLen == 0) {
        return "";
    }

    std::string result;
    result.reserve(dataLen);

    for (size_t i = 0; i < dataLen; ++i) {
        uint8_t byte = data[i];
        // Only include printable characters and common whitespace
        if ((byte >= 32 && byte <= 126) || byte == '\r' || byte == '\n' || byte == '\t') {
            result += static_cast<char>(byte);
        } else {
            // Stop at first non-text character (likely binary data)
            break;
        }
    }

    return result;
}

std::string FTPParser::getCommandDescription(const std::string& command) {
    static const std::map<std::string, std::string> descriptions = {
        {"USER", "User name"},
        {"PASS", "Password"},
        {"ACCT", "Account"},
        {"CWD", "Change working directory"},
        {"CDUP", "Change to parent directory"},
        {"SMNT", "Structure mount"},
        {"QUIT", "Logout"},
        {"REIN", "Reinitialize"},
        {"PORT", "Data port"},
        {"PASV", "Passive mode"},
        {"TYPE", "Representation type"},
        {"STRU", "File structure"},
        {"MODE", "Transfer mode"},
        {"RETR", "Retrieve file"},
        {"STOR", "Store file"},
        {"STOU", "Store file uniquely"},
        {"APPE", "Append file"},
        {"ALLO", "Allocate"},
        {"REST", "Restart"},
        {"RNFR", "Rename from"},
        {"RNTO", "Rename to"},
        {"ABOR", "Abort"},
        {"DELE", "Delete file"},
        {"RMD", "Remove directory"},
        {"MKD", "Make directory"},
        {"PWD", "Print working directory"},
        {"LIST", "List files"},
        {"NLST", "Name list"},
        {"SITE", "Site parameters"},
        {"SYST", "System"},
        {"STAT", "Status"},
        {"HELP", "Help"},
        {"NOOP", "No operation"},
        {"FEAT", "Feature list"},
        {"OPTS", "Options"},
        {"SIZE", "File size"},
        {"MDTM", "File modification time"}
    };

    auto it = descriptions.find(command);
    return (it != descriptions.end()) ? it->second : "Unknown command";
}

std::string FTPParser::getResponseCodeDescription(uint16_t code) {
    static const std::map<uint16_t, std::string> descriptions = {
        {110, "Restart marker reply"},
        {120, "Service ready in nnn minutes"},
        {125, "Data connection already open; transfer starting"},
        {150, "File status okay; about to open data connection"},
        {200, "Command okay"},
        {202, "Command not implemented, superfluous at this site"},
        {211, "System status, or system help reply"},
        {212, "Directory status"},
        {213, "File status"},
        {214, "Help message"},
        {215, "NAME system type"},
        {220, "Service ready for new user"},
        {221, "Service closing control connection"},
        {225, "Data connection open; no transfer in progress"},
        {226, "Closing data connection"},
        {227, "Entering Passive Mode"},
        {230, "User logged in, proceed"},
        {250, "Requested file action okay, completed"},
        {257, "PATHNAME created"},
        {331, "User name okay, need password"},
        {332, "Need account for login"},
        {350, "Requested file action pending further information"},
        {421, "Service not available, closing control connection"},
        {425, "Can't open data connection"},
        {426, "Connection closed; transfer aborted"},
        {450, "Requested file action not taken"},
        {451, "Requested action aborted: local error in processing"},
        {452, "Requested action not taken"},
        {500, "Syntax error, command unrecognized"},
        {501, "Syntax error in parameters or arguments"},
        {502, "Command not implemented"},
        {503, "Bad sequence of commands"},
        {504, "Command not implemented for that parameter"},
        {530, "Not logged in"},
        {532, "Need account for storing files"},
        {550, "Requested action not taken"},
        {551, "Requested action aborted: page type unknown"},
        {552, "Requested file action aborted"},
        {553, "Requested action not taken"}
    };

    auto it = descriptions.find(code);
    if (it != descriptions.end()) {
        return it->second;
    }

    // Return category-based description for unknown codes
    int category = code / 100;
    switch (category) {
        case 1: return "Positive Preliminary reply";
        case 2: return "Positive Completion reply";
        case 3: return "Positive Intermediate reply";
        case 4: return "Transient Negative Completion reply";
        case 5: return "Permanent Negative Completion reply";
        default: return "Unknown response code";
    }
}

std::string FTPParser::getCommandString(const FTPMetadata& ftp_meta) {
    if (ftp_meta.command.empty()) return "N/A";
    std::string result = ftp_meta.command;
    if (!ftp_meta.arguments.empty()) {
        result += " " + ftp_meta.arguments;
    }
    return result;
}

std::string FTPParser::getResponseString(const FTPMetadata& ftp_meta) {
    if (ftp_meta.response_code == 0) return "N/A";
    std::string result = std::to_string(ftp_meta.response_code);
    if (!ftp_meta.response_text.empty()) {
        result += " " + ftp_meta.response_text;
    }
    return result;
}

std::string FTPParser::getTypeString(const FTPMetadata& ftp_meta) {
    return ftp_meta.type;
}

bool FTPParser::isValidCommand(const std::string& cmd) {
    // Common FTP commands
    static const std::vector<std::string> valid_commands = {
        "USER", "PASS", "ACCT", "CWD", "CDUP", "SMNT", "QUIT", "REIN",
        "PORT", "PASV", "TYPE", "STRU", "MODE", "RETR", "STOR", "STOU",
        "APPE", "ALLO", "REST", "RNFR", "RNTO", "ABOR", "DELE", "RMD",
        "MKD", "PWD", "LIST", "NLST", "SITE", "SYST", "STAT", "HELP",
        "NOOP", "FEAT", "OPTS", "SIZE", "MDTM"
    };
    
    return std::find(valid_commands.begin(), valid_commands.end(), cmd) != valid_commands.end();
}

bool FTPParser::isValidResponseCode(uint16_t code) {
    // FTP response codes are 3-digit numbers from 100-599
    return code >= 100 && code <= 599;
}
