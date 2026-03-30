#include "parsers/TelnetParser.h"
#include <pcapplusplus/TcpLayer.h>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <iomanip>

// Telnet protocol constant definitions
namespace {
    const uint8_t IAC = 0xFF;                    // Interpret As Command
    const uint8_t DONT = 0xFE;                   // Don't do option
    const uint8_t DO = 0xFD;                     // Do option
    const uint8_t WONT = 0xFC;                   // Won't do option
    const uint8_t WILL = 0xFB;                   // Will do option
    const uint8_t SB = 0xFA;                     // Subnegotiation Begin
    const uint8_t GA = 0xF9;                     // Go Ahead
    const uint8_t EL = 0xF8;                     // Erase Line
    const uint8_t EC = 0xF7;                     // Erase Character
    const uint8_t AYT = 0xF6;                    // Are You There
    const uint8_t AO = 0xF5;                     // Abort Output
    const uint8_t IP = 0xF4;                     // Interrupt Process
    const uint8_t BRK = 0xF3;                    // Break
    const uint8_t DM = 0xF2;                     // Data Mark
    const uint8_t NOP = 0xF1;                    // No Operation
    const uint8_t SE = 0xF0;                     // Subnegotiation End
    
    // Telnet option constants
    const uint8_t OPT_ECHO = 0x01;               // Echo
    const uint8_t OPT_SUPPRESS_GO_AHEAD = 0x03;  // Suppress Go Ahead
    const uint8_t OPT_STATUS = 0x05;             // Status
    const uint8_t OPT_TIMING_MARK = 0x06;        // Timing Mark
    const uint8_t OPT_TERMINAL_TYPE = 0x18;      // Terminal Type
    const uint8_t OPT_NAWS = 0x1F;               // Negotiate About Window Size
    const uint8_t OPT_TERMINAL_SPEED = 0x20;     // Terminal Speed
    const uint8_t OPT_TOGGLE_FLOW_CONTROL = 0x21; // Toggle Flow Control
    const uint8_t OPT_LINEMODE = 0x22;           // Linemode
    const uint8_t OPT_X_DISPLAY_LOCATION = 0x23; // X Display Location
    const uint8_t OPT_ENVIRONMENT = 0x24;        // Environment Variables
    const uint8_t OPT_ENVIRONMENT_OPTION = 0x27; // Environment Option
    const uint8_t OPT_START_TLS = 0x2E;          // Start TLS
}

bool TelnetParser::parse(pcpp::Packet& packet, PacketMetadata& metadata) {
    auto* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
    if (!tcpLayer) {
        return false;
    }

    // Check if this is a Telnet packet (port 23)
    if (!isTelnetPacket(packet)) {
        return false;
    }

    // Set Telnet presence flag
    metadata.has_telnet = true;

    // Parse Telnet data content
    return parseTelnetData(tcpLayer, metadata);
}

bool TelnetParser::isTelnetPacket(pcpp::Packet& packet) {
    auto* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
    if (!tcpLayer) {
        return false;
    }

    uint16_t srcPort = tcpLayer->getSrcPort();
    uint16_t dstPort = tcpLayer->getDstPort();

    // Check if this is a Telnet port (23)
    return (srcPort == 23 || dstPort == 23);
}

bool TelnetParser::parseTelnetData(pcpp::TcpLayer* tcpLayer, PacketMetadata& metadata) {
    if (!tcpLayer) {
        return false;
    }

    // Get TCP payload
    uint8_t* payload = tcpLayer->getLayerPayload();
    size_t payloadLen = tcpLayer->getLayerPayloadSize();

    if (!payload || payloadLen == 0) {
        // Empty payload is valid (e.g., ACK packet)
        metadata.telnet.type = "EMPTY";
        
        // Set session type (based on port)
        uint16_t srcPort = tcpLayer->getSrcPort();
        if (srcPort == 23) {
            metadata.telnet.session_type = "SERVER";
        } else {
            metadata.telnet.session_type = "CLIENT";
        }
        
        return true;
    }

    // Set total data length
    metadata.telnet.total_data_length = payloadLen;

    // Parse IAC command sequences
    size_t commandCount = parseIACCommands(payload, payloadLen, metadata);

    // Parse plain text data
    parseTextData(payload, payloadLen, metadata);

    // Determine data type
    if (commandCount > 0 && metadata.telnet.text_length > 0) {
        metadata.telnet.type = "MIXED";
    } else if (commandCount > 0) {
        metadata.telnet.type = "CONTROL";
    } else if (metadata.telnet.text_length > 0) {
        metadata.telnet.type = "TEXT";
    } else {
        metadata.telnet.type = "UNKNOWN";
    }

    // Set control flags
    metadata.telnet.is_control = (commandCount > 0);
    metadata.telnet.is_text = (metadata.telnet.text_length > 0);

    // Try to determine session type (based on port)
    uint16_t srcPort = tcpLayer->getSrcPort();
    if (srcPort == 23) {
        metadata.telnet.session_type = "SERVER";
    } else {
        metadata.telnet.session_type = "CLIENT";
    }

    return true;
}

size_t TelnetParser::parseIACCommands(const uint8_t* data, size_t dataLen, PacketMetadata& metadata) {
    if (!data || dataLen == 0) {
        return 0;
    }

    size_t commandCount = 0;
    size_t i = 0;

    while (i < dataLen) {
        // Find IAC byte
        if (data[i] == IAC && i + 1 < dataLen) {
            uint8_t cmd = data[i + 1];
            std::string commandStr;

            // Parse command type
            switch (cmd) {
                case DO:
                case DONT:
                case WILL:
                case WONT:
                    if (i + 2 < dataLen) {
                        uint8_t option = data[i + 2];
                        commandStr = commandToString(cmd) + " " + optionToString(option);
                        i += 3; // Skip IAC + command + option
                    } else {
                        commandStr = commandToString(cmd) + " (incomplete)";
                        i += 2; // Skip IAC + command
                    }
                    break;

                case SB: // Subnegotiation begin
                    commandStr = commandToString(cmd);
                    i += 2; // Skip IAC + SB
                    // Find SE (subnegotiation end)
                    while (i < dataLen - 1) {
                        if (data[i] == IAC && data[i + 1] == SE) {
                            i += 2; // Skip IAC + SE
                            break;
                        }
                        i++;
                    }
                    break;

                case SE: // Subnegotiation end
                    commandStr = commandToString(cmd);
                    i += 2;
                    break;

                case GA:
                case EL:
                case EC:
                case AYT:
                case AO:
                case IP:
                case BRK:
                case DM:
                case NOP:
                    commandStr = commandToString(cmd);
                    i += 2; // Skip IAC + command
                    break;

                default:
                    // Unknown command
                    commandStr = "UNKNOWN(" + std::to_string(cmd) + ")";
                    i += 2;
                    break;
            }

            if (!commandStr.empty()) {
                metadata.telnet.commands.push_back(commandStr);
                commandCount++;
            }

            metadata.telnet.iac_sequences++;
                    } else {
                i++; // Move to next byte
            }
    }

    metadata.telnet.command_count = commandCount;
    
    // Generate command summary
    if (commandCount > 0) {
        std::ostringstream oss;
        oss << "Found " << commandCount << " IAC command(s): ";
        for (size_t j = 0; j < std::min(commandCount, static_cast<size_t>(5)); ++j) {
            if (j > 0) oss << ", ";
            oss << metadata.telnet.commands[j];
        }
        if (commandCount > 5) {
            oss << ", ...";
        }
        metadata.telnet.command_summary = oss.str();
    }

    return commandCount;
}

void TelnetParser::parseTextData(const uint8_t* data, size_t dataLen, PacketMetadata& metadata) {
    if (!data || dataLen == 0) {
        return;
    }

    std::string textData;
    size_t textLength = 0;
    size_t i = 0;

    while (i < dataLen) {
        if (data[i] == IAC) {
            // Skip IAC sequence
            if (i + 1 < dataLen) {
                uint8_t cmd = data[i + 1];
                switch (cmd) {
                    case DO:
                    case DONT:
                    case WILL:
                    case WONT:
                        if (i + 2 < dataLen) {
                                                    i += 3; // Skip IAC + command + option
                    } else {
                        i += 2; // Skip IAC + command
                    }
                        break;

                                    case SB: // Subnegotiation begin
                    i += 2; // Skip IAC + SB
                    // Find SE (subnegotiation end)
                    while (i < dataLen - 1) {
                        if (data[i] == IAC && data[i + 1] == SE) {
                            i += 2; // Skip IAC + SE
                            break;
                        }
                        i++;
                    }
                    break;

                case SE: // Subnegotiation end
                        i += 2;
                        break;

                    default:
                                            i += 2; // Skip IAC + command
                    break;
                }
            } else {
                i++; // Skip IAC
            }
        } else {
            // Plain text character
            if (data[i] >= 32 || data[i] == '\r' || data[i] == '\n' || data[i] == '\t') {
                textData += static_cast<char>(data[i]);
                textLength++;
            }
            i++;
        }
    }

    metadata.telnet.text_length = textLength;
    metadata.telnet.filtered_text = textData;
    metadata.telnet.text_preview = extractDataPreview(
        reinterpret_cast<const uint8_t*>(textData.c_str()), 
        textData.length()
    );
    metadata.telnet.text_sequences = (textLength > 0) ? 1 : 0;
}

std::string TelnetParser::commandToString(uint8_t cmd) {
    switch (cmd) {
        case DO: return "DO";
        case DONT: return "DONT";
        case WILL: return "WILL";
        case WONT: return "WONT";
        case SB: return "SB";
        case GA: return "GA";
        case EL: return "EL";
        case EC: return "EC";
        case AYT: return "AYT";
        case AO: return "AO";
        case IP: return "IP";
        case BRK: return "BRK";
        case DM: return "DM";
        case NOP: return "NOP";
        case SE: return "SE";
        default: {
            std::ostringstream oss;
            oss << "CMD(0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(cmd) << ")";
            return oss.str();
        }
    }
}

std::string TelnetParser::optionToString(uint8_t option) {
    switch (option) {
        case OPT_ECHO: return "ECHO";
        case OPT_SUPPRESS_GO_AHEAD: return "SUPPRESS_GO_AHEAD";
        case OPT_STATUS: return "STATUS";
        case OPT_TIMING_MARK: return "TIMING_MARK";
        case OPT_TERMINAL_TYPE: return "TERMINAL_TYPE";
        case OPT_NAWS: return "NAWS";
        case OPT_TERMINAL_SPEED: return "TERMINAL_SPEED";
        case OPT_TOGGLE_FLOW_CONTROL: return "TOGGLE_FLOW_CONTROL";
        case OPT_LINEMODE: return "LINEMODE";
        case OPT_X_DISPLAY_LOCATION: return "X_DISPLAY_LOCATION";
        case OPT_ENVIRONMENT: return "ENVIRONMENT";
        case OPT_ENVIRONMENT_OPTION: return "ENVIRONMENT_OPTION";
        case OPT_START_TLS: return "START_TLS";
        default: {
            std::ostringstream oss;
            oss << "OPT(0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(option) << ")";
            return oss.str();
        }
    }
}

std::string TelnetParser::dataToString(const uint8_t* data, size_t dataLen) {
    if (!data || dataLen == 0) {
        return "";
    }

    std::string result;
    for (size_t i = 0; i < dataLen; ++i) {
        if (data[i] >= 32 || data[i] == '\r' || data[i] == '\n' || data[i] == '\t') {
            result += static_cast<char>(data[i]);
        } else {
            // Convert control characters to readable form
            std::ostringstream oss;
            oss << "\\x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
            result += oss.str();
        }
    }
    return result;
}

std::string TelnetParser::extractDataPreview(const uint8_t* data, size_t dataLen, size_t maxLen) {
    if (!data || dataLen == 0) {
        return "";
    }

    std::string preview = dataToString(data, std::min(dataLen, maxLen));
    
    if (dataLen > maxLen) {
        preview += "...";
    }

    return preview;
}

