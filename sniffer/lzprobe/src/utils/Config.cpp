#include "utils/Config.h"
#include <iostream>
#include <getopt.h>
#include <filesystem>
#include <algorithm>

// Static constants
const std::vector<std::string> Config::VALID_PROTOCOLS = {
    "tcp", "udp", "vxlan", "vlan", "wifi", "gre", "http", "dns", "tls"
};

Config::Config() {
    // Default values are set in header file
}

bool Config::parseArguments(int argc, char* argv[]) {
    static struct option long_options[] = {
        {"input_file", required_argument, 0, 'i'},
        {"output_dir", required_argument, 0, 'o'},
        {"filter", required_argument, 0, 'f'},
        {"protocol", required_argument, 0, 'p'},
        {"max_packets", required_argument, 0, 'm'},
        {"verbose", no_argument, 0, 'v'},
        {"quiet", no_argument, 0, 'q'},
        {"statistics", no_argument, 0, 's'},
        {"json", no_argument, 0, 'j'},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0}
    };

    int option_index = 0;
    int c;

    while ((c = getopt_long(argc, argv, "i:o:f:p:m:vqsjhV", long_options, &option_index)) != -1) {
        switch (c) {
            case 'i':
                input_file = optarg;
                break;
            case 'o':
                output_dir = optarg;
                break;
            case 'f':
                filter = optarg;
                break;
            case 'p':
                protocol_filter = optarg;
                break;
            case 'm':
                try {
                    max_packets = std::stoi(optarg);
                } catch (const std::exception& e) {
                    std::cerr << "Error: Invalid max_packets value '" << optarg << "'\n";
                    return false;
                }
                break;
            case 'v':
                verbose = true;
                break;
            case 'q':
                quiet = true;
                break;
            case 's':
                statistics = true;
                break;
            case 'j':
                json_output = true;
                break;
            case 'h':
                help = true;
                return true;
            case 'V':
                version = true;
                return true;
            case '?':
            default:
                return false;
        }
    }

    return true;
}

bool Config::validate() const {
    if (!validateInputFile()) return false;
    if (!validateOutputDirectory()) return false;
    if (!validateProtocolFilter()) return false;
    if (!validateMaxPackets()) return false;
    return true;
}

bool Config::validateInputFile() const {
    if (input_file.empty()) {
        std::cerr << "Error: Input file is required\n\n";
        return false;
    }

    if (!std::filesystem::exists(input_file)) {
        std::cerr << "Error: Input file '" << input_file << "' does not exist\n";
        return false;
    }

    if (!std::filesystem::is_regular_file(input_file)) {
        std::cerr << "Error: Input file '" << input_file << "' is not a regular file\n";
        return false;
    }

    return true;
}

bool Config::validateOutputDirectory() const {
    if (!std::filesystem::exists(output_dir)) {
        try {
            std::filesystem::create_directories(output_dir);
            if (verbose) {
                std::cout << "Created output directory: " << output_dir << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "Error: Failed to create output directory '" << output_dir << "': " << e.what() << std::endl;
            return false;
        }
    }
    return true;
}

bool Config::validateProtocolFilter() const {
    if (protocol_filter.empty()) {
        return true;
    }

    auto it = std::find(VALID_PROTOCOLS.begin(), VALID_PROTOCOLS.end(), protocol_filter);
    if (it == VALID_PROTOCOLS.end()) {
        std::cerr << "Error: Invalid protocol filter '" << protocol_filter << "'\n";
        std::cerr << "Valid protocols: ";
        for (size_t i = 0; i < VALID_PROTOCOLS.size(); ++i) {
            if (i > 0) std::cerr << ", ";
            std::cerr << VALID_PROTOCOLS[i];
        }
        std::cerr << std::endl;
        return false;
    }

    return true;
}

bool Config::validateMaxPackets() const {
    if (max_packets <= 0 && max_packets != -1) {
        std::cerr << "Error: max_packets must be positive\n";
        return false;
    }
    return true;
}

void Config::printUsage(const char* program_name) const {
    std::cout << "Usage: " << program_name << " [OPTIONS] --input_file <pcap_file>\n\n"
              << "Options:\n"
              << "  -i, --input_file <file>     Input PCAP file to analyze (required)\n"
              << "  -o, --output_dir <dir>      Output directory for logs (default: logs)\n"
              << "                              Auto-creates subdirectory based on input filename\n"
              << "  -f, --filter <filter>       BPF filter expression\n"
              << "  -p, --protocol <protocol>   Filter by specific protocol (tcp, udp, vxlan, vlan, wifi, gre)\n"
              << "  -m, --max_packets <num>     Maximum number of packets to process\n"
              << "  -v, --verbose               Enable verbose output\n"
              << "  -q, --quiet                 Suppress normal output\n"
              << "  -s, --statistics            Show packet statistics\n"
              << "  -j, --json                  Output results in JSON format\n"
              << "  -h, --help                  Show this help message\n"
              << "  -V, --version               Show version information\n\n"
              << "Directory Structure:\n"
              << "  By default, output files are organized by protocol/filename:\n"
              << "    input.pcap        -> logs/input/\n"
              << "    http_test.pcap    -> logs/http/\n"
              << "    dataset/dns.pcap  -> logs/dns/\n\n"
              << "Examples:\n"
              << "  " << program_name << " -i dataset/http_test.pcap     # Output: logs/http/\n"
              << "  " << program_name << " -i dataset/dns_test.pcap -v -j # Output: logs/dns/\n"
              << "  " << program_name << " -i input.pcap -o custom       # Output: custom/input/\n"
              << "  " << program_name << " -i input.pcap -f \"tcp port 80\" -p tcp\n"
              << "  " << program_name << " -i input.pcap -m 1000 -j\n\n";
}

void Config::printVersion() const {
    std::cout << "LizProbe Network Protocol Parser v0.0.1\n"
              << "Copyright (c) 2025\n"
              << "A comprehensive network packet analysis tool\n\n";
}
