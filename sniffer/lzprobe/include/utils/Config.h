#ifndef CONFIG_H
#define CONFIG_H

#include <string>
#include <vector>

class Config {
public:
    // Constructor
    Config();
    
    // Command line parsing
    bool parseArguments(int argc, char* argv[]);
    
    // Configuration validation
    bool validate() const;
    
    // Help and version
    void printUsage(const char* program_name) const;
    void printVersion() const;
    
    // Configuration getters
    const std::string& getInputFile() const { return input_file; }
    const std::string& getOutputDir() const { return output_dir; }
    const std::string& getFilter() const { return filter; }
    const std::string& getProtocolFilter() const { return protocol_filter; }
    int getMaxPackets() const { return max_packets; }
    bool isVerbose() const { return verbose; }
    bool isQuiet() const { return quiet; }
    bool showStatistics() const { return statistics; }
    bool isJsonOutput() const { return json_output; }
    bool showHelp() const { return help; }
    bool showVersion() const { return version; }
    
    // Configuration setters
    void setOutputDir(const std::string& dir) { output_dir = dir; }
    void setVerbose(bool v) { verbose = v; }
    void setQuiet(bool q) { quiet = q; }

private:
    // Configuration parameters
    std::string input_file;
    std::string output_dir = "logs";
    std::string filter = "";
    std::string protocol_filter = "";
    int max_packets = -1;  // -1 means unlimited
    bool verbose = false;
    bool quiet = false;
    bool statistics = false;
    bool json_output = false;
    bool help = false;
    bool version = false;
    
    // Validation helpers
    bool validateInputFile() const;
    bool validateOutputDirectory() const;
    bool validateProtocolFilter() const;
    bool validateMaxPackets() const;
    
    // Static constants
    static const std::vector<std::string> VALID_PROTOCOLS;
};

#endif // CONFIG_H