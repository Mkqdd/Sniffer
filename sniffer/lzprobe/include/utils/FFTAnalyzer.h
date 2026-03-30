#ifndef FFT_ANALYZER_H
#define FFT_ANALYZER_H

#include <vector>
#include <complex>
#include <cmath>
#include <algorithm>
#include <fftw3.h>

// Structure to hold FFT analysis results
struct FFTResult {
    std::vector<std::complex<double>> fft_coefficients;  // Raw FFT coefficients
    std::vector<double> magnitudes;                      // Magnitude spectrum
    std::vector<double> frequencies;                     // Frequency bins
    std::vector<size_t> top_ten_indices;                 // Indices of top 10 frequencies by magnitude
    std::vector<double> top_ten_magnitudes;              // Top 10 magnitudes
    std::vector<double> top_ten_frequencies;             // Top 10 frequencies
    std::vector<double> top_ten_arctan_features;         // Arctan of top magnitudes (up to 10)
    double sampling_rate;                                // Sampling rate used
    size_t fft_size;                                     // Size of FFT
    
    FFTResult() : sampling_rate(0.0), fft_size(0) {}
};

// FFT Analyzer class for packet inter-arrival time analysis
class FFTAnalyzer {
public:
    FFTAnalyzer();
    ~FFTAnalyzer();
    
    /**
     * @brief Analyze packet inter-arrival times using FFT
     * @param iat_times Vector of inter-arrival times in seconds
     * @return FFTResult containing FFT analysis results
     */
    FFTResult analyzeIAT(const std::vector<double>& iat_times);
    
    /**
     * @brief Extract top frequency features from IAT sequence
     * @param iat_times Vector of inter-arrival times in seconds
     * @return Vector of arctan features (arctan of top magnitudes ranked by contribution, up to 10)
     */
    std::vector<double> extractTopTenFeatures(const std::vector<double>& iat_times);
    
    /**
     * @brief Set minimum number of samples required for FFT analysis
     * @param min_samples Minimum number of samples (default: 4)
     */
    void setMinSamples(size_t min_samples);
    
    /**
     * @brief Set whether to apply windowing function before FFT
     * @param apply_windowing Whether to apply Hanning window (default: true)
     */
    void setWindowing(bool apply_windowing);

private:
    size_t min_samples_;           // Minimum samples required for analysis
    bool apply_windowing_;         // Whether to apply windowing
    
    /**
     * @brief Compute FFT using FFTW library
     * @param input Input data (real values)
     * @param output Output data (complex values)
     * @param size Size of the data
     */
    void computeFFTW(const double* input, fftw_complex* output, size_t size);
    
    /**
     * @brief Apply Hanning window to the input data
     * @param data Input data to be windowed
     */
    void applyHanningWindow(std::vector<double>& data);
    
    /**
     * @brief Calculate sampling rate from inter-arrival times
     * @param iat_times Vector of inter-arrival times
     * @return Estimated sampling rate
     */
    double calculateSamplingRate(const std::vector<double>& iat_times);
    
    /**
     * @brief Extract top N frequency components by magnitude
     * @param magnitudes Magnitude spectrum
     * @param n Number of top components to extract
     * @return Indices of top N components
     */
    std::vector<size_t> getTopNIndices(const std::vector<double>& magnitudes, size_t n);
};

#endif // FFT_ANALYZER_H
