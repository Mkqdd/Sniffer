#include "utils/FFTAnalyzer.h"
#include <iostream>
#include <numeric>
#include <cmath>
#include <cstring>

FFTAnalyzer::FFTAnalyzer() : min_samples_(4), apply_windowing_(true) {
}

FFTAnalyzer::~FFTAnalyzer() {
}

void FFTAnalyzer::setMinSamples(size_t min_samples) {
    min_samples_ = min_samples;
}

void FFTAnalyzer::setWindowing(bool apply_windowing) {
    apply_windowing_ = apply_windowing;
}

FFTResult FFTAnalyzer::analyzeIAT(const std::vector<double>& iat_times) {
    FFTResult result;
    
    // Check if we have enough samples
    if (iat_times.size() < min_samples_) {
        return result; // Return empty result
    }
    
    // Prepare input data
    std::vector<double> input_data(iat_times);
    
    // Apply windowing if enabled
    if (apply_windowing_) {
        applyHanningWindow(input_data);
    }
    
    // Calculate sampling rate
    result.sampling_rate = calculateSamplingRate(iat_times);
    result.fft_size = input_data.size();
    
    // Allocate FFTW arrays
    double* fftw_input = fftw_alloc_real(input_data.size());
    fftw_complex* fftw_output = fftw_alloc_complex((input_data.size() / 2) + 1);
    
    if (!fftw_input || !fftw_output) {
        // Memory allocation failed
        if (fftw_input) fftw_free(fftw_input);
        if (fftw_output) fftw_free(fftw_output);
        return result;
    }
    
    // Copy input data to FFTW array
    std::memcpy(fftw_input, input_data.data(), input_data.size() * sizeof(double));
    
    // Create FFTW plan and execute
    fftw_plan plan = fftw_plan_dft_r2c_1d(input_data.size(), fftw_input, fftw_output, FFTW_ESTIMATE);
    if (plan) {
        fftw_execute(plan);
        fftw_destroy_plan(plan);
        
        // Convert FFTW output to our format
        size_t output_size = (input_data.size() / 2) + 1;
        result.fft_coefficients.reserve(output_size);
        result.magnitudes.reserve(output_size);
        result.frequencies.reserve(output_size);
        
        for (size_t i = 0; i < output_size; ++i) {
            // Convert fftw_complex to std::complex<double>
            std::complex<double> coeff(fftw_output[i][0], fftw_output[i][1]);
            result.fft_coefficients.push_back(coeff);
            
            // Calculate magnitude
            double magnitude = std::abs(coeff);
            result.magnitudes.push_back(magnitude);
            
            // Calculate frequency bin
            double frequency = (static_cast<double>(i) * result.sampling_rate) / input_data.size();
            result.frequencies.push_back(frequency);
        }
        
        // Find top frequency components by magnitude (up to 10, or all available)
        size_t num_features = std::min(size_t(10), result.magnitudes.size());
        result.top_ten_indices = getTopNIndices(result.magnitudes, num_features);
        
        // Extract available features (no padding)
        result.top_ten_magnitudes.reserve(num_features);
        result.top_ten_frequencies.reserve(num_features);
        result.top_ten_arctan_features.reserve(num_features);
        
        // Add available features
        for (size_t idx : result.top_ten_indices) {
            if (idx < result.magnitudes.size()) {
                result.top_ten_magnitudes.push_back(result.magnitudes[idx]);
                result.top_ten_frequencies.push_back(result.frequencies[idx]);
                
                // Calculate arctan feature: arctan of the magnitude (contribution)
                double arctan_feature = std::atan(result.magnitudes[idx]);
                result.top_ten_arctan_features.push_back(arctan_feature);
            }
        }
    }
    
    // Clean up FFTW arrays
    fftw_free(fftw_input);
    fftw_free(fftw_output);
    
    return result;
}

std::vector<double> FFTAnalyzer::extractTopTenFeatures(const std::vector<double>& iat_times) {
    FFTResult result = analyzeIAT(iat_times);
    return result.top_ten_arctan_features;
}

void FFTAnalyzer::computeFFTW(const double* input, fftw_complex* output, size_t size) {
    // Create and execute FFTW plan
    fftw_plan plan = fftw_plan_dft_r2c_1d(size, const_cast<double*>(input), output, FFTW_ESTIMATE);
    if (plan) {
        fftw_execute(plan);
        fftw_destroy_plan(plan);
    }
}

void FFTAnalyzer::applyHanningWindow(std::vector<double>& data) {
    size_t n = data.size();
    for (size_t i = 0; i < n; ++i) {
        double window_value = 0.5 * (1.0 - std::cos(2.0 * M_PI * i / (n - 1)));
        data[i] *= window_value;
    }
}

double FFTAnalyzer::calculateSamplingRate(const std::vector<double>& iat_times) {
    if (iat_times.empty()) {
        return 1.0; // Default sampling rate
    }
    
    // Calculate average inter-arrival time
    double sum = std::accumulate(iat_times.begin(), iat_times.end(), 0.0);
    double avg_iat = sum / iat_times.size();
    
    // Sampling rate is inverse of average inter-arrival time
    // Add small epsilon to avoid division by zero
    return 1.0 / (avg_iat + 1e-9);
}

std::vector<size_t> FFTAnalyzer::getTopNIndices(const std::vector<double>& magnitudes, size_t n) {
    // Create vector of indices
    std::vector<size_t> indices(magnitudes.size());
    std::iota(indices.begin(), indices.end(), 0);
    
    // Sort indices by magnitude in descending order
    std::partial_sort(indices.begin(), indices.begin() + std::min(n, indices.size()), indices.end(),
                     [&magnitudes](size_t a, size_t b) {
                         return magnitudes[a] > magnitudes[b];
                     });
    
    // Return top N indices
    size_t actual_n = std::min(n, indices.size());
    return std::vector<size_t>(indices.begin(), indices.begin() + actual_n);
}