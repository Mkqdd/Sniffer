#ifndef FILE_UTILS_H
#define FILE_UTILS_H

#include <string>

namespace FileUtils {
    bool createDirIfNotExist(const std::string &path);
}

#endif // FILE_UTILS_H