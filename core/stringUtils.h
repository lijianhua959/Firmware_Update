#pragma once

#include <string>
#include <vector>

//#define BUILD_TYPE Debug


#ifdef __cplusplus
extern "C" {
#endif

std::string utf8_to_gbk(const std::string& utf8_str);

void print_log(const char *format, ...);

void str_split(std::string str, char separator, std::vector<std::string> &output);

std::string get_filename(const std::string& path);

std::string gbk_to_utf8(const std::string& gbk_str);


bool file_exists(const char* path);

std::string convert_system_path(const std::string& str);

bool ping(const std::string& host);

#ifdef __cplusplus
}
#endif
