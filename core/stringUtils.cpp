#include "stringUtils.h"

#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <io.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/select.h>
#endif

#include <iostream>
#include <string.h>
#include <stdio.h>
#include <stdlib.h> 


void print_log(const char *format, ...)
{
#ifdef BUILD_TYPE
    #include <stdarg.h>
 
    static char output[1024]={0};
    va_list arg_list;
    va_start(arg_list,format);
    vsnprintf(output,sizeof(output),format, arg_list);
    printf("%s", output);
    va_end(arg_list);
#endif
}

#ifdef _WIN32
// 将错误码转换为可读字符串
std::string get_last_error_string(DWORD error_code) {
    LPSTR buffer = nullptr;
    DWORD size = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, error_code, 0, (LPSTR)&buffer, 0, NULL
    );
    if (size == 0) {
        return "未知错误";
    }
    std::string message(buffer, size);
    LocalFree(buffer);
    return message;
}
#endif

void str_split(std::string str, char separator, std::vector<std::string> &output)
{
    output.clear();
    int startIndex = 0, endIndex = 0;
    for (int i = 0; i <= str.size(); i++)
    {
        if (str[i] == separator || i == str.size())
        {
            endIndex = i;
            std::string temp;
            temp.append(str, startIndex, endIndex - startIndex);
            output.push_back(temp);
            startIndex = endIndex + 1;
        }
    }
}

std::string get_filename(const std::string& path) {
    // 处理 Windows 反斜杠和 Unix 正斜杠
    size_t pos = path.find_last_of("/\\");
    if (pos != std::string::npos) {
        return path.substr(pos + 1);
    }
    return path;
}

std::string gbk_to_utf8(const std::string& gbk_str) {
#ifdef _WIN32
    // GBK -> WCHAR
    int wlen = MultiByteToWideChar(CP_ACP, 0, gbk_str.c_str(), -1, NULL, 0);
    wchar_t* wstr = new wchar_t[wlen];
    MultiByteToWideChar(CP_ACP, 0, gbk_str.c_str(), -1, wstr, wlen);

    // WCHAR -> UTF-8
    int ulen = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
    char* utf8_str = new char[ulen];
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, utf8_str, ulen, NULL, NULL);

    std::string result(utf8_str);
    delete[] wstr;
    delete[] utf8_str;
    return result;
#else
    return std::string(gbk_str);
#endif
}

std::string utf8_to_gbk(const std::string& utf8_str) {
#ifdef _WIN32
    // UTF-8 -> WCHAR
    int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8_str.c_str(), -1, NULL, 0);
    wchar_t* wstr = new wchar_t[wlen];
    MultiByteToWideChar(CP_UTF8, 0, utf8_str.c_str(), -1, wstr, wlen);

    // WCHAR -> GBK
    int len = WideCharToMultiByte(CP_ACP, 0, wstr, -1, NULL, 0, NULL, NULL);
    char* gbk_str = new char[len];
    WideCharToMultiByte(CP_ACP, 0, wstr, -1, gbk_str, len, NULL, NULL);

    std::string result(gbk_str);
    delete[] wstr;
    delete[] gbk_str;
    return result;
#else
    return utf8_str;
#endif
}

bool file_exists(const char* path) {
#ifdef _WIN32
    return (_access(path, 0) == 0); // 检查存在性
#else
    return (access(path, F_OK) == 0); // F_OK 检测存在性
#endif
}

std::string convert_system_path(const std::string& str)
{
#ifdef _WIN32
    UINT code_page = GetACP();
    if (936 == code_page)
    {
        std::string gbk_path = utf8_to_gbk(str);
        return gbk_path;
    }
#endif
    // TODO 处理其它的编码
    return str;
}

bool ping(const std::string& host)
{
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return false;

    struct in_addr ip_addr;
    if (InetPtonA(AF_INET, host.c_str(), &ip_addr) != 1) {
        WSACleanup();
        return false;
    }

    HANDLE hIcmp = IcmpCreateFile();  // 正确调用位置
    if (hIcmp == INVALID_HANDLE_VALUE) {
        WSACleanup();
        return false;
    }

    // 使用 IcmpSendEcho2 和 ICMP_ECHO_REPLY32
    char send_data[] = "PingTest";
    constexpr DWORD reply_size = sizeof(ICMP_ECHO_REPLY) + sizeof(send_data)+8;
    BYTE reply_buffer[reply_size];
    DWORD result = IcmpSendEcho2(
        hIcmp, nullptr, nullptr, nullptr,
        ip_addr.s_addr, 
        send_data, sizeof(send_data), 
        nullptr, 
        reply_buffer, reply_size, 
        2000
    );

    if (result == 0) {
        DWORD error = GetLastError();
        print_log("ping error , error no : %d \n", error);
    } else {
        print_log("ping success : %d \n", result);
    }

    IcmpCloseHandle(hIcmp);
    WSACleanup();
    return (result > 0);
#else
    // linux执行需要权限，暂时不做处理
#if 0
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) return false;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        close(sock);
        return false;
    }

    struct icmphdr packet;
    memset(&packet, 0, sizeof(packet));
    packet.type = ICMP_ECHO;
    packet.un.echo.id = getpid();
    packet.un.echo.sequence = 0;

    if (sendto(sock, &packet, sizeof(packet), 0, 
              (struct sockaddr*)&addr, sizeof(addr)) <= 0) {
        close(sock);
        return false;
    }

    fd_set read_set;
    FD_ZERO(&read_set);
    FD_SET(sock, &read_set);
    struct timeval timeout = { 2000 / 1000, (2000 % 1000) * 1000 };

    int ready = select(sock + 1, &read_set, nullptr, nullptr, &timeout);
    close(sock);
    return (ready >= 0);
#else
    return true;
#endif
#endif    
}
