#pragma once

#include <libssh2.h>
#include <functional>
#include <string>

class SshExec
{
public:
    SshExec(const std::string& ip, const int port=22, const std::string& user="root", const std::string& passwd="", const int m_timeout=2000);
    ~SshExec() = default;

    /**
     * @brief 执行命令
     * @param strCmd 命令
     * @param handler 回调函数，用于处理命令输出
     * @return true 执行成功，false 执行失败
     */
    bool exec(const std::string& strCmd, std::function<void(std::string)> handler=nullptr);
    
    /**
     * @brief 上传文件
     * @param LocalPath 本地文件路径
     * @param RemoteDir 远程目录
     * @param handler 回调函数，用于处理上传进度
     * @return true 上传成功，false 上传失败
     */
    bool upFile(const std::string& LocalPath, const std::string& RemoteDir, std::function<void(int)> handler=nullptr);

private:
    std::string     m_host;        // 主机名或IP地址
    std::string     m_user;        // 用户名
    std::string     m_password;    // 密码
    int             m_port;        // 端口号
    int             m_timeout;     // 超时时间，单位为毫秒
};
