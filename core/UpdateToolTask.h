#pragma once

#include <memory>
#include <optional>
#include <string>
#include <functional>

class SshExec;
class UpdateResultType;

// 进度条回调
using progressHandler = std::function<void(int)>;

class UpdateToolTask
{
public:
    /**
        消息类型
    */
    enum class UpdateStatus
    {
        SUCCESS,
        FAIL,
        TIPS,
        UNKNOWN
    };

    // 消息处理回调
    using statusMsgMsgHandler = std::function<void(UpdateStatus, std::string)>;

public:
    UpdateToolTask(std::string host="192.168.1.200", int port=22, std::string username="root",
            std::string password="", std::string filePath="", const int timeout_ms=2000, bool isReboot=false);
    ~UpdateToolTask() = default;

    UpdateResultType processor(statusMsgMsgHandler statusMsgHandlerCallback=nullptr, progressHandler progressHandlerCallback=nullptr);

    /**
     * @brief generateMD5 判断更新包的MD5和本地文件的MD5是否一致
     * @param filePath
     * @return
     */
    bool judgeInternalMd5(std::string path);

private:
    void statusMsg(UpdateStatus status, std::string msg);
    void progress(int value);

private:
    std::shared_ptr<SshExec>        m_sshExec;                          // 远程连接类
    std::string                     m_filePath;                         // 更新包路径
    bool                            m_isReboot{ false };                         // 是否重启

    std::string                     m_host;                             // 主机ip
    bool                            m_isExecScriptSucceed{false};       // 判断角本是否执行成功
    int                             m_progressValue{0};                 // 执行进度

    statusMsgMsgHandler             m_statusMsgHandlerCallback{nullptr};// 状态消息回调
    progressHandler                 m_progressHandlerCallback{nullptr}; // 进度回调
};


class UpdateResultType
{
public:
	int code = 0;
	std::string desc{"SUCCESS"};

	UpdateResultType(int cd, const char *dsc)
		: code(cd), desc(dsc)
	{
	}

    inline UpdateResultType &operator=(const UpdateResultType &et)
	{
		code = et.code;
		desc = et.desc;

		return *this;
	}

	inline bool operator==(const UpdateResultType &et) const
	{
		return (code == et.code);
	}

	inline bool operator!=(const UpdateResultType &et) const
	{
		return (code != et.code);
	}

	virtual std::string what() const
	{
		return desc;
	}
};


// 设备异常参数
const static UpdateResultType RESULT_OK                         = { 0, "update successed!" };
const static UpdateResultType UPDATE_FILE_NOT_FOUND             = { 1, "update file not found!" };
const static UpdateResultType DEVICE_NOT_ONLINE                 = { 2, "device not online!" };
const static UpdateResultType CONNECT_DEVICE_ERROR              = { 3, "connect device error!" };
const static UpdateResultType UPLOAD_ERROR                      = { 4, "upload package error!" };
const static UpdateResultType MD5_ERROR                         = { 5, "device update package loss!" };
const static UpdateResultType DECRYPT_ERROR                     = { 6, "update package decrypt error!" };
const static UpdateResultType SCRIPT_CONFIG_ERROR               = { 7, "update package config error!" };
const static UpdateResultType SCRIPT_EXEC_ERROR                 = { 8, "update script exec failed!" };
const static UpdateResultType SCRIPT_EXEC_RESULT_ERROR          = { 9, "check exec not finish or log error!" };
const static UpdateResultType DEVICE_ERROR                      = { 10, "device malfunction!" };
const static UpdateResultType UPDATE_VERSION_ERROR              = { 11, "md5 update package please make file version greater than and equal v0.1.14!" };
