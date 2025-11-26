#include "UpdateToolTask.h"
#include "SshExec.h"
#include "stringUtils.h"

#include <fstream>
#include <iostream>
#include <chrono>
#include <vector>
#include <stdlib.h>
#include <thread>


using namespace std;

#define TEMP_PAHT "/opt/oem"

int getValue(int max = 5000)
{
    int number;
    srand((unsigned)time(NULL)); // time()用系统时间初始化种。为rand()生成不同的随机种子。
    number = rand() % max + 1;   // 生成1~100随机数
    return number;
}

UpdateToolTask::UpdateToolTask(std::string host, int port, std::string username, std::string password, std::string filePath
    , const int timeout_ms, bool isReboot)
    : m_isReboot(isReboot), m_host(host)
{
    m_filePath = convert_system_path(filePath);
    m_sshExec = std::make_shared<SshExec>(host, port, username, password, timeout_ms);
}

UpdateResultType UpdateToolTask::processor(statusMsgMsgHandler statusMsgHandlerCallback, progressHandler progressHandlerCallback)
{
    std::string tempMsg;                    // 临时变量，用于存储命令输出
    std::vector<std::string> splitData;
    bool isInternalMd5 = false;             // 判断更新包是否包含MD5
    bool result = false;
    std::string md5_1, md5_2;
    int waitTime = 0;
    UpdateResultType updateResult{0, "SUCCESS"};

    m_statusMsgHandlerCallback = statusMsgHandlerCallback;
    m_progressHandlerCallback = progressHandlerCallback;

    // 1、检查是否可以更新
    // 1.1 检查更新包是否存在
    progress(0);
    ifstream f(m_filePath);
    if (!f.good())
    {
        statusMsg(UpdateStatus::FAIL, "没有找到更新包!");
        updateResult = UPDATE_FILE_NOT_FOUND;
        goto check_error;
    }
    print_log("file path: %s\n", m_filePath.c_str());

    // 1.2 ping 设备查看设备是否在线
    if (!ping(m_host))
    {
        statusMsg(UpdateStatus::FAIL, "请检查设备是否连接!");
        updateResult = DEVICE_NOT_ONLINE;
        goto check_error;
    }

    // 1.3 检查是否可以ssh连接
    result = m_sshExec->exec("ls");
    if (!result)
    {
        statusMsg(UpdateStatus::FAIL, "连接器件错误!");
        updateResult = CONNECT_DEVICE_ERROR;
        goto check_error;
    }

    // 2、判断更新包中需要判断MD5
    isInternalMd5 = judgeInternalMd5(m_filePath);

    // 3、上传更新包
    // 3.1 创建临时文件夹
    result = m_sshExec->exec("mkdir -p /opt/oem", [](std::string msg){ std::cout << msg << std::endl; });
    if (!result)
    {
        statusMsg(UpdateStatus::FAIL, "创建临时文件夹错误!");
        updateResult = DEVICE_ERROR;
        goto error;
    }

    statusMsg(UpdateStatus::TIPS, "上传更新包...!");
    print_log("update package uploading!\n");

    // 3.2 上传更新包到设备中
    result = m_sshExec->upFile(m_filePath, "/opt/oem/updata_temp.sh", [this](int value)
    {
        progress(value);
    });
    if (!result)
    {
        statusMsg(UpdateStatus::FAIL, "上传更新包错误!");
        updateResult = UPLOAD_ERROR;
        goto error;
    }
    else {
        statusMsg(UpdateStatus::TIPS, "上传成功!");
        print_log("update package upload successed!\n");
    }

    std::this_thread::sleep_for(200ms);
    progress(100);
    statusMsg(UpdateStatus::TIPS, "更新中...!");
    print_log("updating...\n");

    // 4、验证上传的更新包是否完整
    // 4.1 验证更新包外部的md5

    // 4.2验证更新包内部的md5
    if (isInternalMd5)
    {
        progress(10);
        result = m_sshExec->exec("head -c 16 /opt/oem/updata_temp.sh | xxd -p >> /opt/oem/md5_raw.txt", [this](std::string msg)
        {
            print_log("get md5 1: %s\n", msg.c_str());
        });
        progress(30);
        result = m_sshExec->exec("dd if=/opt/oem/updata_temp.sh  bs=16 skip=1 | dd of=/opt/oem/updata_enc_temp.sh bs=4M", [this](std::string msg)
        {
            print_log("get md5 2: %s\n", msg.c_str());
        });
        progress(60);
        result = m_sshExec->exec("md5sum /opt/oem/updata_enc_temp.sh >> /opt/oem/md5.txt", [this](std::string msg)
        {
            print_log("%s\n", msg.c_str());
        });
        
        progress(80);
        tempMsg = "";

        m_sshExec->exec("cat /opt/oem/md5_raw.txt", [this, &tempMsg](std::string msg){
            tempMsg += msg;
        });
        str_split(tempMsg, '\n', splitData);

        md5_1 = splitData.at(0);

        tempMsg = "";
        m_sshExec->exec("cat /opt/oem/md5.txt", [this, &tempMsg](std::string msg){
            tempMsg += msg;
        });

        str_split(tempMsg, ' ', splitData);
        if (splitData.size()>=1) {
            md5_2 = splitData.at(0); 
        }
        //std::cout << "mdt51: " << md5_1 << "   size:" << md5_1.size() << "   md5_2:" << md5_2 << "   size:" << md5_2.size() << std::endl;
        if (md5_1!=md5_2)
        {
            statusMsg(UpdateStatus::FAIL, "下位机更新包数据丢失!");
            updateResult = MD5_ERROR;
            goto error;
        }

        result = m_sshExec->exec("openssl enc -d -aes-256-cbc -salt -in /opt/oem/updata_enc_temp.sh -out /opt/updata.sh -pbkdf2 -pass pass:lv-ytdxcmqwbqspgr",  [this](std::string msg){
            // print_log("%s\n", msg.c_str())
        });
    } else {
        result = m_sshExec->exec("openssl enc -d -aes-256-cbc -salt -in /opt/oem/updata_temp.sh -out /opt/updata.sh -pbkdf2 -pass pass:lv-ytdxcmqwbqspgr");
    }

    if (!result)
    {
        statusMsg(UpdateStatus::FAIL, "更新包解密错误!");
        updateResult = DECRYPT_ERROR;
        goto error;
    }

    // 删除临时文件，因为脚本会自动重启
    m_sshExec->exec("rm -rf /opt/oem");

    // 5、开始执行更新脚本
    // 5.1 给更新包执行权限
    result = m_sshExec->exec("chmod u+x /opt/updata.sh");
    if (!result)
    {
        statusMsg(UpdateStatus::FAIL, "更新包配置错误!");
        updateResult = SCRIPT_CONFIG_ERROR;
        goto error;
    }
    print_log("exec update!\n");

    // 5.2 执行更新脚本
    tempMsg = "";
    result = m_sshExec->exec("cd /opt/ && /opt/updata.sh", [this, &tempMsg](std::string msg) {
        tempMsg += msg;

        m_progressValue += getValue(12);
        if (m_progressValue >= 100)
        {
            m_progressValue = 0;
        }
        progress(m_progressValue);
    });

    if (!result)
    {
        statusMsg(UpdateStatus::FAIL, "更新包执行失败!");
        updateResult = SCRIPT_EXEC_ERROR;
        goto error;
    }

    // 5.3 检查更新脚本执行结果
    if (tempMsg.empty() || !(tempMsg.find("更新完成!") == std::string::npos || tempMsg.find("清理缓存") == std::string::npos))
    {
        statusMsg(UpdateStatus::FAIL, "更新失败!");
        updateResult = SCRIPT_EXEC_RESULT_ERROR;
        goto error;
    }

    // 5.4 将进度条拉到100%
    m_isExecScriptSucceed = true;
    while (m_progressValue != 100)
    {
        waitTime = getValue(500);
        m_progressValue += getValue(30);
        if (m_progressValue >= 100)
        {
            m_progressValue = 100;
        }
        progress(m_progressValue);
        std::this_thread::sleep_for(200ms);
    }
    print_log("update successed!\n");

    goto successed;
check_error:
    return updateResult;
error:
    m_sshExec->exec("rm -rf /opt/oem/");
    return updateResult;
successed:
    // 设备重启
    if (m_isReboot)
    {
        // 目前更新完成会自动重启，所以这条命令无法执行
        m_sshExec->exec("/sbin/reboot");
    }

    return updateResult;
}

bool UpdateToolTask::judgeInternalMd5(std::string path)
{
    // 将filename
    std::string fileName = get_filename(path);
    std::vector<std::string> files_split;
    str_split(fileName, '_', files_split);

    if (files_split.size() == 4)
    {
        // 验证
        if (files_split.at(0) == "dm")
        {
            // 截取
            std::vector<std::string> versions;
            str_split(files_split.at(3), '.', versions);
            std::string majorStr;
            if (versions.size() > 1)
            {
                majorStr = std::string(versions.at(0).begin()+1, versions.at(0).end());
            }

            if (versions.size() != 4)
            {
                return false;
            }

            int major = atoi(majorStr.c_str());
            int minor = atoi(versions.at(1).c_str());
            int patch = atoi(versions.at(2).c_str());

            // 判断更新包版本大于等于 0.0.14
            if (major > 0 || minor > 1 || (minor==1 && patch >= 14))
            {
                statusMsg(UpdateStatus::TIPS, "md5 update package please make file version greater than and equal v0.1.14!");
                return true;
            }
        }
    }
    return false;
}

void UpdateToolTask::statusMsg(UpdateStatus status, std::string msg)
{
    print_log(msg.c_str());
    if (m_statusMsgHandlerCallback != nullptr)
    {
        m_statusMsgHandlerCallback(status, msg);
    }
}

void UpdateToolTask::progress(int value)
{
    if (m_progressHandlerCallback != nullptr)
    {
        m_progressHandlerCallback(value);
    }
}
