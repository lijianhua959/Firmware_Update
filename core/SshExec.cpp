#include "SshExec.h"
#include "stringUtils.h"

#include <sys/types.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <iostream>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#endif


int waitSocket(int nSocketFd, LIBSSH2_SESSION * pSession, const int timeout_ms)
{
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = timeout_ms * 1000;

    fd_set fd;
    FD_ZERO(&fd);

    FD_SET(nSocketFd, &fd);

    /* now make sure we wait in the correct direction */
    int dir = libssh2_session_block_directions(pSession);

    fd_set *pWriteFd = nullptr;
    fd_set *pReadFd = nullptr;

    if (dir & LIBSSH2_SESSION_BLOCK_INBOUND)
        pReadFd = &fd;

    if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND)
        pWriteFd = &fd;

    int rc = select(nSocketFd + 1, pReadFd, pWriteFd, NULL, &timeout);

    return rc;
}

SshExec::SshExec(const std::string & ip, const int port, const std::string & user, const std::string & passwd, const int m_timeout)
    : m_host(ip), m_user(user), m_password(passwd), m_port(port)
{
}

bool SshExec::exec(const std::string& strCmd, std::function<void(std::string)> handler)
{
    int exitcode;
    char *exitsignal = (char *)"none";
    int bytecount = 0;

#ifdef _WIN32
    WSADATA wsadata;
    int err;

    err = WSAStartup(MAKEWORD(2, 0), &wsadata);
    if (err != 0) {
        print_log("WSAStartup failed with error: %d\n", err);
        return false;
    }
#endif

    int nLibssh2Err = libssh2_init(0);
    if (nLibssh2Err != 0) {
        return false;
    }

    /* Ultra basic "connect to port 22 on localhost"
    * Your code is responsible for creating the socket establishing the
    * connection
    */
    int nSocketFd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(m_port);
    sin.sin_addr.s_addr = inet_addr(m_host.c_str());
    if (::connect(nSocketFd, (struct sockaddr*)(&sin), sizeof(struct sockaddr_in)) != 0) {
        //print_log("connect error: \n");
        return false;
    }

    /* Create a session instance */
    LIBSSH2_SESSION *pSession = libssh2_session_init();
    if (nullptr == pSession)
        return false;

    /* tell libssh2 we want it all done non-blocking */
    libssh2_session_set_blocking(pSession, 0);

    /* ... start it up. This will trade welcome banners, exchange keys,
    * and setup crypto, compression, and MAC layers
    */
    while ((nLibssh2Err = libssh2_session_handshake(pSession, nSocketFd)) == LIBSSH2_ERROR_EAGAIN);
    if (nLibssh2Err != 0)
    {
        char *err_msg;
        int err_len;
        libssh2_session_last_error(pSession, &err_msg, &err_len, 0);
        std::cout << "Failure establishing SSH session (" << err_msg << ")" << std::endl;
        return false;
    }

    LIBSSH2_KNOWNHOSTS *pNH = libssh2_knownhost_init(pSession);
    if (nullptr == pNH) {
        /* eeek, do cleanup here */
        return false;
    }

    /* read all hosts from here */
    libssh2_knownhost_readfile(pNH, "known_hosts", LIBSSH2_KNOWNHOST_FILE_OPENSSH);

    /* store all known hosts to here */
    libssh2_knownhost_writefile(pNH, "dumpfile", LIBSSH2_KNOWNHOST_FILE_OPENSSH);

    size_t len;
    int type;
    std::string fingerprint = libssh2_session_hostkey(pSession, &len, &type);
    if (fingerprint.empty()) {
        struct libssh2_knownhost *host;
#if LIBSSH2_VERSION_NUM >= 0x010206
        /* introduced in 1.2.6 */
        int check = libssh2_knownhost_checkp(pNH, m_host.c_str(), m_port,
            fingerprint.c_str(), len,
            LIBSSH2_KNOWNHOST_TYPE_PLAIN |
            LIBSSH2_KNOWNHOST_KEYENC_RAW,
            &host);
#else
        /* 1.2.5 or older */
        int check = libssh2_knownhost_check(pNH, m_host.toLocal8Bit().constData(),
            fingerprint.toLocal8Bit().constData(), len,
            LIBSSH2_KNOWNHOST_TYPE_PLAIN |
            LIBSSH2_KNOWNHOST_KEYENC_RAW,
            &host);
#endif
        /*****
        * At this point, we could verify that 'check' tells us the key is
        * fine or bail out.
        *****/
    }
    else {
        /* eeek, do cleanup here */
        return false;
    }
    libssh2_knownhost_free(pNH);

    /* We could authenticate via password */
    while ((nLibssh2Err = libssh2_userauth_password(pSession, m_user.c_str(),
        m_password.c_str())) == LIBSSH2_ERROR_EAGAIN);
    if (nLibssh2Err != 0)
    {
        return false;
    }

#if 0
    libssh2_trace(session, ~0);
#endif

    LIBSSH2_CHANNEL *pChannel;
    /* Exec non-blocking on the remove host */
    while ((pChannel = libssh2_channel_open_session(pSession)) == NULL &&
        libssh2_session_last_error(pSession, NULL, NULL, 0) == LIBSSH2_ERROR_EAGAIN)
    {
        waitSocket(nSocketFd, pSession, m_timeout);
    }
    if (nullptr == pChannel)
    {
        return false;
    }
    while ((nLibssh2Err = libssh2_channel_exec(pChannel, strCmd.c_str())) ==
        LIBSSH2_ERROR_EAGAIN)
    {
        waitSocket(nSocketFd, pSession, m_timeout);
    }
    if (nLibssh2Err != 0)
    {
        return false;
    }

    for (;;)
    {
        /* loop until we block */
        int rc;
        do
        {
            char buffer[0x4000];
            rc = libssh2_channel_read(pChannel, buffer, sizeof(buffer-1));
            if (rc > 0)
            {
                int i;
                bytecount += rc;
                //print_log("We read:\n");
                // for (i = 0; i < rc; ++i)
                //     fputc(buffer[i], stderr);
                buffer[rc] = '\0';
                if (handler != NULL)
                    handler(buffer);
            }
            else {
                if (rc != LIBSSH2_ERROR_EAGAIN)
                {
                    //print_log("libssh2_channel_read returned %d\n", rc);
                }
                    /* no need to output this for the EAGAIN case */
            }
        } while (rc > 0);

        /* this is due to blocking that would occur otherwise so we loop on
        this condition */
        if (rc == LIBSSH2_ERROR_EAGAIN)
        {
            waitSocket(nSocketFd, pSession, m_timeout);
        }
        else
            break;
    }

    exitcode = 127;
    while ((nLibssh2Err = libssh2_channel_close(pChannel)) == LIBSSH2_ERROR_EAGAIN)
        waitSocket(nSocketFd, pSession, m_timeout);

    if (nLibssh2Err != 0)
    {
        exitcode = libssh2_channel_get_exit_status(pChannel);
        libssh2_channel_get_exit_signal(pChannel, &exitsignal,
            NULL, NULL, NULL, NULL, NULL);
    }

    if (exitsignal)
    {
        //print_log("\nGot signal: %s\n", exitsignal);
    }
    else
        print_log("\nEXIT: %d bytecount: %d\n", exitcode, bytecount);

    libssh2_channel_free(pChannel);
    pChannel = NULL;

shutdown:

    libssh2_session_disconnect(pSession,
        "Normal Shutdown, Thank you for playing");
    libssh2_session_free(pSession);

#ifdef _WIN32
    closesocket(nSocketFd);
#else
    close(nSocketFd);
#endif
    // fprintf(stderr, "all done\n");

    libssh2_exit();

    return true;
}

bool SshExec::upFile(const std::string &LocalPath, const std::string &RemotePath, std::function<void(int)> handler)
{
    char mem[102400];
    size_t nread;
    char *ptr;
    FILE *local;
    int rc;

    struct stat fileinfo;
    stat(LocalPath.c_str(), &fileinfo);

    local = fopen(LocalPath.c_str(), "rb");
    if(!local) {
        print_log("Can't open local file %s\n", LocalPath.c_str());
        return -1;
    }

    int exitcode;
    char *exitsignal = (char *)"none";
    int bytecount = 0;

#ifdef _WIN32
    WSADATA wsadata;
    int err;

    err = WSAStartup(MAKEWORD(2, 0), &wsadata);
    if (err != 0) {
        print_log("WSAStartup failed with error: %d\n", err);
        return false;
    }
#endif

    int nLibssh2Err = libssh2_init(0);
    if (nLibssh2Err != 0) {
        return false;
    }

    /* Ultra basic "connect to port 22 on localhost"
    * Your code is responsible for creating the socket establishing the
    * connection
    */
    int nSocketFd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(m_port);
    sin.sin_addr.s_addr = inet_addr(m_host.c_str());
    if (::connect(nSocketFd, (struct sockaddr*)(&sin), sizeof(struct sockaddr_in)) != 0) {
        print_log("connect error: \n");
        return false;
    }

    /* Create a session instance */
    LIBSSH2_SESSION *pSession = libssh2_session_init();
    if (nullptr == pSession)
        return false;

    /* tell libssh2 we want it all done non-blocking */
    libssh2_session_set_blocking(pSession, 1);

    /* ... start it up. This will trade welcome banners, exchange keys,
    * and setup crypto, compression, and MAC layers
    */
    while ((nLibssh2Err = libssh2_session_handshake(pSession, nSocketFd)) == LIBSSH2_ERROR_EAGAIN);
    if (nLibssh2Err != 0)
    {
        return false;
    }

    LIBSSH2_KNOWNHOSTS *pNH = libssh2_knownhost_init(pSession);
    if (nullptr == pNH) {
        /* eeek, do cleanup here */
        return false;
    }

    /* read all hosts from here */
    libssh2_knownhost_readfile(pNH, "known_hosts", LIBSSH2_KNOWNHOST_FILE_OPENSSH);

    /* store all known hosts to here */
    libssh2_knownhost_writefile(pNH, "dumpfile", LIBSSH2_KNOWNHOST_FILE_OPENSSH);

    size_t len;
    int type;
    std::string fingerprint = libssh2_session_hostkey(pSession, &len, &type);
    if (fingerprint.empty()) {
        struct libssh2_knownhost *host;
#if LIBSSH2_VERSION_NUM >= 0x010206
        /* introduced in 1.2.6 */
        int check = libssh2_knownhost_checkp(pNH, m_host.c_str(), m_port,
            fingerprint.c_str(), len,
            LIBSSH2_KNOWNHOST_TYPE_PLAIN |
            LIBSSH2_KNOWNHOST_KEYENC_RAW,
            &host);
#else
        /* 1.2.5 or older */
        int check = libssh2_knownhost_check(pNH, m_host.toLocal8Bit().constData(),
            fingerprint.toLocal8Bit().constData(), len,
            LIBSSH2_KNOWNHOST_TYPE_PLAIN |
            LIBSSH2_KNOWNHOST_KEYENC_RAW,
            &host);
#endif
        /*****
        * At this point, we could verify that 'check' tells us the key is
        * fine or bail out.
        *****/
    }
    else {
        /* eeek, do cleanup here */
        return false;
    }
    libssh2_knownhost_free(pNH);

    /* We could authenticate via password */
    while ((nLibssh2Err = libssh2_userauth_password(pSession, m_user.c_str(),
        m_password.c_str())) == LIBSSH2_ERROR_EAGAIN);
    if (nLibssh2Err != 0)
    {
        return false;
    }

#if 0
    libssh2_trace(session, ~0);
#endif

    LIBSSH2_CHANNEL *pChannel;
    /* Exec non-blocking on the remove host */
    // while ((pChannel = libssh2_channel_open_session(pSession)) == NULL &&
    //     libssh2_session_last_error(pSession, NULL, NULL, 0) == LIBSSH2_ERROR_EAGAIN)
    // {
    //     WaitSocket(nSocketFd, pSession);
    // }
    // if (nullptr == pChannel)
    // {
    //     return false;
    // }

    /* Send a file via scp. The mode parameter must only have permissions! */
    pChannel = libssh2_scp_send(pSession, RemotePath.c_str(), fileinfo.st_mode & 0777,(unsigned long)fileinfo.st_size);
    if(!pChannel) {
        char *errmsg;
        int errlen;
        int err = libssh2_session_last_error(pSession, &errmsg, &errlen, 0);

        print_log("Unable to open a session: (%d) %s\n", err, errmsg);
        if(pSession) {
            libssh2_session_disconnect(pSession, "Normal Shutdown");

            libssh2_session_free(pSession);
            return false;
        }
    }

    print_log("SCP session waiting to send file\n");
    int readFileSize=0;
    size_t fileSize = fileinfo.st_size;
    do {
        nread = fread(mem, 1, sizeof(mem), local);

        if(nread <= 0) {
            /* end of file */
            break;
        }
        ptr = mem;

        do {
            /* write the same data over and over, until error or completion */
            rc = libssh2_channel_write(pChannel, ptr, nread);

            if(rc < 0) {
                print_log("ERROR %d\n", rc);
                break;
            }
            else {
                /* rc indicates how many bytes were written this time */
                ptr += rc;
                nread -= rc;
                readFileSize += rc;
                if (handler != NULL)
                {
                    int progress = (readFileSize*1.0/fileSize)*100;
                    // printf("progress: %d%\n", progress);
                    handler(progress);
                }
            }
        } while(nread);

    } while(1);

    print_log("Sending EOF\n");
    libssh2_channel_send_eof(pChannel);


    print_log("Waiting for EOF\n");
    libssh2_channel_wait_eof(pChannel);

    exitcode = 127;
    while ((nLibssh2Err = libssh2_channel_close(pChannel)) == LIBSSH2_ERROR_EAGAIN)
        waitSocket(nSocketFd, pSession, m_timeout);

    if (nLibssh2Err != 0)
    {
        exitcode = libssh2_channel_get_exit_status(pChannel);
        libssh2_channel_get_exit_signal(pChannel, &exitsignal,
            NULL, NULL, NULL, NULL, NULL);
    }

    if (exitsignal)
        print_log("\nGot signal: %s\n", exitsignal);
    else
        print_log("\nEXIT: %d bytecount: %d\n", exitcode, bytecount);

    libssh2_channel_free(pChannel);
    pChannel = NULL;

shutdown:

    libssh2_session_disconnect(pSession,
        "Normal Shutdown, Thank you for playing");
    libssh2_session_free(pSession);

#ifdef _WIN32
    closesocket(nSocketFd);
#else
    close(nSocketFd);
#endif
    print_log("all done\n");

    libssh2_exit();

    return true;
}