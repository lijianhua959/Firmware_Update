#include <iostream>
#include "SshExec.h"

int main()
{
    std::cout << "Hello World!" << std::endl;

    SshExec sshExec("192.168.1.201", 22, "root", "dm-zgyfjch");

    sshExec.exec("ls -l", [](std::string msg) {
        std::cout << msg << std::endl;
      });

    return 0;
}