// works on 64 bit
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

typedef unsigned long long int datatype;
typedef uint64_t word_t;
#define word_size sizeof(word_t)

static char insert_code[] = "\x0f\x05\xcc";
//  \x0f\x05 is for syscall
//  \xxc is for int3 to setup a breakpoint

size_t calculate_size(const char *str)
{
    size_t result = strlen(str) + 1 + sizeof(insert_code);
    result += (result % word_size);
    return result;
}

void getdata(pid_t child, const word_t *addr, word_t *str, int len)
{
    int k = ((len + word_size - 1) / word_size); // -1 for rounding up
    for (int i = 0; i < k; i++)
    {
        *str++ = ptrace(PTRACE_PEEKDATA, child, addr++, NULL);
    }
}

void putdata(pid_t child, const word_t *addr, const word_t *str, int len)
{
    int k = ((len + word_size - 1) / word_size); // -1 for rounding up
    for (int i = 0; i < k; i++)
    {
        ptrace(PTRACE_POKEDATA, child, addr++, *str++);
    }
}

int redirect_fd_to_path(const char *Spid, const char *Sfd, const char *path)
{

    struct user_regs_struct registers;
    struct user_regs_struct oldregisters;
    size_t size = calculate_size(path);
    size_t path_len = strlen(path) + 1; // +1 because size is not from 0

    char *endptr;
    int pid = strtol(Spid, &endptr, 10);
    if (errno != 0 || *endptr != '\0')
    {
        printf("Invalid pid\n");
        return 1;
    }

    int fd = strtol(Sfd, &endptr, 10);
    if (errno != 0 || *endptr != '\0')
    {
        printf("Invalid fd\n");
        return 1;
    }

    // attaching and stopping process
    ptrace(PT_ATTACH, pid, NULL, NULL);
    waitpid(pid, NULL, 0);
    printf("attached\n");

    // geting registers
    ptrace(PTRACE_GETREGS, pid, NULL, &registers);

    // saving registers to put back in later
    memcpy(&oldregisters, &registers, sizeof(registers));
    printf("got registers\n");

    // backing up code
    void *addr = (void *)registers.rip; // storing current instruction pointer
    void *backup = alloca(size);        // allocating space for backup
    getdata(pid, addr, backup, size);   // getting data from process
    printf("backed up memory\n");

    // putting new path in
    void *data = alloca(size);
    memset(data, 0, size);                                     // zeroing out data
    memcpy(data, path, path_len);                              // putting outpath in
    memcpy(data + path_len, insert_code, sizeof(insert_code)); // put sys call for stop
    putdata(pid, addr, data, size);
    printf("put new fd path\n");

    //  \/will be in rax  \/in addr
    // int new_fd = open(path, O_WRONLY | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
    registers.rip = (datatype)(addr + path_len);   // set new instruction pointer
    registers.rax = 0x02;                          // sys call to open a file
    registers.rdi = (datatype)addr;                // first argument for open (const char *path)
    registers.rsi = O_CREAT;                       // write only and create (int flags)
    registers.rdx = S_IRWXU | S_IRWXG | S_IRWXO;   // read write for owner, group and others (umode_t mode)
    ptrace(PTRACE_SETREGS, pid, NULL, &registers); // put changed registers back in
    ptrace(PTRACE_CONT, pid, NULL, NULL);          // continue process
    waitpid(pid, NULL, 0);                         // wait for open to finish
    printf("opened file\n");

    // dup2(new_fd, fd);
    ptrace(PTRACE_GETREGS, pid, NULL, &registers); // get registers after open completed
    registers.rip = (datatype)(addr + path_len);   // set new instruction pointer
    registers.rdi = registers.rax;                 // first argument for dup2 (int newfd)
    registers.rax = 0x21;                          // sys call to dup2
    registers.rsi = fd;                            // second argument for dup2 (int oldfd)
    ptrace(PTRACE_SETREGS, pid, NULL, &registers); // put changed registers in
    ptrace(PTRACE_CONT, pid, NULL, NULL);          // continue process
    waitpid(pid, NULL, 0);                         // wait for dup2 to finish
    printf("duped file\n");

    // close(new_fd);
    ptrace(PTRACE_GETREGS, pid, NULL, &registers); // get registers after open completed
    registers.rip = (datatype)(addr + path_len);   // set new instruction pointer
    registers.rax = 0x03;                          // sys call to close
    ptrace(PTRACE_SETREGS, pid, NULL, &registers); // put changed registers in
    ptrace(PTRACE_CONT, pid, NULL, NULL);          // continue process
    waitpid(pid, NULL, 0);                         // wait for close to finish
    printf("closed file\n");

    // puting old memory back
    putdata(pid, addr, backup, size);
    ptrace(PTRACE_SETREGS, pid, NULL, &oldregisters);

    ptrace(PTRACE_DETACH, pid, NULL, NULL); // adios
    printf("done\n");
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        printf("Usage: %s <pid> <fd> <path>\n", argv[0]);
        return 1;
    }

    return redirect_fd_to_path(argv[1], argv[2], argv[3]);
}