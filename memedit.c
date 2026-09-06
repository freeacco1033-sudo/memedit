#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s read <pid> <address>\n", argv[0]);
        fprintf(stderr, "  %s write <pid> <address> <value>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[2]);
    unsigned long addr = strtoul(argv[3], NULL, 16);

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace ATTACH");
        return 1;
    }
    waitpid(pid, NULL, 0);

    if (strcmp(argv[1], "read") == 0) {
        unsigned int data = 0;
        for (int i = 0; i < 4; i++) {
            long word = ptrace(PTRACE_PEEKDATA, pid, (void*)(addr + i), NULL);
            if (word == -1) {
                perror("ptrace PEEKDATA");
                ptrace(PTRACE_DETACH, pid, NULL, NULL);
                return 1;
            }
            data |= ((unsigned int)(word & 0xFF)) << (i * 8);
        }
        float result;
        memcpy(&result, &data, sizeof(result));
        printf("0x%lx = %f\n", addr, result);
    } else if (strcmp(argv[1], "write") == 0 && argc == 5) {
        float value = atof(argv[4]);
        unsigned int data;
        memcpy(&data, &value, sizeof(value));
        for (int i = 0; i < 4; i++) {
            unsigned int byte = (data >> (i * 8)) & 0xFF;
            if (ptrace(PTRACE_POKEDATA, pid, (void*)(addr + i), (void*)byte) == -1) {
                perror("ptrace POKEDATA");
                ptrace(PTRACE_DETACH, pid, NULL, NULL);
                return 1;
            }
        }
        printf("OK\n");
    }

    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 0;
}
