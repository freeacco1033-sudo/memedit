#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <math.h>
#include <errno.h>
#include <libgen.h>
#include <elf.h>

ssize_t read_mem(pid_t pid, unsigned long addr, void *buf, size_t len) {
    struct iovec local = { buf, len };
    struct iovec remote = { (void*)addr, len };
    ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (n > 0) return n;
    if (errno == ENOSYS || errno == EPERM) {
        for (size_t i = 0; i < len; i += sizeof(long)) {
            long word = ptrace(PTRACE_PEEKDATA, pid, (void*)(addr + i), NULL);
            if (word == -1) return -1;
            size_t copy = (len - i < sizeof(long)) ? len - i : sizeof(long);
            memcpy((char*)buf + i, &word, copy);
        }
        return len;
    }
    return -1;
}

ssize_t write_mem(pid_t pid, unsigned long addr, const void *buf, size_t len) {
    struct iovec local = { (void*)buf, len };
    struct iovec remote = { (void*)addr, len };
    ssize_t n = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    if (n > 0) return n;
    if (errno == ENOSYS || errno == EPERM) {
        for (size_t i = 0; i < len; i += sizeof(long)) {
            long word;
            size_t copy = (len - i < sizeof(long)) ? len - i : sizeof(long);
            memcpy(&word, (char*)buf + i, copy);
            if (ptrace(PTRACE_POKEDATA, pid, (void*)(addr + i), (void*)word) == -1) return -1;
        }
        return len;
    }
    return -1;
}

void attach_process(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace ATTACH");
        exit(1);
    }
    waitpid(pid, NULL, 0);
}

void detach_process(pid_t pid) {
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

int scan_and_replace_count(pid_t pid, float target, float new_value) {
    char maps_path[128];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *fp = fopen(maps_path, "r");
    if (!fp) return 0;

    unsigned long start, end;
    char perms[5];
    char path[256];
    int count = 0;

    while (fscanf(fp, "%lx-%lx %4s %*s %*s %*s %255[^\n]", &start, &end, perms, path) == 3) {
        if (perms[0] != 'r' || perms[1] != 'w') continue;
        size_t len = end - start;
        if (len == 0 || len > 200 * 1024 * 1024) continue;

        char *buf = malloc(len);
        if (!buf) continue;
        ssize_t nread = read_mem(pid, start, buf, len);
        if (nread <= 0) { free(buf); continue; }

        for (size_t i = 0; i + 4 <= (size_t)nread; i += 4) {
            float val;
            memcpy(&val, buf + i, sizeof(val));
            if (fabsf(val - target) < 0.01f) {
                if (write_mem(pid, start + i, &new_value, sizeof(new_value)) > 0)
                    count++;
            }
        }
        free(buf);
    }
    fclose(fp);
    return count;
}

void loop_scan(pid_t pid, float target, float new_value, int interval_ms) {
    int attempt = 0;
    while (1) {
        attempt++;
        int n = scan_and_replace_count(pid, target, new_value);
        printf("[%d] Patched %d\n", attempt, n);
        fflush(stdout);
        usleep(interval_ms * 1000);
    }
}

void scan_and_replace(pid_t pid, float target, float new_value) {
    int c = scan_and_replace_count(pid, target, new_value);
    printf("Patched %d occurrences\n", c);
}

void dump_libs(pid_t pid, const char *outdir) {
    char maps_path[128];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *fp = fopen(maps_path, "r");
    if (!fp) { perror("fopen maps"); return; }

    char mkdir_cmd[512];
    snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p %s", outdir);
    system(mkdir_cmd);

    attach_process(pid);

    char line[512];
    int count = 0;
    while (fgets(line, sizeof(line), fp)) {
        unsigned long start, end;
        char perms[5];
        char path[256] = {0};
        if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %255[^\n]", &start, &end, perms, path) < 3) continue;
        if (strstr(path, ".so") == NULL) continue;
        if (perms[0] != 'r') continue;

        char filename[512];
        char *base = basename(path);
        snprintf(filename, sizeof(filename), "%s/%s_%lx_%lx.so", outdir, base, start, end);
        FILE *out = fopen(filename, "wb");
        if (!out) continue;

        size_t len = end - start;
        char *buf = malloc(len);
        if (!buf) { fclose(out); continue; }
        ssize_t n = read_mem(pid, start, buf, len);
        if (n > 0) { fwrite(buf, 1, n, out); count++; }
        free(buf);
        fclose(out);
    }

    fclose(fp);
    detach_process(pid);
    printf("Total dumped: %d files\n", count);
}

void dump_single_lib(pid_t pid, const char *libname, const char *outpath) {
    char maps_path[128];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *fp = fopen(maps_path, "r");
    if (!fp) { perror("fopen maps"); return; }

    unsigned long base_addr = 0;
    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), fp)) {
        unsigned long start, end;
        char perms[5];
        char path[256] = {0};
        if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %255[^\n]", &start, &end, perms, path) < 3) continue;
        if (strstr(path, libname) != NULL && strstr(perms, "r-xp") != NULL) {
            base_addr = start;
            found = 1;
            break;
        }
    }
    fclose(fp);
    if (!found) { printf("Library %s not found\n", libname); return; }

    attach_process(pid);

    unsigned char ident[16];
    if (read_mem(pid, base_addr, ident, 16) <= 0) {
        printf("Failed to read ELF identification\n");
        detach_process(pid);
        return;
    }

    FILE *out = fopen(outpath, "wb");
    if (!out) { perror("fopen output"); detach_process(pid); return; }

    if (ident[EI_CLASS] == ELFCLASS64) {
        Elf64_Ehdr ehdr;
        if (read_mem(pid, base_addr, &ehdr, sizeof(ehdr)) <= 0) {
            fclose(out); detach_process(pid); return;
        }
        fwrite(&ehdr, sizeof(ehdr), 1, out);
        for (int i = 0; i < ehdr.e_phnum; i++) {
            Elf64_Phdr phdr;
            unsigned long phdr_addr = base_addr + ehdr.e_phoff + i * ehdr.e_phentsize;
            if (read_mem(pid, phdr_addr, &phdr, sizeof(phdr)) <= 0) continue;
            if (phdr.p_type == PT_LOAD && phdr.p_filesz > 0) {
                fseek(out, phdr.p_offset, SEEK_SET);
                char *buf = malloc(phdr.p_filesz);
                if (read_mem(pid, base_addr + phdr.p_vaddr, buf, phdr.p_filesz) > 0)
                    fwrite(buf, 1, phdr.p_filesz, out);
                free(buf);
            }
        }
    } else if (ident[EI_CLASS] == ELFCLASS32) {
        Elf32_Ehdr ehdr;
        if (read_mem(pid, base_addr, &ehdr, sizeof(ehdr)) <= 0) {
            fclose(out); detach_process(pid); return;
        }
        fwrite(&ehdr, sizeof(ehdr), 1, out);
        for (int i = 0; i < ehdr.e_phnum; i++) {
            Elf32_Phdr phdr;
            unsigned long phdr_addr = base_addr + ehdr.e_phoff + i * ehdr.e_phentsize;
            if (read_mem(pid, phdr_addr, &phdr, sizeof(phdr)) <= 0) continue;
            if (phdr.p_type == PT_LOAD && phdr.p_filesz > 0) {
                fseek(out, phdr.p_offset, SEEK_SET);
                char *buf = malloc(phdr.p_filesz);
                if (read_mem(pid, base_addr + phdr.p_vaddr, buf, phdr.p_filesz) > 0)
                    fwrite(buf, 1, phdr.p_filesz, out);
                free(buf);
            }
        }
    }

    fclose(out);
    detach_process(pid);
    printf("Dumped %s to %s\n", libname, outpath);
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s read <pid> <address>\n", argv[0]);
        fprintf(stderr, "  %s write <pid> <address> <value_float>\n", argv[0]);
        fprintf(stderr, "  %s writei <pid> <address> <value_int>\n", argv[0]);
        fprintf(stderr, "  %s writeb <pid> <address> <value_byte>\n", argv[0]);
        fprintf(stderr, "  %s scan <pid> <target_float> <new_float>\n", argv[0]);
        fprintf(stderr, "  %s loopscan <pid> <target_float> <new_float> <interval_ms>\n", argv[0]);
        fprintf(stderr, "  %s dumplibs <pid> <output_dir>\n", argv[0]);
        fprintf(stderr, "  %s dumpelf <pid> <libname> <output_path>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[2]);

    if (strcmp(argv[1], "loopscan") == 0 && argc == 6) {
        float target = atof(argv[3]);
        float new_val = atof(argv[4]);
        int interval = atoi(argv[5]);
        loop_scan(pid, target, new_val, interval);
        return 0;
    }

    if (strcmp(argv[1], "scan") == 0 && argc == 5) {
        scan_and_replace(pid, atof(argv[3]), atof(argv[4]));
        return 0;
    }

    if (strcmp(argv[1], "dumplibs") == 0 && argc == 4) {
        dump_libs(pid, argv[3]);
        return 0;
    }

    if (strcmp(argv[1], "dumpelf") == 0 && argc == 5) {
        dump_single_lib(pid, argv[3], argv[4]);
        return 0;
    }

    unsigned long addr = strtoul(argv[3], NULL, 16);

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace ATTACH");
        return 1;
    }
    waitpid(pid, NULL, 0);

    if (strcmp(argv[1], "read") == 0) {
        float result;
        if (read_mem(pid, addr, &result, sizeof(result)) <= 0) {
            perror("read");
            ptrace(PTRACE_DETACH, pid, NULL, NULL);
            return 1;
        }
        printf("0x%lx = %f\n", addr, result);
    } else if (strcmp(argv[1], "write") == 0 && argc == 5) {
        float value = atof(argv[4]);
        if (write_mem(pid, addr, &value, sizeof(value)) <= 0) {
            perror("write");
            ptrace(PTRACE_DETACH, pid, NULL, NULL);
            return 1;
        }
        printf("OK\n");
    } else if (strcmp(argv[1], "writei") == 0 && argc == 5) {
        int value = atoi(argv[4]);
        if (write_mem(pid, addr, &value, sizeof(value)) <= 0) {
            perror("writei");
            ptrace(PTRACE_DETACH, pid, NULL, NULL);
            return 1;
        }
        printf("OK\n");
    } else if (strcmp(argv[1], "writeb") == 0 && argc == 5) {
        unsigned char value = (unsigned char)atoi(argv[4]);
        if (write_mem(pid, addr, &value, 1) <= 0) {
            perror("writeb");
            ptrace(PTRACE_DETACH, pid, NULL, NULL);
            return 1;
        }
        printf("OK\n");
    } else {
        fprintf(stderr, "Invalid arguments\n");
    }

    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 0;
}
