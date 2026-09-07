#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <errno.h>
#include <math.h>

// دالة لقراءة كتلة من الذاكرة باستخدام process_vm_readv مع fallback إلى ptrace
ssize_t read_mem(pid_t pid, unsigned long addr, void *buf, size_t len) {
    struct iovec local = { buf, len };
    struct iovec remote = { (void*)addr, len };
    ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (n > 0) return n;
    // fallback إلى ptrace بالكلمات
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

// دالة لكتابة كتلة من الذاكرة باستخدام process_vm_writev مع fallback إلى ptrace
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

// أمر البحث والاستبدال
void scan_and_replace(pid_t pid, float target, float new_value) {
    char maps_path[128];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *fp = fopen(maps_path, "r");
    if (!fp) {
        perror("fopen maps");
        return;
    }

    unsigned long start, end;
    char perms[5];
    char path[256];
    int count = 0;

    while (fscanf(fp, "%lx-%lx %4s %*s %*s %*s %255[^\n]", &start, &end, perms, path) == 3) {
        // نبحث في المناطق القابلة للقراءة والكتابة فقط (rw-p)
        if (perms[0] != 'r' || perms[1] != 'w') continue;
        size_t len = end - start;
        if (len == 0 || len > 200 * 1024 * 1024) continue; // تجاهل المناطق الضخمة

        char *buf = malloc(len);
        if (!buf) continue;

        ssize_t nread = read_mem(pid, start, buf, len);
        if (nread <= 0) {
            free(buf);
            continue;
        }

        for (size_t i = 0; i + sizeof(float) <= (size_t)nread; i += 4) {
            float val;
            memcpy(&val, buf + i, sizeof(val));
            if (fabsf(val - target) < 0.01f) { // تطابق تقريبي
                float new_val = new_value;
                if (write_mem(pid, start + i, &new_val, sizeof(new_val)) > 0) {
                    count++;
                }
            }
        }
        free(buf);
    }
    fclose(fp);
    printf("Patched %d occurrences\n", count);
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s read <pid> <address>\n", argv[0]);
        fprintf(stderr, "  %s write <pid> <address> <value_float>\n", argv[0]);
        fprintf(stderr, "  %s writei <pid> <address> <value_int>\n", argv[0]);
        fprintf(stderr, "  %s writeb <pid> <address> <value_byte>\n", argv[0]);
        fprintf(stderr, "  %s scan <pid> <target_float> <new_float>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[2]);

    if (strcmp(argv[1], "scan") == 0 && argc == 5) {
        float target = atof(argv[3]);
        float new_val = atof(argv[4]);
        scan_and_replace(pid, target, new_val);
        return 0;
    }

    // الأوامر الأخرى كما كانت
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
