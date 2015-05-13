#ifndef __JELLY_H__
#define __JELLY_H__

#include <CL/cl.h>

struct jellyfish{
    cl_context ctx;
    cl_device_id dev;
    cl_platform_id platform;
    cl_program program;
    cl_command_queue cq;
    cl_kernel kernels[3];
};

// globals
int correct_packet = 0;
cl_mem logger, output, input, local, group, storage;
cl_int err;
size_t global_size = 4;
size_t local_size = 2;

#endif
