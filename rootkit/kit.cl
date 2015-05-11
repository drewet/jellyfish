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

#define g_id get_global_id(0)
#define gr_id get_group_id(0)
#define l_id get_local_id(0)
#define l_size get_local_size(0)

typedef unsigned char (uchar);

__kernel void log_fopen(__global uchar *log, __local uchar *output, __global uchar *storage){
    uchar *input = log[g_id];
    output[l_id] = input;
    barrier(CLK_LOCAL_MEM_FENCE);  // just to be safe

    int i;
    uchar **store;

    if(l_id == 0){
        for(i = 0; i < l_size; i++){
            store += output[i];
	}
	storage[gr_id] += store;
    }
}

__kernel void log_mkdir(__global uchar *log, __local uchar *output, __global uchar *storage){
    uchar *input = log[g_id];
    output[l_id] = input;
    barrier(CLK_LOCAL_MEM_FENCE);  // just to be safe

    int i;
    uchar **store;

    if(l_id == 0){
        for(i = 0; i < l_size; i++){
            store += output[i];
	}
	storage[gr_id] += store;
    }
}

__kernel void log_lstat(__global uchar *log, __local uchar *output, __global uchar *storage){   
    uchar *input = log[g_id];
    output[l_id] = input;
    barrier(CLK_LOCAL_MEM_FENCE);  // just to be safe

    int i;
    uchar **store;

    if(l_id == 0){
        for(i = 0; i < l_size; i++){
            store += output[i];
	}
	storage[gr_id] += store;
    }
}

__kernel void log_lstat64(__global uchar *log, __local uchar *output, __global uchar *storage){   
    uchar *input = log[g_id];
    output[l_id] = input;
    barrier(CLK_LOCAL_MEM_FENCE);  // just to be safe

    int i;
    uchar **store;

    if(l_id == 0){
        for(i = 0; i < l_size; i++){
            store += output[i];
	}
	storage[gr_id] += store;
    }
}

__kernel void log_creat(__global uchar *log, __local uchar *output, __global uchar *storage){   
    uchar *input = log[g_id];
    output[l_id] = input;
    barrier(CLK_LOCAL_MEM_FENCE);  // just to be safe

    int i;
    uchar **store;

    if(l_id == 0){
        for(i = 0; i < l_size; i++){
            store += output[i];
	}
	storage[gr_id] += store;
    }
}

__kernel void log_execve(__global uchar *log, __local uchar *output, __global uchar *storage){   
    uchar *input = log[g_id];
    output[l_id] = input;
    barrier(CLK_LOCAL_MEM_FENCE);  // just to be safe

    int i;
    uchar **store;

    if(l_id == 0){
        for(i = 0; i < l_size; i++){
            store += output[i];
	}
	storage[gr_id] += store;
    }
}

__kernel void log_open(__global uchar *log, __local uchar *output, __global uchar *storage){
    uchar *input = log[g_id];
    output[l_id] = input;
    barrier(CLK_LOCAL_MEM_FENCE);  // just to be safe

    int i;
    uchar **store;

    if(l_id == 0){
        for(i = 0; i < l_size; i++){
            store += output[i];
	}
	storage[gr_id] += store;
    }
}
