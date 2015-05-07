#define g_id get_global_id(0)
#define gr_id get_group_id(0)
#define l_id get_local_id(0)
#define l_size get_local_size(0)

#define key 0x42

typedef unsigned char uchar

__kernel void jelly_xor(__global uchar *input, __local uchar *local_result
			__global uchar *group_result){
    int i;
    uchar **string;

    if(l_id == 0){
        for(i = 0; i < l_size; i++){
            local_result[i] ^= key;
	    string += local_result[i];
	}
	group_result[gr_id] = string;
    } 
}
