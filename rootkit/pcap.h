#ifndef PCAP_H
#define PCAP_H
#endif

#include <pcap/pcap.h>

#define SNAP_LEN 1518 // default
#define SIZE_UDP 8  // header length

// ip header
struct sniff_ip{
    unsigned char ip_vhl;  // version << 4 | header length >> 2
    unsigned char ip_tos;   // type of service
    unsigned short ip_len;  // total length
    unsigned short ip_id;   // identification
    unsigned short ip_off;  // fragment offset field
    #define IP_RF 0x8000    // reserved fragment flag
    #define IP_DF 0x4000    // don't fragment flag
    #define IP_MF 0x2000    // more fragments flag
    #define IP_OFFMASK 0x1fff  // mask for fragmenting bits
    unsigned char ip_ttl;      // time to live
    unsigned char ip_p;        // protocol
    unsigned short ip_sum;     // checksum
    struct in_addr ip_src, ip_dst;  // source and dest address
};

#define IP_HL(ip)  (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)   (((ip)->ip_vhl) >> 4)

// udp header
struct sniff_udp{
    unsigned short udph_sport;
    unsigned short udph_dport;
    unsigned short udph_len;
    unsigned short udph_chksum;
};

void got_packet_udp(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) __attribute__((visibility("hidden")));
static int (*old_pcap_loop)(pcap_t *p, int cnt, pcap_handler callback, unsigned char *user);
static void (*old_callback)(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
