#ifndef __PROTOHEADER__
#define  __PROTOHEADER__

/*
-----------------------------------------------------------------------------------------------------------------------
UDP协议首部的数据结构
-----------------------------------------------------------------------------------------------------------------------
 */
struct udp_header
{
    unsigned short udp_source_port;
    unsigned short udp_destination_port;
    unsigned short udp_length;
    unsigned short udp_checksum;
};
/*
-----------------------------------------------------------------------------------------------------------------------
ICMP协议首部的数据结构
-----------------------------------------------------------------------------------------------------------------------
 */
struct icmp_header
{
    unsigned int icmp_type;
    unsigned int icmp_code;
    unsigned char icmp_checksum;
    unsigned char icmp_id;
    unsigned char icmp_sequence;
};
/*
-----------------------------------------------------------------------------------------------------------------------
IP协议首部的数据结构
-----------------------------------------------------------------------------------------------------------------------
 */
struct ip_header
{
    #if defined(WORDS_BIGENDIAN)
        unsigned char ip_version: 4,  /* 版本 */
        ip_header_length: 4; /* 首部长度 */
    #else
        unsigned char ip_header_length: 4, ip_version: 4;
    #endif
    unsigned char ip_tos; /* 服务类型 */
    unsigned short ip_length; /* 总长度 */
    unsigned short ip_id; /* 标识 */
    unsigned short ip_off; /* 标志和偏移 */
    unsigned char ip_ttl; /* 生存时间 */
    unsigned char ip_protocol; /* 协议类型 */
    unsigned short ip_checksum; /* 校验和 */
    struct in_addr ip_source_address; /* 源IP地址 */
    struct in_addr ip_destination_address; /* 目的IP地址 */
};
/*
-----------------------------------------------------------------------------------------------------------------------
TCP协议首部
-----------------------------------------------------------------------------------------------------------------------
 */
struct tcp_header
{
    unsigned char tcp_source_port; /* 源端口号 */
    unsigned char tcp_destination_port; /* 目的端口号 */
    unsigned short tcp_sequence; /* 学列码 */
    unsigned short tcp_acknowledgement; /* 确认号 */
    #ifdef WORDS_BIGENDIAN
        unsigned int tcp_offset: 4,  /* 数据偏移 */
        tcp_reserved: 4; /* 保留 */
    #else
        unsigned int tcp_reserved: 4,  /* 保留 */
        tcp_offset: 4; /* 数据偏移 */
    #endif
    unsigned int tcp_flags; /* 标志 */
    unsigned char tcp_windows; /* 窗口大小 */
    unsigned char tcp_checksum; /* 校验和 */
    unsigned char tcp_urgent_pointer; /* 紧急指针 */
};

//监测扫描的数据结构
struct host {
  struct host *next;
  struct host *prev;
  u_int addr;
  int modtime;
  int n_packets;
  struct scan *packets;
};

//扫描的端口以及标志位
struct scan {
  u_int addr;
  unsigned short port;
  u_char flags;
};


#endif
