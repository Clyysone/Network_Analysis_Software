#ifndef BASE_TYPE_H
#define BASE_TYPE_H

#include <pcap.h>
#include <qstring.h>
#define PCAP_FILE_MAGIC_1 0Xd4
#define PCAP_FILE_MAGIC_2 0Xc3
#define PCAP_FILE_MAGIC_3 0Xb2
#define PCAP_FILE_MAGIC_4 0Xa1

//const uint32_t MAX_MTU = 1500; //设置最大MTU为1500

typedef char char8_t;
typedef short int16_t;
typedef int int32_t;
typedef long long64_t;
typedef unsigned char uchar8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long ulong64_t;

//pcap文件头结构体(24字节)
typedef struct pcapFileHeader{
    uchar8_t magic[4]; //读取顺序(4字节)
    uint16_t version_major; //主要版本号(2字节)
    uint16_t version_minor; //次要版本号(2字节)
    int32_t thiszone; //时区修正(4字节)
    uint32_t sigfigs; //精准时间戳(4字节)
    uint32_t snaplen; //抓包最大长度(4字节)
    uint32_t linktype; //链路类型(4字节)
}pcapFileHeader_t;

//pcap数据包头结构体(16字节)
typedef struct pcapPktHeader{
    uint32_t seconds; //秒数(4字节)
    uint32_t u_seconds; //毫秒数(4字节)
    uint32_t caplen; //数据包长度(4字节)
    uint32_t len; //文件数据包长度(4字节)
}pcapPktHeader_t;

//MAC数据帧头(14字节)
typedef struct MACHeader{
    uchar8_t DstMAC[6]; //目的MAC地址(6字节)
    uchar8_t SrcMAC[6]; //源MAC地址(6字节)
    uint16_t FrameType; //帧类型(2字节)
}MACHeader_t;

//MA数据帧尾(4字节)
typedef struct MACTail{
    uint32_t Checksum; //数据帧尾校验和(4字节)
}MACTail_t;

//IP数据报头(20字节)
typedef struct IPHeader{
    uchar8_t Ver_Hlen; //版本+报头长度(1字节)
    uchar8_t TOS; //服务类型(1字节)
    uint16_t TotalLen; //总长度(2字节)
    uint16_t ID; //标识(2字节)
    uint16_t Flag_Segment; //标志(3bit)+片偏移(13bit)(2字节)
    uchar8_t TTL; //生存周期(1字节)
    uchar8_t Protocol; //协议类型(1字节)
    uint16_t Checksum; //头部校验和(2字节)
    uint32_t SrcIP; //源IP地址(4字节)
    uint32_t DstIP; //目的IP地址(4字节)
}IPHeader_t;

//TCP报文段头(20字节)
typedef struct TCPHeader{
    uint16_t SrcPort; //源端口(2字节)
    uint16_t DstPort; //目的端口(2字节)
    uint32_t SeqNum; //序号(4字节)
    uint32_t AckNum; //确认号(4字节)
    uchar8_t HeaderLen; //数据报头的长度(4bit)+保留(4bit)(1字节)
    uchar8_t Flags; //标识TCP不同的控制信息(1字节)
    uint16_t Window; //窗口大小(2字节)
    uint16_t Checksum; //校验和(2字节)
    uint16_t UrgentPoint; //紧急指针(2字节)
}TCPHeader_t;

//TCP可选选项部分
typedef struct TCPOptions{
    char8_t m_ckind;
    char8_t m_cLength;
    char8_t m_cContext[32];
}TCPOption_t;

//UDP报文段头(8字节）
typedef struct UDPHeader{
    uint16_t SrcPort; //源端口号(2字节)
    uint16_t DstPort; //目的端口号(2字节)
    uint16_t HeaderLen; //头部长度(2字节)
    uint16_t Checksum; //校验和(2字节)
}UDPHeader_t;

//ICMP头部(4字节）
typedef struct ICMPHeader{
    uchar8_t ICMPType; //类型(1字节)
    uchar8_t ICMPCode; //代码(1字节)
    uint16_t Checksum; //校验和(2字节)
}ICMPHeader_t;

//pcap中一个包，包含指向下一个包的指针
typedef struct pcappkt{
    pcappkt *nextpkt;
    pcapPktHeader_t pkthdr;
    uchar8_t pktdata[];
}pcappkt_t;

void pcap_callback_t(uchar8_t *argument, const struct pcap_pkthdr* pkt_header, const uchar8_t *pkt_content);
char* data_ucharTostr(uchar *source , int length);
char* _4No_pro(int num);
#endif // BASE_TYPE_H
