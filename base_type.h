#ifndef BASE_TYPE_H
#define BASE_TYPE_H

#include <pcap.h>
#include <netinet/ip.h>     //结构体 struct iphdr
#include <netinet/tcp.h>    //结构体 struct tcphdr
#include <netinet/udp.h>    //结构体 struct udphdr
#include <netinet/ip_icmp.h>    //结构体 struct icmphdr
#include <net/if_arp.h>     //结构体 struct arphdr
#include <netinet/if_ether.h>   //结构体 struct ethhdr和 struct ether_arp（整个arp包，包括arp首部）
#include <netinet/in.h>     //定义了IP地址结构struct sockaddr_in
#include <qstring.h>

//定义一些常量
#define EPT_IP 0x0800 //type:IP
#define EPT_ARP 0x0806 //type:ARP
#define EPT_RARP 0x0835 //type:RARP
#define IPT_ICMP 1   //type:ICMP
#define IPT_TCP 6    //type:TCP
#define IPT_UDP 17   //type:UDP
#define ARP_HRD 0x0001 //dummy type for 802.3 frames
#define ARP_REQUSET 0x0001 //ARP request
#define ARP_REPLY 0x0002 //ARP reply
#define ICMP_TYPE_REQUEST 8
#define ICMP_TYPE_REPLY 0

#define ETH_HLEN 14 //以太网头长度
#define IP_HLEN 20  //IP头长度
#define TCP_HLEN 20 //TCP头长度
#define UDP_HLEN 8  //UDP头长度
#define ICMP_HLEN 4 //ICMP头长度
#define ARP_HLEN 8  //  ARP头长度
#define PCAP_FILE_MAGIC_1 0xd4
#define PCAP_FILE_MAGIC_2 0xc3
#define PCAP_FILE_MAGIC_3 0xb2
#define PCAP_FILE_MAGIC_4 0xa1

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
typedef struct ts{
    uint32_t ts_sec;//秒数(4字节)
    uint32_t ts_usec;//毫秒数(4字节)
}ts_t;
typedef struct pcapPktHeader{
    ts_t ts;
    uint32_t caplen; //数据包长度(4字节)
    uint32_t len; //文件数据包长度(4字节)
}pcapPktHeader_t;

//MAC数据帧头(14字节)
typedef struct EtherHeader{
    uchar8_t DstMAC[6]; //目的MAC地址(6字节)
    uchar8_t SrcMAC[6]; //源MAC地址(6字节)
    uint16_t FrameType; //帧类型(2字节)
}EtherHeader_t;

//MA数据帧尾(4字节)
typedef struct EtherTail{
    uint32_t Checksum; //数据帧尾校验和(4字节)
}EtherTail_t;

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
    uint16_t SegLen; //报文段长度(2字节)
    uint16_t Checksum; //校验和(2字节)
}UDPHeader_t;

//ICMP头部(4字节）
typedef struct ICMPHeader{
    uchar8_t ICMPType; //类型(1字节)
    uchar8_t ICMPCode; //代码(1字节)
    uint16_t Checksum; //校验和(2字节)
}ICMPHeader_t;

//ARP头
typedef struct ARPHeader{
    uint16_t ARPHrd;
    uint16_t ARPPro;
    uchar8_t ARPHLn;
    uchar8_t ARPPln;
    uint16_t ARPOP;
}ARPHeader_t;

/*每个协议类型设置一个链表用来存储解析后的数据
 *  ARP ICMP TCP UDP
*/
//ICMP
typedef struct ICMP_List{
    struct ICMP_List *next;
    int Seq_num;
    pcapPktHeader_t pkthdr;
    EtherHeader_t etherhdr;
    IPHeader_t iphdr;
    ICMPHeader_t icmphdr;
    uchar8_t data[];
}ICMP_List_t;

typedef struct TCP_List{
    struct TCP_List *next;
    int Seq_num;
    pcapPktHeader_t pkthdr;
    EtherHeader_t etherhdr;
    IPHeader_t iphdr;
    TCPHeader_t tcphdr;
    uchar8_t data[];
}TCP_List_t;

typedef struct UDP_List{
    struct UDP_List *next;
    int Seq_num;
    pcapPktHeader_t pkthdr;
    EtherHeader_t etherhdr;
    IPHeader_t iphdr;
    UDPHeader_t udphdr;
    uchar8_t data[];
}UDP_List_t;

typedef struct ARP_List{
    struct ARP_List *next;
    int Seq_num;
    pcapPktHeader_t pkthdr;
    EtherHeader_t etherhdr;
    ARPHeader_t arphdr;
    uchar8_t data[];
}ARP_List_t;

//总表（包含所有表的表头指针）
typedef struct All_list_hdr{
    int icmp_num;
    int tcp_num;
    int udp_num;
    int arp_num;
    ICMP_List_t *icmp_listhdr;
    TCP_List_t *tcp_listhdr;
    UDP_List_t *udp_listhdr;
    ARP_List_t *arp_listhdr;
}All_list_hdr_t;

void pcap_callback_t(uchar8_t *argument, const struct pcap_pkthdr* pkt_header, const uchar8_t *pkt_content);
void data_ucharToHexstr(uchar *source , uint32_t length , char *str);
void data_HexstrTochar(char *source , int length , char *dest_str);
void _4No_pro(int num , char *no_now);
QString ucharToHexQStr(uchar8_t ch);
QString ushortToHexQStr(uint32_t ch);
QString uintToIPQstr(uint32_t ip);
QString ucharToMACQstr(uchar8_t *ether);
void PcapHdrCopy(const struct pcap_pkthdr *src_pcappkt, pcapPktHeader_t *dst_pcappkt);
void EtherHdrCopy(EtherHeader_t *src_ether,EtherHeader_t *dst_ether);   //以太网头的复制
void IPHdrCopy(IPHeader_t *src_ip,IPHeader_t *dst_ip);  //IP头的复制
void ICMPHdrCopy(ICMPHeader_t *src_icmp,ICMPHeader_t *dst_icmp);    //ICMP头的复制
void TCPHdrCopy(TCPHeader_t *src_tcp,TCPHeader_t *dst_tcp); //TCP头的复制
void UDPHdrCopy(UDPHeader_t *src_udp,UDPHeader_t *dst_udp); //UDP头的复制
void ARPHdrCopy(ARPHeader_t *src_arp,ARPHeader_t *dst_arp); //ARP头的复制
void DataChToCh(const uchar8_t *src_ch,uchar8_t *dst_ch,uint32_t len); //字符串的复制

#endif // BASE_TYPE_H
