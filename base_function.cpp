#include "base_type.h"

extern All_list_hdr_t Alist_Hdr;
extern double zero_t;
extern int line;
extern int flag_icmp;
extern int flag_tcp;
extern int flag_udp;
extern int flag_arp;
//回调函数，第一个参数argument为pcap_loop中的第三个参数，第二个参数为pcap文件中数据包头，第三个参数为pcap文件中数据包内容
void pcap_callback_t(uchar8_t *argument, const struct pcap_pkthdr* pkt_header, const uchar8_t *pkt_content) //可能会有问题
{
    uchar8_t *rm_warning ;
    rm_warning = argument;  //消除警告
    //将数据分类并存入链表
    struct EtherHeader *ethernet;
    struct IPHeader *ip;
    struct ICMPHeader *icmp;
    struct TCPHeader *tcp;
    struct UDPHeader *udp;
    struct ARPHeader *arp;
    static ICMP_List_t *temp_icmp = NULL;
    static TCP_List_t *temp_tcp = NULL;
    static UDP_List_t *temp_udp = NULL;
    static ARP_List_t *temp_arp = NULL;
    if(line == 0)
        zero_t = (double)pkt_header->ts.tv_sec + ((double)(pkt_header->ts.tv_usec)/1000000);
    ethernet = (struct EtherHeader *)pkt_content;
    switch(ntohs(ethernet->FrameType))
    {
        //IPv4 MAC头中类型码 0x0800
        case EPT_IP:
            ip = (struct IPHeader *)(pkt_content+ETH_HLEN);
            switch(ip->Protocol)
            {
                //ICMP IP头中类型码为 1
                case IPT_ICMP:
                    icmp = (struct ICMPHeader *)(pkt_content+ETH_HLEN+IP_HLEN);
                    Alist_Hdr.icmp_num = Alist_Hdr.icmp_num + 1;
                    if(flag_icmp == 1){
                        temp_icmp = (ICMP_List_t *)malloc(sizeof(ICMP_List_t) + (pkt_header->caplen)-(ETH_HLEN+IP_HLEN+ICMP_HLEN));
                        Alist_Hdr.icmp_listhdr = temp_icmp;
                    }
                    else{
                        temp_icmp->next = (ICMP_List_t *)malloc(sizeof(ICMP_List_t) + (pkt_header->caplen)-(ETH_HLEN+IP_HLEN+ICMP_HLEN));
                        temp_icmp = temp_icmp->next;
                        temp_icmp->next = NULL;                        
                    }
                    PcapHdrCopy(pkt_header,&(temp_icmp->pkthdr));
                    EtherHdrCopy(ethernet,&(temp_icmp->etherhdr));
                    IPHdrCopy(ip,&(temp_icmp->iphdr));
                    ICMPHdrCopy(icmp,&(temp_icmp->icmphdr));
                    DataChToCh((pkt_content+ETH_HLEN+IP_HLEN+ICMP_HLEN), temp_icmp->data, (pkt_header->caplen)-(ETH_HLEN+IP_HLEN+ICMP_HLEN));
                    temp_icmp->Seq_num = line+1;
                    flag_icmp = 0;
                    switch(icmp->ICMPType)
                    {
                        //请求类型 ICMP头中类型码为 8
                        case ICMP_TYPE_REQUEST:
                            break;
                        //应答类型 ICMP头中类型码为 0
                        case ICMP_TYPE_REPLY:
                            break;
                        //其他类型 目标不可达、超时、源抑制、时间戳请求等
                        default:
                            break;
                    }
                    break;
                //TCP IP头中类型码为 6
                case IPT_TCP:
                    tcp = (struct TCPHeader *)(pkt_content+ETH_HLEN+IP_HLEN);
                    Alist_Hdr.tcp_num = Alist_Hdr.tcp_num + 1;
                    if(flag_tcp == 1){
                        temp_tcp = (TCP_List_t *)malloc(sizeof(TCP_List_t) + (pkt_header->caplen)-(ETH_HLEN+IP_HLEN+TCP_HLEN));
                        Alist_Hdr.tcp_listhdr = temp_tcp;
                    }
                    else{
                        temp_tcp->next = (TCP_List_t *)malloc(sizeof(TCP_List_t) + (pkt_header->caplen)-(ETH_HLEN+IP_HLEN+TCP_HLEN));
                        temp_tcp = temp_tcp->next;
                        temp_tcp->next = NULL;                        
                    }
                    PcapHdrCopy(pkt_header,&(temp_tcp->pkthdr));
                    EtherHdrCopy(ethernet,&(temp_tcp->etherhdr));
                    IPHdrCopy(ip,&(temp_tcp->iphdr));
                    TCPHdrCopy(tcp,&(temp_tcp->tcphdr));
                    DataChToCh(pkt_content+ETH_HLEN+IP_HLEN+(temp_tcp->tcphdr.HeaderLen)/4,temp_tcp->data,(pkt_header->caplen)-(ETH_HLEN+IP_HLEN+(temp_tcp->tcphdr.HeaderLen)/4));
                    temp_tcp->Seq_num = line+1;
                    flag_tcp = 0;
                    break;
                //UDP IP头中类型码为 17
                case IPT_UDP:
                    udp = (struct UDPHeader *)(pkt_content+ETH_HLEN+IP_HLEN);
                    Alist_Hdr.udp_num = Alist_Hdr.udp_num + 1;
                    if(flag_udp == 1){
                        temp_udp = (UDP_List_t *)malloc(sizeof(UDP_List_t) + (pkt_header->caplen)-(ETH_HLEN+IP_HLEN+UDP_HLEN));
                        Alist_Hdr.udp_listhdr = temp_udp;
                    }
                    else{
                        temp_udp->next = (UDP_List_t *)malloc(sizeof(UDP_List_t) + (pkt_header->caplen)-(ETH_HLEN+IP_HLEN+UDP_HLEN));
                        temp_udp = temp_udp->next;
                        temp_udp->next = NULL;
                    }
                    PcapHdrCopy(pkt_header,&(temp_udp->pkthdr));
                    EtherHdrCopy(ethernet,&(temp_udp->etherhdr));
                    IPHdrCopy(ip,&(temp_udp->iphdr));
                    UDPHdrCopy(udp,&(temp_udp->udphdr));
                    DataChToCh(pkt_content+ETH_HLEN+IP_HLEN+UDP_HLEN,temp_udp->data,(pkt_header->caplen)-(ETH_HLEN+IP_HLEN+UDP_HLEN));
                    temp_udp->Seq_num = line+1;
                    flag_udp = 0;
                    break;
                default:
                    break;
            }
            break;
        //ARP MAC头中类型码 0x0806
        case EPT_ARP:
            arp = (struct ARPHeader *)(pkt_content+ETH_HLEN);
            Alist_Hdr.arp_num = Alist_Hdr.arp_num + 1;
            if(flag_arp == 1){
                temp_arp = (ARP_List_t *)malloc(sizeof(ARP_List_t) + (pkt_header->caplen)-(ETH_HLEN+ARP_HLEN));
                Alist_Hdr.arp_listhdr = temp_arp;
            }
            else{
                temp_arp->next = (ARP_List_t *)malloc(sizeof(ARP_List_t) + (pkt_header->caplen)-(ETH_HLEN+ARP_HLEN));
                temp_arp = temp_arp->next;
                temp_arp->next = NULL;               
            }
            PcapHdrCopy(pkt_header,&(temp_arp->pkthdr));
            EtherHdrCopy(ethernet,&(temp_arp->etherhdr));
            ARPHdrCopy(arp,&(temp_arp->arphdr));
            DataChToCh(pkt_content+ETH_HLEN+ARP_HLEN,temp_arp->data,(pkt_header->caplen)-(ETH_HLEN+ARP_HLEN));
            temp_arp->Seq_num = line+1;
            flag_arp = 0;
            switch(arp->ARPOP)
            {
                //ARP请求 值为1
                case ARP_REQUSET:
                    break;
                //ARP应答 值为2
                case ARP_REPLY:
                    break;
                default:
                    break;
            }
            break;
        //IPv6 MAC头中的类型码 0x86dd
        case ETHERTYPE_IPV6:
            break;
        //其他类型RARP、VLAN等
        default:
            break;
    }
    line++;
}

//将二进制字符串转换为十六进制字符串，长度变为两倍
void data_ucharToHexstr(uchar8_t *source , uint32_t length , char *str)
{
    uchar8_t byte[2];
    for(uint32_t i=0; i<length; i++){
        byte[0] = source[i]/16; //字符高4位
        byte[1] = source[i]%16; //字符低4位
        if(byte[0]>=0 && byte[0]<=9)
            str[2*i] = '0' + byte[0];
        else
            str[2*i] = 'a' + byte[0] - 10;
        if(byte[1]>=0 && byte[1]<=9)
            str[2*i+1] = '0' + byte[1];
        else
            str[2*i+1] = 'a' + byte[1] -10;
    }
}
//将十六进制字符串转换为二进制字符串，长度变为二分之一
void data_HexstrTochar(char *source , int length , char *dest_str)
{
    char byte[2];
    for(int i=0; i<length; i++){
        if(source[2*i]>='0' && source[2*i]<= '9')
            byte[0] = source[2*i] - '0';
        else
            byte[0] = source[2*i] - 'a' + 10;
        if(source[2*i+1]>='0' && source[2*i+1]<= '9')
            byte[1] = source[2*i+1] - '0';
        else
            byte[1] = source[2*i+1] - 'a' + 10;
        dest_str[i] = byte[0]*16 + byte[1]; //高位左移4位加上低位
    }
}
//4位的十六进制字节计数
void _4No_pro(int num, char *no_now)
{
    for(int i=0; i<4; i++){
        no_now[i] = '0';
    }
    int temp[2];
    temp[0] = num/16;
    temp[1] = num%16;
    if(temp[1] < 10){
        no_now[2] = '0'+temp[1];
        no_now[1] = '0'+temp[0];
    }
    else{
        no_now[2] = 'a'+temp[1]-10;
        no_now[1] = '0'+temp[0];
    }
}

QString ucharToHexQStr(uchar8_t ch)
{
    uchar8_t byte[2];
    QString str;
    byte[0] = ch/16;
    byte[1] = ch%16;
    for(int i=0; i<2; i++){
        if(byte[i]>=0 && byte[i]<=9)
            byte[i] = '0'+ byte[i];
        else
            byte[i] = 'a'+ byte[i] - 10;
    }
    str = QString(QLatin1Char(byte[0]))+QString(QLatin1Char(byte[1]));
    return str;
}

QString ushortToHexQStr(uint16_t ch)
{
    uchar8_t byte[2];
    byte[0] = (uchar8_t)(ch>>8);
    byte[1] = (uchar8_t)ch;
    return ucharToHexQStr(byte[0])+ucharToHexQStr(byte[1]);
}

QString uintToIPQstr(uint32_t ip)
{
    QString str = "";
    uchar8_t *temp_srcIP = (uchar8_t *)(&ip);
    for(int i=0; i<4; i++){
        str += QString::number(temp_srcIP[i]);
        if(i!=3)
            str += ".";
    }
    return str;
}

QString ucharToMACQstr(uchar8_t *ether)
{
    QString str = "";
    for(int i=0; i<6; i++){
        str += ucharToHexQStr(ether[i]);
        if(i!=5)
            str += ":";
    }
    return str;
}

void PcapHdrCopy(const struct pcap_pkthdr *src_pcappkt, pcapPktHeader_t *dst_pcappkt)    //pcap数据包头的复制
{
    dst_pcappkt->len = src_pcappkt->len;
    dst_pcappkt->caplen = src_pcappkt->caplen;
    dst_pcappkt->ts.ts_sec = src_pcappkt->ts.tv_sec;
    dst_pcappkt->ts.ts_usec = src_pcappkt->ts.tv_usec;
}

void EtherHdrCopy(EtherHeader_t *src_ether,EtherHeader_t *dst_ether)  //以太网头的复制
{
    for(int i=0; i<6; i++){
        dst_ether->SrcMAC[i] = src_ether->SrcMAC[i];
        dst_ether->DstMAC[i] = src_ether->DstMAC[i];
    }
    dst_ether->FrameType = src_ether->FrameType;
}
void IPHdrCopy(IPHeader_t *src_ip,IPHeader_t *dst_ip)  //IP头的复制
{
    dst_ip->Ver_Hlen = src_ip->Ver_Hlen;
    dst_ip->TOS = src_ip->TOS;
    dst_ip->TotalLen = src_ip->TotalLen;
    dst_ip->ID = src_ip->ID;
    dst_ip->Flag_Segment = src_ip->Flag_Segment;
    dst_ip->TTL = src_ip->TTL;
    dst_ip->Protocol = src_ip->Protocol;
    dst_ip->Checksum = src_ip->Checksum;
    dst_ip->SrcIP = src_ip->SrcIP;
    dst_ip->DstIP = src_ip->DstIP;
}
void ICMPHdrCopy(ICMPHeader_t *src_icmp,ICMPHeader_t *dst_icmp)   //ICMP头的复制
{
    dst_icmp->ICMPCode = src_icmp->ICMPCode;
    dst_icmp->ICMPType = src_icmp->ICMPType;
    dst_icmp->Checksum = src_icmp->Checksum;
}
void TCPHdrCopy(TCPHeader_t *src_tcp,TCPHeader_t *dst_tcp) //TCP头的复制
{
    dst_tcp->SrcPort = src_tcp->SrcPort;
    dst_tcp->DstPort = src_tcp->DstPort;
    dst_tcp->SeqNum = src_tcp->SeqNum;
    dst_tcp->AckNum = src_tcp->AckNum;
    dst_tcp->HeaderLen = src_tcp->HeaderLen;
    dst_tcp->Flags = src_tcp->Flags;
    dst_tcp->Window = src_tcp->Window;
    dst_tcp->Checksum = src_tcp->Checksum;
    dst_tcp->UrgentPoint = src_tcp->UrgentPoint;
}
void UDPHdrCopy(UDPHeader_t *src_udp,UDPHeader_t *dst_udp) //UDP头的复制
{
    dst_udp->SrcPort = src_udp->SrcPort;
    dst_udp->DstPort = src_udp->DstPort;
    dst_udp->SegLen= src_udp->SegLen;
    dst_udp->Checksum = src_udp->Checksum;
}
void ARPHdrCopy(ARPHeader_t *src_arp,ARPHeader_t *dst_arp) //ARP头的复制
{
    dst_arp->ARPHrd = src_arp->ARPHrd;
    dst_arp->ARPPro = src_arp->ARPPro;
    dst_arp->ARPHLn = src_arp->ARPHLn;
    dst_arp->ARPPln = src_arp->ARPPln;
    dst_arp->ARPOP = src_arp->ARPOP;
}
void DataChToCh(const uchar8_t *src_ch,uchar8_t *dst_ch,uint32_t len) //字符串的复制
{
    for(uint32_t i=0; i<len; i++){
        dst_ch[i] = src_ch[i];
    }
    dst_ch[len] = '\0';
}

bool FindHttpStr(QString str)
{
    for(int i=0; i<(str.length()-4); i++){
        if(str.mid(i,4) == "HTTP")
            return true;
    }
    return false;
}

bool DNSJudgeFunc(UDPHeader_t udp_hdr)
{
    if(ntohs(udp_hdr.SrcPort) == 53 || ntohs(udp_hdr.DstPort) == 53)
        return true;
    else
        return false;
}

bool DHCPJudgeFunc(UDPHeader_t udp_hdr)
{
    if((ntohs(udp_hdr.SrcPort) == 67 && ntohs(udp_hdr.DstPort) == 68) ||
            (ntohs(udp_hdr.SrcPort) == 68 && ntohs(udp_hdr.DstPort) == 67))
        return true;
    else
        return false;
}
