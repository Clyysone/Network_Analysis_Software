#include "base_type.h"
#include <QDebug>
#include <pcap.h>

extern pcappkt_t *allpkt_temp;
//回调函数，第一个参数argument为pcap_loop中的第三个参数，第二个参数为pcap文件中数据包头，第三个参数为pcap文件中数据包内容
void pcap_callback_t(uchar8_t *argument, const struct pcap_pkthdr* pkt_header, const uchar8_t *pkt_content)
{
    allpkt_temp->nextpkt = (pcappkt_t *)malloc(sizeof(pcappkt_t)+pkt_header->caplen);
    allpkt_temp = allpkt_temp->nextpkt;
    strcpy((char *)allpkt_temp->pktdate,(char *)pkt_content);
    allpkt_temp->pkthdr.len = pkt_header->len;
    allpkt_temp->pkthdr.caplen = pkt_header->caplen;
    allpkt_temp->pkthdr.seconds = pkt_header->ts.tv_sec;
    allpkt_temp->pkthdr.u_seconds = pkt_header->ts.tv_usec;
    allpkt_temp->nextpkt = NULL;
}

QString data_ucharTostr(uchar *source , int length)
{
    char str[2*length];
    uchar8_t byte[2];
    for(int i=0; i<length; i++){
        byte[0] = source[i]/16;
        byte[1] = source[i]%16;
        if(byte[0]>=0 && byte[0]<=9)
            str[2*i] = '0' + byte[0];
        else
            str[2*i] = 'a' + byte[0] - 10;
        if(byte[1]>=0 && byte[1]<=9)
            str[2*i+1] = '0' +byte[1];
        else
            str[2*i+1] = 'a' + byte[1] -10;
    }
    return QString(QLatin1String(str));
}
