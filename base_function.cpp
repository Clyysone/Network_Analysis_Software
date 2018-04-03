#include "base_type.h"

extern pcappkt_t *allpkt_temp;
//回调函数，第一个参数argument为pcap_loop中的第三个参数，第二个参数为pcap文件中数据包头，第三个参数为pcap文件中数据包内容
void pcap_callback_t(uchar8_t *argument, const struct pcap_pkthdr* pkt_header, const uchar8_t *pkt_content)
{
    uchar8_t *rm_warning ;
    rm_warning = argument;  //消除警告
    allpkt_temp->nextpkt = (pcappkt_t *)malloc(sizeof(pcappkt_t) + pkt_header->caplen);
    allpkt_temp = allpkt_temp->nextpkt;
    for(uint i=0; i<pkt_header->caplen; i++){
        allpkt_temp->pktdata[i] = pkt_content[i];
    }
    allpkt_temp->pkthdr.len = pkt_header->len;
    allpkt_temp->pkthdr.caplen = pkt_header->caplen;
    allpkt_temp->pkthdr.ts.ts_sec = pkt_header->ts.tv_sec;
    allpkt_temp->pkthdr.ts.ts_usec = pkt_header->ts.tv_usec;
    allpkt_temp->nextpkt = NULL;
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

QString charToHexQStr(uchar8_t ch)
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

QString shortToHexQStr(uint32_t ch){
    uchar8_t byte[2];
    byte[0] = (uchar8_t)(ch>>8);
    byte[1] = (uchar8_t)ch;
    return charToHexQStr(byte[0])+charToHexQStr(byte[1]);
}
