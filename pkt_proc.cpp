#include "pkt_proc.h"
#include "ui_pkt_proc.h"

pkt_proc::pkt_proc(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::pkt_proc)
{
    ui->setupUi(this);
    mybox = new QMessageBox(this);
    content_model = new QStandardItemModel();
    time_sec = 0;
    Alist_Hdr = {0,0,0,0,NULL,NULL,NULL,NULL};
    line = 0;
    flag_icmp = flag_tcp = flag_udp = flag_arp = 1;
    analyse_pkt(); //解析包中数据并存在链表中
    overview_init();
    initWidget();  //调用一波初始化
}

pkt_proc::~pkt_proc()
{
    pcap_close(source_pcap_t);
    delete ui;
}

void pkt_proc::analyse_pkt()
{
    //根据路径打开pcap文件
    //***待修改***(文件路径问题）
    QString temp_string = "/Users/yanliang/Desktop/Clyysone/inbox/Bs_Pro/Graduation_pro/";
    temp_string += analyse_filename;
    if((source_pcap_t = pcap_open_offline(temp_string.toLatin1().data()
            ,errbuf)) == NULL){
        mybox->show();
        mybox->setText(analyse_filename+"文件打开失败!");
    }
    else{
        mybox->show();
        mybox->setText(analyse_filename+"文件打开成功!");
    }
    //读取文件中内容到链表当中
    pcap_loop(source_pcap_t,-1,pcap_callback_t,NULL);
}

void pkt_proc::overview_init()
{
    //设置总览中的表格相关信息(表1)
    allinfo_model = new QStandardItemModel();
    allinfo_model->setHorizontalHeaderItem(0,new QStandardItem(QObject::tr("序号")));
    allinfo_model->setHorizontalHeaderItem(1,new QStandardItem(QObject::tr("时间")));
    allinfo_model->setHorizontalHeaderItem(2,new QStandardItem(QObject::tr("源地址")));
    allinfo_model->setHorizontalHeaderItem(3,new QStandardItem(QObject::tr("目的地址")));
    allinfo_model->setHorizontalHeaderItem(4,new QStandardItem(QObject::tr("协议")));
    allinfo_model->setHorizontalHeaderItem(5,new QStandardItem(QObject::tr("长度")));
    allinfo_model->setHorizontalHeaderItem(6,new QStandardItem(QObject::tr("信息")));
    ui->overviewTable->setModel(allinfo_model);
    ui->overviewTable->setSelectionBehavior(QAbstractItemView::SelectRows);//设置为整行选择
    ui->overviewTable->setEditTriggers(QAbstractItemView::NoEditTriggers);//设置为禁止编辑
    ui->overviewTable->setColumnWidth(0,50);
    ui->overviewTable->setColumnWidth(1,80);
    ui->overviewTable->setColumnWidth(2,130);
    ui->overviewTable->setColumnWidth(3,130);
    ui->overviewTable->setColumnWidth(4,50);
    ui->overviewTable->setColumnWidth(5,55);
    ui->overviewTable->setColumnWidth(6,250);

    //显示到总览表(表1)
    /*ETHERNET
     *    IP (0x0800)
     *        ICMP (1)
     *        TCP  (6)
     *           HTTP (80)
     *        UDP  (17)
     *           DHCP (S:67, C:68)
     *           DNS (53)
     *    ARP (0x0806)
    */
    //ICMP , TCP(HTTP) , UDP(DHCP、DNS) , ARP依次遍历后输出到表中
    ICMP_List_t *icmp_p = Alist_Hdr.icmp_listhdr; //初始的icmp链表头指针
    TCP_List_t *tcp_p = Alist_Hdr.tcp_listhdr; //初始的tcp链表头指针
    UDP_List_t *udp_p = Alist_Hdr.udp_listhdr; //初始的udp链表头指针
    ARP_List_t *arp_p = Alist_Hdr.arp_listhdr; //初始的arp链表头指针
    double temp_t;
    //ICMP依次输出到表1
    while(icmp_p){
        temp_t = (double)icmp_p->pkthdr.ts.ts_sec + ((double)(icmp_p->pkthdr.ts.ts_usec)/1000000);
        allinfo_model->setItem(icmp_p->Seq_num-1,0,new QStandardItem(QString::number(icmp_p->Seq_num)));
        allinfo_model->setItem(icmp_p->Seq_num-1,1,new QStandardItem(QString::number(temp_t-zero_t,'f',6)));
        allinfo_model->setItem(icmp_p->Seq_num-1,2,new QStandardItem(uintToIPQstr(icmp_p->iphdr.SrcIP)));
        allinfo_model->setItem(icmp_p->Seq_num-1,3,new QStandardItem(uintToIPQstr(icmp_p->iphdr.DstIP)));
        allinfo_model->setItem(icmp_p->Seq_num-1,4,new QStandardItem("ICMP"));
        allinfo_model->setItem(icmp_p->Seq_num-1,5,new QStandardItem(QString::number(icmp_p->pkthdr.caplen)));
        switch(icmp_p->icmphdr.ICMPType)
        {
            //能返回目的地，响应-应答包(0)
            case ICMP_TYPE_REPLY:
                ICMPType0_t *icmp0;
                icmp0 = (ICMPType0_t *)(icmp_p->data);
                allinfo_model->setItem(icmp_p->Seq_num-1,6,new QStandardItem("Echo reply.id:0x"+
                                                                             ushortToHexQStr(ntohs(icmp0->ICMPID))+" seq:"+
                                                                             ushortToHexQStr(ntohs(icmp0->ICMPSeq))));
                break;
            //不能到达目的地(3)
            case ICMP_TYPE_UNREACH:
                ICMPType3_t *icmp3;
                icmp3 = (ICMPType3_t *)(icmp_p->data);
                allinfo_model->setItem(icmp_p->Seq_num-1,6,new QStandardItem("Destination unreachable "+
                                                                             ushortToHexQStr(ntohs(icmp3->ICMPPmvoid))+" "+
                                                                             ushortToHexQStr(ntohs(icmp3->ICMPNextmtu))));
                break;
            //能到达目的地，响应-请求包(8)
            case ICMP_TYPE_REQUEST:
                ICMPType8_t *icmp8;
                icmp8 = (ICMPType8_t *)(icmp_p->data);
                allinfo_model->setItem(icmp_p->Seq_num-1,6,new QStandardItem("Echo request.id:0x"+
                                                                             ushortToHexQStr(ntohs(icmp8->ICMPID))+" seq:"+
                                                                             ushortToHexQStr(ntohs(icmp8->ICMPSeq))));
                break;
            //超时(11)
            case ICMP_TYPE_TIMEOUT:
                ICMPType11_t *icmp11;
                icmp11 = (ICMPType11_t *)(icmp_p->data);
                allinfo_model->setItem(icmp_p->Seq_num-1,6,new QStandardItem("Time Exceeded "+
                                                                             QString::number(icmp11->ICMPVoid)));
                break;
            //其他类型
            default:
                allinfo_model->setItem(icmp_p->Seq_num-1,6,new QStandardItem("Cant be resolved.This type of ICMP is not supported"));
                break;
        }
        icmp_p = icmp_p->next;
    }
    //TCP(HTTP)依次输出到表1
    while(tcp_p){
        temp_t = (double)tcp_p->pkthdr.ts.ts_sec + ((double)(tcp_p->pkthdr.ts.ts_usec)/1000000);
        allinfo_model->setItem(tcp_p->Seq_num-1,0,new QStandardItem(QString::number(tcp_p->Seq_num)));
        allinfo_model->setItem(tcp_p->Seq_num-1,1,new QStandardItem(QString::number(temp_t-zero_t,'f',6)));
        allinfo_model->setItem(tcp_p->Seq_num-1,2,new QStandardItem(uintToIPQstr(tcp_p->iphdr.SrcIP)));
        allinfo_model->setItem(tcp_p->Seq_num-1,3,new QStandardItem(uintToIPQstr(tcp_p->iphdr.DstIP)));
        //判断是否是HTTP
        if(FindHttpStr(QString(QLatin1String((char *)tcp_p->data)))){
            allinfo_model->setItem(tcp_p->Seq_num-1,4,new QStandardItem("HTTP"));
            allinfo_model->setItem(tcp_p->Seq_num-1,6,new QStandardItem(QString(QLatin1String((char *)tcp_p->data))));
        }
        else{
            allinfo_model->setItem(tcp_p->Seq_num-1,4,new QStandardItem("TCP"));
            allinfo_model->setItem(tcp_p->Seq_num-1,6,new QStandardItem("port:"+QString::number(ntohs(tcp_p->tcphdr.SrcPort)) + " → " +
                                                                        QString::number(ntohs(tcp_p->tcphdr.DstPort)) + "  Seq=" +
                                                                        QString::number(ntohl(tcp_p->tcphdr.SeqNum)) + "  Ack=" +
                                                                        QString::number(ntohl(tcp_p->tcphdr.AckNum)) + "  Win=" +
                                                                        QString::number(ntohs(tcp_p->tcphdr.Window))));
        }
        allinfo_model->setItem(tcp_p->Seq_num-1,5,new QStandardItem(QString::number(tcp_p->pkthdr.caplen)));
        tcp_p = tcp_p->next;
    }
    //UDP(DNS DHCP)依次输出到表1
    while(udp_p){
        temp_t = (double)udp_p->pkthdr.ts.ts_sec + ((double)(udp_p->pkthdr.ts.ts_usec)/1000000);
        allinfo_model->setItem(udp_p->Seq_num-1,0,new QStandardItem(QString::number(udp_p->Seq_num)));
        allinfo_model->setItem(udp_p->Seq_num-1,1,new QStandardItem(QString::number(temp_t-zero_t,'f',6)));
        allinfo_model->setItem(udp_p->Seq_num-1,2,new QStandardItem(uintToIPQstr(udp_p->iphdr.SrcIP)));
        allinfo_model->setItem(udp_p->Seq_num-1,3,new QStandardItem(uintToIPQstr(udp_p->iphdr.DstIP)));
        allinfo_model->setItem(udp_p->Seq_num-1,5,new QStandardItem(QString::number(udp_p->pkthdr.caplen)));
        //判断是否是DNS
        if(DNSJudgeFunc(udp_p->udphdr)){
            DNSHeader_t *dns;
            dns = (DNSHeader_t *)(udp_p->data);
            allinfo_model->setItem(udp_p->Seq_num-1,4,new QStandardItem("DNS"));
            allinfo_model->setItem(udp_p->Seq_num-1,6,new QStandardItem("DNS")); //++++++++++++
        }
        //判断是否是DHCP
        else if(DHCPJudgeFunc(udp_p->udphdr)){
            DHCPHeader_t *dhcp;
            dhcp = (DHCPHeader_t *)(udp_p->data);
            allinfo_model->setItem(udp_p->Seq_num-1,4,new QStandardItem("DHCP"));
            allinfo_model->setItem(udp_p->Seq_num-1,6,new QStandardItem("DHCP"));//++++++++++++
        }
        else{
            allinfo_model->setItem(udp_p->Seq_num-1,4,new QStandardItem("UDP"));
            allinfo_model->setItem(udp_p->Seq_num-1,6,new QStandardItem("port:"+QString::number(ntohs(udp_p->udphdr.SrcPort))+" → " +
                                                                      QString::number(ntohs(udp_p->udphdr.DstPort))+"  Len=" +
                                                                      QString::number(ntohs(udp_p->udphdr.SegLen)-UDP_HLEN)));
        }
        udp_p = udp_p->next;
    }
    //ARP依次输出到表1
    while(arp_p){
        temp_t = (double)arp_p->pkthdr.ts.ts_sec + ((double)(arp_p->pkthdr.ts.ts_usec)/1000000);
        allinfo_model->setItem(arp_p->Seq_num-1,0,new QStandardItem(QString::number(arp_p->Seq_num)));
        allinfo_model->setItem(arp_p->Seq_num-1,1,new QStandardItem(QString::number(temp_t-zero_t,'f',6)));
        allinfo_model->setItem(arp_p->Seq_num-1,2,new QStandardItem(ucharToMACQstr(arp_p->etherhdr.SrcMAC)));
        allinfo_model->setItem(arp_p->Seq_num-1,3,new QStandardItem(ucharToMACQstr(arp_p->etherhdr.DstMAC)));
        allinfo_model->setItem(arp_p->Seq_num-1,4,new QStandardItem("ARP"));
        allinfo_model->setItem(arp_p->Seq_num-1,5,new QStandardItem(QString::number(arp_p->pkthdr.caplen)));
        if(ntohs(arp_p->arphdr.ARPOP) == 1){  //请求
            allinfo_model->setItem(arp_p->Seq_num-1,6,new QStandardItem("From "+uintToIPQstr(*((uint *)(arp_p->data + 6)))+
                                                                        " request:"+uintToIPQstr(*((uint *)(arp_p->data + 16)))));
        }
        else if (ntohs(arp_p->arphdr.ARPOP) == 2){    //应答
            allinfo_model->setItem(arp_p->Seq_num-1,6,new QStandardItem("To " + uintToIPQstr(*((uint *)(arp_p->data + 16)))+" reply:"+
                                                                        uintToIPQstr(*((uint *)(arp_p->data + 6)))+
                                                                        "⇄" +ucharToMACQstr(arp_p->data)));
        }
        arp_p = arp_p->next;
    }
}
//进行一些初始化操作
void pkt_proc::initWidget()
{
    //设置数据内容表中的相关信息(表2)
    content_model->setHorizontalHeaderItem(16,new QStandardItem(QObject::tr("ASCII码")));
    ui->contentTable->setModel(content_model);
    ui->contentTable->setEditTriggers(QAbstractItemView::NoEditTriggers);//设置为禁止编辑
    ui->contentTable->setSelectionBehavior(QAbstractItemView::SelectRows);//设置为整行选择
    ui->contentTable->setShowGrid(false);//隐藏表格线
    for(int i=0; i<16; i++)
        ui->contentTable->setColumnWidth(i,34);
    ui->contentTable->setColumnWidth(16,200);

    //显示统计表初始(表4)
    ui->statistics_browser->clear();
    ui->statistics_browser->insertPlainText("► Pcap文件信息：");
    ui->statistics_browser->insertPlainText("\n        ◇ 文件名称：" + analyse_filename);
    ui->statistics_browser->insertPlainText("\n        ◇ 链路类型：Ethernet");
    ui->statistics_browser->insertPlainText("\n        ◇ 抓包数量：" + QString::number(line));
    time_sec = (uint64_t)zero_t;
    ui->statistics_browser->insertPlainText("\n        ◇ 抓包时间：" + QString(QLatin1String(ctime((const time_t *)&(time_sec)))));
    ui->statistics_browser->insertPlainText("► 包类型统计信息：");
    ui->statistics_browser->insertPlainText("\n        ◇ ICMP：" + QString::number(Alist_Hdr.icmp_num));
    ui->statistics_browser->insertPlainText("\n        ◇ TCP：" + QString::number(Alist_Hdr.tcp_num));
    ui->statistics_browser->insertPlainText("\n        ◇ UDP：" + QString::number(Alist_Hdr.udp_num));
    ui->statistics_browser->insertPlainText("\n        ◇ ARP：" + QString::number(Alist_Hdr.arp_num));
    ui->statistics_browser->insertPlainText("\n► 条件统计信息：");
    ui->statistics_browser->insertPlainText("\n        ◇ 暂无");

    //设置初始lineEdit
    ui->ipaddr_input->setEnabled(0);
    ui->port_input->setEnabled(0);
}

//总览表点击事件
void pkt_proc::on_overviewTable_clicked(const QModelIndex &index)
{
    //清空内容不清除表头
    content_model->removeRows(0,content_model->rowCount());
    //清除详细信息显示框
    ui->headerTable->clear();
    /*数据显示和分析统计部分（表2 和 表3）
     *ETHERNET
     *    IP
     *        ICMP
     *        TCP
     *           HTTP
     *        UDP
     *           DHCP
     *           DNS
     *    ARP
    */
    struct pcapPktHeader *pcappkth = NULL;
    struct EtherHeader *ethernet  = NULL;
    struct IPHeader *ip = NULL;
    struct ICMPHeader *icmp = NULL;
    struct TCPHeader *tcp = NULL;
    struct UDPHeader *udp = NULL;
    struct DNSHeader *dns = NULL;
    struct DHCPHeader *dhcp = NULL;
    struct ARPHeader *arp = NULL;
    uint32_t etheroff = ETH_HLEN;
    uint32_t ipoff = ETH_HLEN+IP_HLEN;
    uint32_t icmpoff = ETH_HLEN+IP_HLEN+ICMP_HLEN;
    uint32_t tcpoff = ETH_HLEN+IP_HLEN+TCP_HLEN;
    uint32_t udpoff = ETH_HLEN+IP_HLEN+UDP_HLEN;
    uint32_t dnsoff = ETH_HLEN+IP_HLEN+UDP_HLEN+DNS_HLEN;
    uint32_t dhcpoff = ETH_HLEN+IP_HLEN+UDP_HLEN+DHCP_HLEN;
    uint32_t arpoff = ETH_HLEN+ARP_HLEN;
    //首先遍历得到对应的数据包结构体指针
    uint32_t pkt_length = 0; //包的字节数
    uchar8_t *pkt_char = NULL;
    uint32_t content_row = 0; // 显示行数，每16字节一行
    QString pro_str = allinfo_model->data(allinfo_model->index(index.row(),4)).toString();
    int cur_seq = allinfo_model->data(allinfo_model->index(index.row(),0)).toInt();
    if(pro_str == "ICMP"){
        ICMP_List_t *temp_icmp_p = Alist_Hdr.icmp_listhdr;
        while(temp_icmp_p){
            if(temp_icmp_p->Seq_num == cur_seq)
                break;
            else
                temp_icmp_p = temp_icmp_p->next;
        }
        pkt_char = (uchar8_t *)malloc(temp_icmp_p->pkthdr.caplen);
        DataChToCh((const uchar8_t *)&(temp_icmp_p->etherhdr), pkt_char, ETH_HLEN);
        DataChToCh((const uchar8_t *)&(temp_icmp_p->iphdr), pkt_char+etheroff, IP_HLEN);
        DataChToCh((const uchar8_t *)&(temp_icmp_p->icmphdr), pkt_char+ipoff, ICMP_HLEN);
        DataChToCh((const uchar8_t *)&(temp_icmp_p->data), pkt_char+icmpoff, temp_icmp_p->pkthdr.caplen-icmpoff);
        pcappkth = &(temp_icmp_p->pkthdr);
        ethernet = &(temp_icmp_p->etherhdr);
        ip = &(temp_icmp_p->iphdr);
        icmp = &(temp_icmp_p->icmphdr);
    }
    else if(pro_str == "TCP" || pro_str == "HTTP"){
        TCP_List_t *temp_tcp_p = Alist_Hdr.tcp_listhdr;
        while(temp_tcp_p){
            if(temp_tcp_p->Seq_num == cur_seq)
                break;
            else
                temp_tcp_p = temp_tcp_p->next;
        }
        pkt_char = (uchar8_t *)malloc(temp_tcp_p->pkthdr.caplen);
        DataChToCh((const uchar8_t *)&(temp_tcp_p->etherhdr), pkt_char, ETH_HLEN);
        DataChToCh((const uchar8_t *)&(temp_tcp_p->iphdr), pkt_char+etheroff, IP_HLEN);
        DataChToCh((const uchar8_t *)&(temp_tcp_p->tcphdr), pkt_char+ipoff, TCP_HLEN);
        DataChToCh((const uchar8_t *)&(temp_tcp_p->data), pkt_char+tcpoff, temp_tcp_p->pkthdr.caplen-tcpoff);
        pcappkth = &(temp_tcp_p->pkthdr);
        ethernet = &(temp_tcp_p->etherhdr);
        ip = &(temp_tcp_p->iphdr);
        tcp = &(temp_tcp_p->tcphdr);
    }
    else if(pro_str == "UDP" || pro_str == "DNS" || pro_str == "DHCP"){
        UDP_List_t *temp_udp_p = Alist_Hdr.udp_listhdr;
        while(temp_udp_p){
            if(temp_udp_p->Seq_num == cur_seq)
                break;
            else
                temp_udp_p = temp_udp_p->next;
        }
        pkt_char = (uchar8_t *)malloc(temp_udp_p->pkthdr.caplen);
        DataChToCh((const uchar8_t *)&(temp_udp_p->etherhdr), pkt_char, ETH_HLEN);
        DataChToCh((const uchar8_t *)&(temp_udp_p->iphdr), pkt_char+etheroff, IP_HLEN);
        DataChToCh((const uchar8_t *)&(temp_udp_p->udphdr), pkt_char+ipoff, UDP_HLEN);
        DataChToCh((const uchar8_t *)&(temp_udp_p->data), pkt_char+udpoff, temp_udp_p->pkthdr.caplen-udpoff);
        pcappkth = &(temp_udp_p->pkthdr);
        ethernet = &(temp_udp_p->etherhdr);
        ip = &(temp_udp_p->iphdr);
        udp = &(temp_udp_p->udphdr);
    }
    else if(pro_str == "ARP"){
        ARP_List_t *temp_arp_p = Alist_Hdr.arp_listhdr;
        while(temp_arp_p){
            if(temp_arp_p->Seq_num == cur_seq)
                break;
            else
                temp_arp_p = temp_arp_p->next;
        }
        pkt_char = (uchar8_t *)malloc(temp_arp_p->pkthdr.caplen);
        DataChToCh((const uchar8_t *)&(temp_arp_p->etherhdr), pkt_char, ETH_HLEN);
        DataChToCh((const uchar8_t *)&(temp_arp_p->arphdr), pkt_char+etheroff, ARP_HLEN);
        DataChToCh((const uchar8_t *)&(temp_arp_p->data), pkt_char+arpoff, temp_arp_p->pkthdr.caplen-arpoff);
        pcappkth = &(temp_arp_p->pkthdr);
        ethernet = &(temp_arp_p->etherhdr);
        arp = &(temp_arp_p->arphdr);
    }
    else{

    }
    //数据包内容的二进制和ascii码显示（表2）
    /*ETHERNET
     *    IP
     *        ICMP
     *        TCP
     *           HTTP
     *        UDP
     *           DHCP
     *           DNS
     *    ARP
    */
    pkt_length = pcappkth->caplen; //包的字节数
    if(pkt_length%16 == 0 )
        content_row = pkt_length/16;
    else content_row = pkt_length/16 + 1;
    char *ch_dest = (char *)malloc(2*pkt_length*sizeof(char));  //***出问题的地方***下次注意
    char *str_dest = (char *)malloc(pkt_length*sizeof(char));
    data_ucharToHexstr(pkt_char, pkt_length, ch_dest);
    data_HexstrTochar(ch_dest, pkt_length, str_dest);
    uchar8_t temp_q[32*content_row]; //row*32 >= length*2 建立一个整行数的数组
    char temp_a[16*content_row]; //建立整行数ascii码的字符的数组，共16位
    //将两个临时数组先进行初始化和赋值
    for(uint32_t i=0; i<32*content_row; i++){
        temp_q[i] = ' ';
    }
    for(uint32_t i=0; i<16*content_row; i++){
        temp_a[i] = ' ';
    }
    for(uint32_t i=0; i<2*pkt_length; i++){
        temp_q[i] = ch_dest[i];
    }
    for(uint32_t i=0; i<pkt_length; i++){
        temp_a[i] = str_dest[i];
    }
    //一行一行提取数据并单行显示
    char temp_onerow[32];//一行十六进制数据
    char temp_onerow_a[16];//一行ascii码数据
    char *temp_no = (char *)malloc(4*sizeof(char));//每行的头位置数
    //对两个单行数组进行初始化
    for(int i=0; i<32; i++){
        temp_onerow[i] = ' ';
    }
    for(int i=0; i<16; i++){
        temp_onerow_a[i] = ' ';
    }
    //一行行显示出来
    for(uint32_t i=0; i<content_row; i++){
        //显示头位置数
        _4No_pro(i,temp_no);
        content_model->setVerticalHeaderItem(i,new QStandardItem(temp_no));
        //显示每行十六进制数据
        for(int j=0; j<32; j++){
            temp_onerow[j] = temp_q[32*i+j];
        }
        for(int m=0; m<16; m++){
            char *temp_ch = (char *)malloc(2*sizeof(char));
            for(int n=0; n<2; n++){
                temp_ch[n] = temp_onerow[2*m+n];
            }
            temp_ch[2] = 0;
            content_model->setItem(i,m,new QStandardItem(temp_ch));//显示到表中
            content_model->item(i, m)->setTextAlignment(Qt::AlignCenter);//居中显示
        }
        //显示每行ascii码数据
        for(int j=0; j<16 ; j++){
            if(temp_a[16*i+j]<=31 || temp_a[16*i+j]==127)
                temp_onerow_a[j] = '.';
            else
                temp_onerow_a[j] = temp_a[16*i+j];
        }
        *(temp_onerow_a+16) = 0;
        content_model->setItem(i,16,new QStandardItem(temp_onerow_a));
        content_model->item(i, 16)->setTextAlignment(Qt::AlignCenter);//居中显示
    }

    //右侧详细解析信息显示(表3)
    /*ETHERNET
     *    IP
     *        ICMP
     *        TCP
     *           HTTP
     *        UDP
     *           DHCP
     *           DNS
     *    ARP
    */
    //PCAP包头
    ui->headerTable->insertPlainText("► pcap数据包头：");
    ui->headerTable->insertPlainText("\n        ◇ 抓去数据包长度：");
    ui->headerTable->insertPlainText(QString::number(pcappkth->caplen));
    ui->headerTable->insertPlainText("字节");
    ui->headerTable->insertPlainText("\n        ◇ 数据包实际长度：");
    ui->headerTable->insertPlainText(QString::number(pcappkth->len));
    ui->headerTable->insertPlainText("字节");
    ui->headerTable->insertPlainText("\n        ◇ 时间：");
    time_sec = (uint64_t)pcappkth->ts.ts_sec;
    ui->headerTable->insertPlainText(QString(QLatin1String(ctime((const time_t *)&(time_sec)))));
    //以太网帧头
    ui->headerTable->insertPlainText("► 以太网帧头（Ethernet）");
    ui->headerTable->insertPlainText("\n        ◇ 目的MAC地址：");
    ui->headerTable->insertPlainText(ucharToMACQstr(ethernet->DstMAC));
    ui->headerTable->insertPlainText("\n        ◇ 源MAC地址：");
    ui->headerTable->insertPlainText(ucharToMACQstr(ethernet->SrcMAC));
    ui->headerTable->insertPlainText("\n        ◇ 协议类型：IP （0x0800）");
    switch(ntohs(ethernet->FrameType))
    {       
        //IP MAC头中类型码 0x0800
        case EPT_IP:
            ui->headerTable->insertPlainText("\n► IP数据报头（Datagram）");
            ui->headerTable->insertPlainText("\n        ◇ 版本信息：IPv");
            ui->headerTable->insertPlainText(QString::number(ip->Ver_Hlen/16));
            ui->headerTable->insertPlainText("\n        ◇ 头长度：");
            ui->headerTable->insertPlainText(QString::number((ip->Ver_Hlen%16)*4)+"字节");
            ui->headerTable->insertPlainText("\n        ◇ 服务类型：");
            ui->headerTable->insertPlainText("0x"+ucharToHexQStr(ip->TOS));
            ui->headerTable->insertPlainText("\n        ◇ 数据报长度：");
            ui->headerTable->insertPlainText(QString::number(ntohs(ip->TotalLen)));
            ui->headerTable->insertPlainText("\n        ◇ 数据包标识：");
            ui->headerTable->insertPlainText("0x"+ushortToHexQStr(ntohs(ip->ID)));
            ui->headerTable->insertPlainText("\n        ◇ 分片信息：");
            ui->headerTable->insertPlainText("0x"+ushortToHexQStr(ntohs(ip->Flag_Segment)));
            ui->headerTable->insertPlainText("\n        ◇ 存活时间：");
            ui->headerTable->insertPlainText(QString::number(ip->TTL));
            ui->headerTable->insertPlainText("\n        ◇ 首部校验和：");
            ui->headerTable->insertPlainText("0x"+ushortToHexQStr(ntohs(ip->Checksum)));
            ui->headerTable->insertPlainText("\n        ◇ 源IP地址：");
            ui->headerTable->insertPlainText(uintToIPQstr(ip->SrcIP));
            ui->headerTable->insertPlainText("\n        ◇ 目的IP地址：");
            ui->headerTable->insertPlainText(uintToIPQstr(ip->DstIP));
            switch(ip->Protocol)
            {
                //ICMP IP头中类型码为 1
                case IPT_ICMP:
                    ui->headerTable->insertPlainText("\n► ICMP报文头（Datagram)");                                               //++++++++++++
                    switch(icmp->ICMPType)
                    {
                        //能返回目的地，响应-应答包(0)
                        case ICMP_TYPE_REPLY:
                            ICMPType0_t *icmp0;
                            icmp0 = (ICMPType0_t *)(pkt_char+icmpoff);
                            ui->headerTable->insertPlainText("\n        ◇ 类型：响应-应答包（0）");
                            ui->headerTable->insertPlainText("\n        ◇ 代码："+QString::number(icmp->ICMPCode));
                            ui->headerTable->insertPlainText("\n        ◇ 校验和：0x"+ushortToHexQStr(ntohs(icmp->Checksum)));
                            ui->headerTable->insertPlainText("\n        ◇ id：0x"+ushortToHexQStr(ntohs(icmp0->ICMPID)));
                            ui->headerTable->insertPlainText("\n        ◇ seq："+ushortToHexQStr(ntohs(icmp0->ICMPSeq)));
                            break;
                        //不能到达目的地(3)
                        case ICMP_TYPE_UNREACH:
                            ICMPType3_t *icmp3;
                            icmp3 = (ICMPType3_t *)(pkt_char+icmpoff);
                            ui->headerTable->insertPlainText("\n        ◇ 类型：目的地不可达（3）");
                            ui->headerTable->insertPlainText("\n        ◇ 代码："+QString::number(icmp->ICMPCode));
                            ui->headerTable->insertPlainText("\n        ◇ 校验和：0x"+ushortToHexQStr(ntohs(icmp->Checksum)));
                            ui->headerTable->insertPlainText("\n        ◇ ICMPPmvoid："+ushortToHexQStr(ntohs(icmp3->ICMPPmvoid)));
                            ui->headerTable->insertPlainText("\n        ◇ ICMPNextmtu："+ushortToHexQStr(ntohs(icmp3->ICMPNextmtu)));
                            break;
                        //能到达目的地，响应-请求包(8)
                        case ICMP_TYPE_REQUEST:
                            ICMPType8_t *icmp8;
                            icmp8 = (ICMPType8_t *)(pkt_char+icmpoff);
                            ui->headerTable->insertPlainText("\n        ◇ 类型：响应-请求包（8）");
                            ui->headerTable->insertPlainText("\n        ◇ 代码："+QString::number(icmp->ICMPCode));
                            ui->headerTable->insertPlainText("\n        ◇ 校验和：0x"+ushortToHexQStr(ntohs(icmp->Checksum)));
                            ui->headerTable->insertPlainText("\n        ◇ id：0x"+ushortToHexQStr(ntohs(icmp8->ICMPID)));
                            ui->headerTable->insertPlainText("\n        ◇ seq："+ushortToHexQStr(ntohs(icmp8->ICMPSeq)));
                            break;
                        //超时(11)
                        case ICMP_TYPE_TIMEOUT:
                            ICMPType11_t *icmp11;
                            icmp11 = (ICMPType11_t *)(pkt_char+icmpoff);
                            ui->headerTable->insertPlainText("\n        ◇ 类型：请求超时（11）");
                            ui->headerTable->insertPlainText("\n        ◇ 代码："+QString::number(icmp->ICMPCode));
                            ui->headerTable->insertPlainText("\n        ◇ 校验和：0x"+ushortToHexQStr(ntohs(icmp->Checksum)));
                            ui->headerTable->insertPlainText("\n        ◇ ICMPVoid："+QString::number(icmp11->ICMPVoid));
                            break;
                        //其他类型 源抑制、时间戳请求等
                        default:
                            ui->headerTable->insertPlainText("\n        ◇ 暂无此类型ICMP数据的解析功能");
                            break;
                    }
                    break;
                //TCP IP头中类型码为 6
                case IPPROTO_TCP:
                    //TCP报文段头
                    ui->headerTable->insertPlainText("\n► TCP报文段头（Segment)");
                    ui->headerTable->insertPlainText("\n        ◇ 源端口号：");
                    ui->headerTable->insertPlainText(QString::number(ntohs(tcp->SrcPort)));
                    ui->headerTable->insertPlainText("\n        ◇ 目标端口号：");
                    ui->headerTable->insertPlainText(QString::number(ntohs(tcp->DstPort)));
                    ui->headerTable->insertPlainText("\n        ◇ 序列号：");
                    ui->headerTable->insertPlainText(QString::number(ntohl(tcp->SeqNum)));
                    ui->headerTable->insertPlainText("\n        ◇ 确认号：");
                    ui->headerTable->insertPlainText(QString::number(ntohl(tcp->AckNum)));
                    ui->headerTable->insertPlainText("\n        ◇ 头部长度：");
                    ui->headerTable->insertPlainText(QString::number(tcp->HeaderLen/4)+"字节");
                    ui->headerTable->insertPlainText("\n        ◇ 标志位：");
                    ui->headerTable->insertPlainText("0x" + ucharToHexQStr(tcp->Flags));
                    ui->headerTable->insertPlainText("\n                 URG: ");
                    ui->headerTable->insertPlainText(QString::number(!(!(0x40 & tcp->Flags))));
                    ui->headerTable->insertPlainText("     ACK: ");
                    ui->headerTable->insertPlainText(QString::number(!(!(0x10 & tcp->Flags))));
                    ui->headerTable->insertPlainText("\n                 PSH: ");
                    ui->headerTable->insertPlainText(QString::number(!(!(0x08 & tcp->Flags))));
                    ui->headerTable->insertPlainText("     RST: ");
                    ui->headerTable->insertPlainText(QString::number(!(!(0x04 & tcp->Flags))));
                    ui->headerTable->insertPlainText("\n                 SYN: ");
                    ui->headerTable->insertPlainText(QString::number(!(!(0x02 & tcp->Flags))));
                    ui->headerTable->insertPlainText("     FIN: ");
                    ui->headerTable->insertPlainText(QString::number(!(!(0x01 & tcp->Flags))));
                    ui->headerTable->insertPlainText("\n        ◇ 窗口大小：");
                    ui->headerTable->insertPlainText(QString::number(ntohs(tcp->Window)));
                    ui->headerTable->insertPlainText("\n        ◇ 校验和：");
                    ui->headerTable->insertPlainText("0x"+ushortToHexQStr(ntohs(tcp->Checksum)));
                    ui->headerTable->insertPlainText("\n        ◇ 紧急指针：");
                    ui->headerTable->insertPlainText(QString::number(ntohs(tcp->UrgentPoint)));
                    //HTTP报文
                    if(pro_str == "HTTP"){
                        ui->headerTable->insertPlainText("\n► HTTP报文（Message)\n        ◇ ");
                        for(uint32_t i=0; i<(pkt_length-tcpoff); i++){
                            if(*(pkt_char+tcpoff+i) == 10 &&
                                 i != (pkt_length-tcpoff-1) &&
                                 i != (pkt_length-tcpoff-3))
                                ui->headerTable->insertPlainText("        ◇ ");
                            else{
                                ui->headerTable->insertPlainText(QString(QLatin1Char(*(pkt_char+tcpoff+i))));
                            }
                        }
                    }
                    //其他TCP报文
                    else{
                        ui->headerTable->insertPlainText("\n► 应用层报文（Message)");
                        ui->headerTable->insertPlainText("\n        ◇ 十六进制数据（"+
                                                         QString::number(pkt_length-tcpoff)+"字节）：");
                        for(uint32_t i=0; i<(pkt_length-tcpoff); i++){
                            if(i%8 == 0)
                                ui->headerTable->insertPlainText("\n                    ");
                            ui->headerTable->insertPlainText(ucharToHexQStr(*(pkt_char+tcpoff+i))+" ");
                        }
                    }
                    break;
                //UDP IP头中类型码为 17
                case IPPROTO_UDP:
                    //UDP报文段头
                    ui->headerTable->insertPlainText("\n► UDP报文段头（Segment)");
                    ui->headerTable->insertPlainText("\n        ◇ 源端口号：");
                    ui->headerTable->insertPlainText(QString::number(ntohs(udp->SrcPort)));
                    ui->headerTable->insertPlainText("\n        ◇ 目标端口号：");
                    ui->headerTable->insertPlainText(QString::number(ntohs(udp->DstPort)));
                    ui->headerTable->insertPlainText("\n        ◇ 报文段长度：");
                    ui->headerTable->insertPlainText(QString::number(ntohs(udp->SegLen)));
                    ui->headerTable->insertPlainText("\n        ◇ 校验和：");
                    ui->headerTable->insertPlainText("0x"+ushortToHexQStr(ntohs(udp->Checksum)));
                    //DNS报文
                    if(pro_str == "DNS"){
                        dns = (struct DNSHeader *)(pkt_char+udpoff);
                        ui->headerTable->insertPlainText("\n► DNS报文（Message)");
                        ui->headerTable->insertPlainText("\n        ◇ 标识：");
                        ui->headerTable->insertPlainText(QString::number(ntohs(dns->ID)));
                        ui->headerTable->insertPlainText("\n        ◇ 标志：");
                        ui->headerTable->insertPlainText(QString::number(ntohs(dns->Flags)));
                        ui->headerTable->insertPlainText("\n        ◇ 问题数：");
                        ui->headerTable->insertPlainText(QString::number(ntohs(dns->Qst_num)));
                        ui->headerTable->insertPlainText("\n        ◇ 资源记录数：");
                        ui->headerTable->insertPlainText(QString::number(ntohs(dns->Rsc_num)));
                        ui->headerTable->insertPlainText("\n        ◇ 授权资源记录数：");
                        ui->headerTable->insertPlainText(QString::number(ntohs(dns->Aut_num)));
                        ui->headerTable->insertPlainText("\n        ◇ 额外资源记录数：");
                        ui->headerTable->insertPlainText(QString::number(ntohs(dns->Adt_num)));
                        ui->headerTable->insertPlainText("\n        ◇ 查询问题：");
                        ui->headerTable->insertPlainText("\n        ◇ 回答：");
                        ui->headerTable->insertPlainText(QString(QLatin1String((char *)(pkt_char+dnsoff))));
                    }
                    //DHCP报文
                    else if(pro_str == "DHCP"){
                        dhcp = (struct DHCPHeader *)(pkt_char+udpoff);
                        ui->headerTable->insertPlainText("\n► DHCP报文（Message)");
                        ui->headerTable->insertPlainText("\n        ◇ 操作码：");
                        ui->headerTable->insertPlainText(QString::number(dhcp->OP));
                        ui->headerTable->insertPlainText("\n        ◇ 硬件类型：");
                        ui->headerTable->insertPlainText(QString::number(dhcp->HrdType));
                        ui->headerTable->insertPlainText("\n        ◇ 硬件长度：");
                        ui->headerTable->insertPlainText(QString::number(dhcp->HrdLen));
                        ui->headerTable->insertPlainText("\n        ◇ 跳数：");
                        ui->headerTable->insertPlainText(QString::number(dhcp->Hops));
                        ui->headerTable->insertPlainText("\n        ◇ 事务ID：");
                        ui->headerTable->insertPlainText(QString::number(ntohl(dhcp->XID)));
                        ui->headerTable->insertPlainText("\n        ◇ 秒数：");
                        ui->headerTable->insertPlainText(QString::number(ntohs(dhcp->Sec)));
                        ui->headerTable->insertPlainText("\n        ◇ 标志：");
                        ui->headerTable->insertPlainText(QString::number(ntohs(dhcp->Flags)));
                        ui->headerTable->insertPlainText("\n        ◇ 客户端IP地址：");
                        ui->headerTable->insertPlainText(uintToIPQstr(dhcp->Ciaddr));
                        ui->headerTable->insertPlainText("\n        ◇ 你的IP地址：");
                        ui->headerTable->insertPlainText(uintToIPQstr(dhcp->Yiaddr));
                        ui->headerTable->insertPlainText("\n        ◇ 服务器IP地址：");
                        ui->headerTable->insertPlainText(uintToIPQstr(dhcp->Siaddr));
                        ui->headerTable->insertPlainText("\n        ◇ 网关IP地址：");
                        ui->headerTable->insertPlainText(uintToIPQstr(dhcp->Giaddr));
                        ui->headerTable->insertPlainText("\n        ◇ 客户端硬件地址：");
                        ui->headerTable->insertPlainText(ucharToMACQstr(dhcp->Chaddr));
                        ui->headerTable->insertPlainText("\n        ◇ 服务器名：");
                        ui->headerTable->insertPlainText(QString(QLatin1String((char *)dhcp->Sname)));
                        ui->headerTable->insertPlainText("\n        ◇ 引导文件名：");
                        ui->headerTable->insertPlainText(QString(QLatin1String((char *)dhcp->File)));
                        ui->headerTable->insertPlainText("\n        ◇ 选项：");
                        ui->headerTable->insertPlainText(QString(QLatin1String((char *)(pkt_char+dhcpoff))));
                    }
                    //其他UDP报文
                    else{
                        ui->headerTable->insertPlainText("\n► 应用层报文（Message)");
                        ui->headerTable->insertPlainText("\n        ◇ 十六进制数据（"+
                                                         QString::number(pkt_length-udpoff)+"字节）：");
                        for(uint32_t i=0; i<(pkt_length-udpoff); i++){
                            if(i%8 == 0)
                                ui->headerTable->insertPlainText("\n                    ");
                            ui->headerTable->insertPlainText(ucharToHexQStr(*(pkt_char+udpoff+i))+" ");
                        }
                    }
                    break;
                default:
                    break;
            }
            break;
        //ARP MAC头中类型码 0x0806
        case ETHERTYPE_ARP:
            //ARP包头
            ui->headerTable->insertPlainText("\n► ARP（datagram)");
            ui->headerTable->insertPlainText("\n        ◇ 硬件类型：Ehernet（1）");
            ui->headerTable->insertPlainText("\n        ◇ 协议类型：IPv4（0x0800）");
            ui->headerTable->insertPlainText("\n        ◇ 硬件地址长度：6字节");
            ui->headerTable->insertPlainText("\n        ◇ 协议地址长度：4字节");
            ui->headerTable->insertPlainText("\n        ◇ 操作类型：" + QString::number(ntohs(arp->ARPOP)));
            switch(ntohs(arp->ARPOP))
            {
                //ARP请求 值为1
                case ARP_REQUSET:
                    ui->headerTable->insertPlainText("（请求）");
                    break;
                //ARP应答 值为2
                case ARP_REPLY:
                    ui->headerTable->insertPlainText("（应答）");
                    break;
                default:
                    break;
            }
            ui->headerTable->insertPlainText("\n        ◇ 源MAC地址：" + ucharToMACQstr(pkt_char+arpoff));
            ui->headerTable->insertPlainText("\n        ◇ 源IP地址：" + uintToIPQstr(*((uint *)(pkt_char+arpoff+6))));
            ui->headerTable->insertPlainText("\n        ◇ 目的MAC地址：" + ucharToMACQstr(pkt_char+arpoff+10));
            ui->headerTable->insertPlainText("\n        ◇ 目的IP地址：" + uintToIPQstr(*((uint *)(pkt_char+arpoff+16))));
            break;
        //其他类型RARP、VLAN等
        default:
            break;
    }
}

void pkt_proc::on_back_btn_clicked()
{
    QMessageBox::StandardButton rb = QMessageBox::question(this, "确认框", "确定要退出?",
                                                           QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes);
    if(rb == QMessageBox::Yes){
        this->close();
        parentWidget()->show();
    }
}

void pkt_proc::on_statistics_btn_clicked()
{
    //清空内容不清除表头
    allinfo_model->removeRows(0,allinfo_model->rowCount());

    //过滤显示到总览表(表1)
    ICMP_List_t *icmp_p = Alist_Hdr.icmp_listhdr;
    TCP_List_t *tcp_p = Alist_Hdr.tcp_listhdr;
    UDP_List_t *udp_p = Alist_Hdr.udp_listhdr;
    ARP_List_t *arp_p = Alist_Hdr.arp_listhdr;
    double temp_t;
    //过滤
    //All____
    if(ui->all_op_btn->isChecked() == true){
        overview_init();
        if(ui->assign_port_btn->isChecked() == true){
            mybox->show();
            mybox->setText("暂不支持所有协议的端口号统计功能");
            ui->all_port_btn->setChecked(true);
            //ui->assign_port_btn->setChecked(false);
        }
        if(ui->assign_ip_btn->isChecked() == true){
            mybox->show();
            mybox->setText("暂不支持所有协议的IP统计功能");
            ui->all_port_btn->setChecked(true);
            //ui->assign_port_btn->setChecked(false);
        }
    }
    //ICMP_____
    else if(ui->icmp_op_btn->isChecked() == true){
        QString temp_ipstr = NULL;
        int line_temp = 0;
        while(icmp_p){
            //port不存在的
            if(ui->assign_port_btn->isChecked() == true){
                mybox->show();
                mybox->setText("该协议不具备端口号");
                ui->all_port_btn->setChecked(true);
                //ui->assign_port_btn->setChecked(false);
                break;
            }
            //仅ip
            else if(ui->assign_ip_btn->isChecked() == true){
                temp_ipstr = ui->ipaddr_input->text();
                if(temp_ipstr == NULL){
                    mybox->show();
                    mybox->setText("请输入IP");
                    break;
                }
                if((uintToIPQstr(icmp_p->iphdr.SrcIP) == temp_ipstr || uintToIPQstr(icmp_p->iphdr.DstIP) == temp_ipstr)){
                    temp_t = (double)icmp_p->pkthdr.ts.ts_sec + ((double)(icmp_p->pkthdr.ts.ts_usec)/1000000);
                    allinfo_model->setItem(line_temp,0,new QStandardItem(QString::number(icmp_p->Seq_num)));
                    allinfo_model->setItem(line_temp,1,new QStandardItem(QString::number(temp_t-zero_t,'f',6)));
                    allinfo_model->setItem(line_temp,2,new QStandardItem(uintToIPQstr(icmp_p->iphdr.SrcIP)));
                    allinfo_model->setItem(line_temp,3,new QStandardItem(uintToIPQstr(icmp_p->iphdr.DstIP)));
                    allinfo_model->setItem(line_temp,4,new QStandardItem("ICMP"));
                    allinfo_model->setItem(line_temp,5,new QStandardItem(QString::number(icmp_p->pkthdr.caplen)));
                    allinfo_model->setItem(line_temp,6,new QStandardItem("ICMP"));
                    line_temp++;
                }
                icmp_p = icmp_p->next;
            }
            else{
                temp_t = (double)icmp_p->pkthdr.ts.ts_sec + ((double)(icmp_p->pkthdr.ts.ts_usec)/1000000);
                allinfo_model->setItem(line_temp,0,new QStandardItem(QString::number(icmp_p->Seq_num)));
                allinfo_model->setItem(line_temp,1,new QStandardItem(QString::number(temp_t-zero_t,'f',6)));
                allinfo_model->setItem(line_temp,2,new QStandardItem(uintToIPQstr(icmp_p->iphdr.SrcIP)));
                allinfo_model->setItem(line_temp,3,new QStandardItem(uintToIPQstr(icmp_p->iphdr.DstIP)));
                allinfo_model->setItem(line_temp,4,new QStandardItem("ICMP"));
                allinfo_model->setItem(line_temp,5,new QStandardItem(QString::number(icmp_p->pkthdr.caplen)));
                allinfo_model->setItem(line_temp,6,new QStandardItem("ICMP"));
                line_temp++;
                icmp_p = icmp_p->next;
            }
        }
    }
    //TCP____//++++++++++++
    else if(ui->tcp_op_btn->isChecked() == true || ui->http_op_btn->isChecked() == true){
        QString temp_ipstr = NULL;
        QString temp_portstr = NULL;
        int line_temp = 0;
        while(tcp_p){
            //ip port 都筛选
            if(ui->assign_ip_btn->isChecked() == true && ui->assign_port_btn->isChecked() == true){
                temp_ipstr = ui->ipaddr_input->text();
                temp_portstr = ui->port_input->text();
                if(temp_ipstr == NULL){
                    mybox->show();
                    mybox->setText("请输入IP");
                    break;
                }
                if(temp_ipstr == NULL){
                    mybox->show();
                    mybox->setText("请输入端口号");
                    break;
                }
                if((uintToIPQstr(tcp_p->iphdr.SrcIP) == temp_ipstr ||
                    uintToIPQstr(tcp_p->iphdr.DstIP) == temp_ipstr) &&
                   (QString::number(ntohs(tcp_p->tcphdr.SrcPort)) == temp_portstr ||
                    QString::number(ntohs(tcp_p->tcphdr.DstPort)) == temp_portstr)){
                    temp_t = (double)tcp_p->pkthdr.ts.ts_sec + ((double)(tcp_p->pkthdr.ts.ts_usec)/1000000);
                    allinfo_model->setItem(line_temp,0,new QStandardItem(QString::number(tcp_p->Seq_num)));
                    allinfo_model->setItem(line_temp,1,new QStandardItem(QString::number(temp_t-zero_t,'f',6)));
                    allinfo_model->setItem(line_temp,2,new QStandardItem(uintToIPQstr(tcp_p->iphdr.SrcIP)));
                    allinfo_model->setItem(line_temp,3,new QStandardItem(uintToIPQstr(tcp_p->iphdr.DstIP)));
                    allinfo_model->setItem(line_temp,5,new QStandardItem(QString::number(tcp_p->pkthdr.caplen)));
                    if(FindHttpStr(QString(QLatin1String((char *)tcp_p->data)))){
                        allinfo_model->setItem(line_temp,4,new QStandardItem("HTTP"));
                        allinfo_model->setItem(line_temp,6,new QStandardItem(QString(QLatin1String((char *)tcp_p->data))));
                    }
                    else{
                        allinfo_model->setItem(line_temp,4,new QStandardItem("TCP"));
                        allinfo_model->setItem(line_temp,6,new QStandardItem("port:"+QString::number(ntohs(tcp_p->tcphdr.SrcPort)) + " → " +
                                                                                    QString::number(ntohs(tcp_p->tcphdr.DstPort)) + "  Seq=" +
                                                                                    QString::number(ntohl(tcp_p->tcphdr.SeqNum)) + "  Ack=" +
                                                                                    QString::number(ntohl(tcp_p->tcphdr.AckNum)) + "  Win=" +
                                                                                    QString::number(ntohs(tcp_p->tcphdr.Window))));
                    }
                    line_temp++;
                }
                tcp_p = tcp_p->next;
            }
            //仅ip
            else if(ui->assign_ip_btn->isChecked() == true && ui->assign_port_btn->isChecked() != true){
                temp_ipstr = ui->ipaddr_input->text();
                if(temp_ipstr == NULL){
                    mybox->show();
                    mybox->setText("请输入IP");
                    break;
                }
                if(uintToIPQstr(tcp_p->iphdr.SrcIP) == temp_ipstr || uintToIPQstr(tcp_p->iphdr.DstIP) == temp_ipstr){
                    temp_t = (double)tcp_p->pkthdr.ts.ts_sec + ((double)(tcp_p->pkthdr.ts.ts_usec)/1000000);
                    allinfo_model->setItem(line_temp,0,new QStandardItem(QString::number(tcp_p->Seq_num)));
                    allinfo_model->setItem(line_temp,1,new QStandardItem(QString::number(temp_t-zero_t,'f',6)));
                    allinfo_model->setItem(line_temp,2,new QStandardItem(uintToIPQstr(tcp_p->iphdr.SrcIP)));
                    allinfo_model->setItem(line_temp,3,new QStandardItem(uintToIPQstr(tcp_p->iphdr.DstIP)));
                    allinfo_model->setItem(line_temp,5,new QStandardItem(QString::number(tcp_p->pkthdr.caplen)));
                    if(FindHttpStr(QString(QLatin1String((char *)tcp_p->data)))){
                        allinfo_model->setItem(line_temp,4,new QStandardItem("HTTP"));
                        allinfo_model->setItem(line_temp,6,new QStandardItem(QString(QLatin1String((char *)tcp_p->data))));
                    }
                    else{
                        allinfo_model->setItem(line_temp,4,new QStandardItem("TCP"));
                        allinfo_model->setItem(line_temp,6,new QStandardItem("port:"+QString::number(ntohs(tcp_p->tcphdr.SrcPort)) + " → " +
                                                                                    QString::number(ntohs(tcp_p->tcphdr.DstPort)) + "  Seq=" +
                                                                                    QString::number(ntohl(tcp_p->tcphdr.SeqNum)) + "  Ack=" +
                                                                                    QString::number(ntohl(tcp_p->tcphdr.AckNum)) + "  Win=" +
                                                                                    QString::number(ntohs(tcp_p->tcphdr.Window))));
                    }
                    line_temp++;
                }
                tcp_p = tcp_p->next;
            }
            //仅port
            else if(ui->assign_ip_btn->isChecked() != true && ui->assign_port_btn->isChecked() == true){
                temp_portstr = ui->port_input->text();
                if(temp_portstr == NULL){
                    mybox->show();
                    mybox->setText("请输入端口号");
                    break;
                }
                if(QString::number(ntohs(tcp_p->tcphdr.SrcPort)) == temp_portstr || QString::number(ntohs(tcp_p->tcphdr.DstPort)) == temp_portstr){
                    temp_t = (double)tcp_p->pkthdr.ts.ts_sec + ((double)(tcp_p->pkthdr.ts.ts_usec)/1000000);
                    allinfo_model->setItem(line_temp,0,new QStandardItem(QString::number(tcp_p->Seq_num)));
                    allinfo_model->setItem(line_temp,1,new QStandardItem(QString::number(temp_t-zero_t,'f',6)));
                    allinfo_model->setItem(line_temp,2,new QStandardItem(uintToIPQstr(tcp_p->iphdr.SrcIP)));
                    allinfo_model->setItem(line_temp,3,new QStandardItem(uintToIPQstr(tcp_p->iphdr.DstIP)));
                    allinfo_model->setItem(line_temp,5,new QStandardItem(QString::number(tcp_p->pkthdr.caplen)));
                    if(FindHttpStr(QString(QLatin1String((char *)tcp_p->data)))){
                        allinfo_model->setItem(line_temp,4,new QStandardItem("HTTP"));
                        allinfo_model->setItem(line_temp,6,new QStandardItem(QString(QLatin1String((char *)tcp_p->data))));
                    }
                    else{
                        allinfo_model->setItem(line_temp,4,new QStandardItem("TCP"));
                        allinfo_model->setItem(line_temp,6,new QStandardItem("port:"+QString::number(ntohs(tcp_p->tcphdr.SrcPort)) + " → " +
                                                                                    QString::number(ntohs(tcp_p->tcphdr.DstPort)) + "  Seq=" +
                                                                                    QString::number(ntohl(tcp_p->tcphdr.SeqNum)) + "  Ack=" +
                                                                                    QString::number(ntohl(tcp_p->tcphdr.AckNum)) + "  Win=" +
                                                                                    QString::number(ntohs(tcp_p->tcphdr.Window))));
                    }
                    line_temp++;
                }
                tcp_p = tcp_p->next;
            }
            //ip port 都为空
            else if(ui->assign_ip_btn->isChecked() != true && ui->assign_port_btn->isChecked() != true){
                temp_t = (double)tcp_p->pkthdr.ts.ts_sec + ((double)(tcp_p->pkthdr.ts.ts_usec)/1000000);
                allinfo_model->setItem(line_temp,0,new QStandardItem(QString::number(tcp_p->Seq_num)));
                allinfo_model->setItem(line_temp,1,new QStandardItem(QString::number(temp_t-zero_t,'f',6)));
                allinfo_model->setItem(line_temp,2,new QStandardItem(uintToIPQstr(tcp_p->iphdr.SrcIP)));
                allinfo_model->setItem(line_temp,3,new QStandardItem(uintToIPQstr(tcp_p->iphdr.DstIP)));
                allinfo_model->setItem(line_temp,5,new QStandardItem(QString::number(tcp_p->pkthdr.caplen)));
                if(FindHttpStr(QString(QLatin1String((char *)tcp_p->data)))){
                    allinfo_model->setItem(line_temp,4,new QStandardItem("HTTP"));
                    allinfo_model->setItem(line_temp,6,new QStandardItem(QString(QLatin1String((char *)tcp_p->data))));
                }
                else{
                    allinfo_model->setItem(line_temp,4,new QStandardItem("TCP"));
                    allinfo_model->setItem(line_temp,6,new QStandardItem("port:"+QString::number(ntohs(tcp_p->tcphdr.SrcPort)) + " → " +
                                                                                QString::number(ntohs(tcp_p->tcphdr.DstPort)) + "  Seq=" +
                                                                                QString::number(ntohl(tcp_p->tcphdr.SeqNum)) + "  Ack=" +
                                                                                QString::number(ntohl(tcp_p->tcphdr.AckNum)) + "  Win=" +
                                                                                QString::number(ntohs(tcp_p->tcphdr.Window))));
                }
                line_temp++;
                tcp_p = tcp_p->next;
            }
        }
    }
    //UDP____//++++++++++++
    else if(ui->udp_op_btn->isChecked() == true){
        QString temp_ipstr = NULL;
        QString temp_portstr = NULL;
        int line_temp = 0;
        while(udp_p){
            //ip port 都筛选
            if(ui->assign_ip_btn->isChecked() == true && ui->assign_port_btn->isChecked() == true){
                temp_ipstr = ui->ipaddr_input->text();
                temp_portstr = ui->port_input->text();
                if(temp_ipstr == NULL){
                    mybox->show();
                    mybox->setText("请输入IP");
                    break;
                }
                if(temp_ipstr == NULL){
                    mybox->show();
                    mybox->setText("请输入端口号");
                    break;
                }
                if((uintToIPQstr(udp_p->iphdr.SrcIP) == temp_ipstr ||
                    uintToIPQstr(udp_p->iphdr.DstIP) == temp_ipstr) &&
                   (QString::number(ntohs(udp_p->udphdr.SrcPort)) == temp_portstr ||
                    QString::number(ntohs(udp_p->udphdr.DstPort)) == temp_portstr)){
                    temp_t = (double)udp_p->pkthdr.ts.ts_sec + ((double)(udp_p->pkthdr.ts.ts_usec)/1000000);
                    allinfo_model->setItem(line_temp,0,new QStandardItem(QString::number(udp_p->Seq_num)));
                    allinfo_model->setItem(line_temp,1,new QStandardItem(QString::number(temp_t-zero_t,'f',6)));
                    allinfo_model->setItem(line_temp,2,new QStandardItem(uintToIPQstr(udp_p->iphdr.SrcIP)));
                    allinfo_model->setItem(line_temp,3,new QStandardItem(uintToIPQstr(udp_p->iphdr.DstIP)));
                    allinfo_model->setItem(line_temp,4,new QStandardItem("UDP"));
                    allinfo_model->setItem(line_temp,5,new QStandardItem(QString::number(udp_p->pkthdr.caplen)));
                    allinfo_model->setItem(line_temp,6,new QStandardItem("port:"+QString::number(ntohs(udp_p->udphdr.SrcPort))+" → " +
                                                                         QString::number(ntohs(udp_p->udphdr.DstPort))+"  Len=" +
                                                                         QString::number(ntohs(udp_p->udphdr.SegLen)-UDP_HLEN)));
                    line_temp++;
                }
                udp_p = udp_p->next;
            }
            //仅ip
            else if(ui->assign_ip_btn->isChecked() == true && ui->assign_port_btn->isChecked() != true){
                temp_ipstr = ui->ipaddr_input->text();
                if(temp_ipstr == NULL){
                    mybox->show();
                    mybox->setText("请输入IP");
                    break;
                }
                if(uintToIPQstr(udp_p->iphdr.SrcIP) == temp_ipstr || uintToIPQstr(udp_p->iphdr.DstIP) == temp_ipstr){
                    temp_t = (double)udp_p->pkthdr.ts.ts_sec + ((double)(udp_p->pkthdr.ts.ts_usec)/1000000);
                    allinfo_model->setItem(line_temp,0,new QStandardItem(QString::number(udp_p->Seq_num)));
                    allinfo_model->setItem(line_temp,1,new QStandardItem(QString::number(temp_t-zero_t,'f',6)));
                    allinfo_model->setItem(line_temp,2,new QStandardItem(uintToIPQstr(udp_p->iphdr.SrcIP)));
                    allinfo_model->setItem(line_temp,3,new QStandardItem(uintToIPQstr(udp_p->iphdr.DstIP)));
                    allinfo_model->setItem(line_temp,4,new QStandardItem("UDP"));
                    allinfo_model->setItem(line_temp,5,new QStandardItem(QString::number(udp_p->pkthdr.caplen)));
                    allinfo_model->setItem(line_temp,6,new QStandardItem("port:"+QString::number(ntohs(udp_p->udphdr.SrcPort))+" → " +
                                                                         QString::number(ntohs(udp_p->udphdr.DstPort))+"  Len=" +
                                                                         QString::number(ntohs(udp_p->udphdr.SegLen)-UDP_HLEN)));
                line_temp++;
                }
                udp_p = udp_p->next;
            }
            //仅port
            else if(ui->assign_ip_btn->isChecked() != true && ui->assign_port_btn->isChecked() == true){
                temp_portstr = ui->port_input->text();
                if(temp_portstr == NULL){
                    mybox->show();
                    mybox->setText("请输入端口号");
                    break;
                }
                if(QString::number(ntohs(udp_p->udphdr.SrcPort)) == temp_portstr || QString::number(ntohs(udp_p->udphdr.DstPort)) == temp_portstr){
                    temp_t = (double)udp_p->pkthdr.ts.ts_sec + ((double)(udp_p->pkthdr.ts.ts_usec)/1000000);
                    allinfo_model->setItem(line_temp,0,new QStandardItem(QString::number(udp_p->Seq_num)));
                    allinfo_model->setItem(line_temp,1,new QStandardItem(QString::number(temp_t-zero_t,'f',6)));
                    allinfo_model->setItem(line_temp,2,new QStandardItem(uintToIPQstr(udp_p->iphdr.SrcIP)));
                    allinfo_model->setItem(line_temp,3,new QStandardItem(uintToIPQstr(udp_p->iphdr.DstIP)));
                    allinfo_model->setItem(line_temp,4,new QStandardItem("UDP"));
                    allinfo_model->setItem(line_temp,5,new QStandardItem(QString::number(udp_p->pkthdr.caplen)));
                    allinfo_model->setItem(line_temp,6,new QStandardItem("port:"+QString::number(ntohs(udp_p->udphdr.SrcPort))+" → " +
                                                                         QString::number(ntohs(udp_p->udphdr.DstPort))+"  Len=" +
                                                                         QString::number(ntohs(udp_p->udphdr.SegLen)-UDP_HLEN)));
                    line_temp++;
                }
                udp_p = udp_p->next;
            }
            //ip port 都为空
            else if(ui->assign_ip_btn->isChecked() != true && ui->assign_port_btn->isChecked() != true){
                temp_t = (double)udp_p->pkthdr.ts.ts_sec + ((double)(udp_p->pkthdr.ts.ts_usec)/1000000);
                allinfo_model->setItem(line_temp,0,new QStandardItem(QString::number(udp_p->Seq_num)));
                allinfo_model->setItem(line_temp,1,new QStandardItem(QString::number(temp_t-zero_t,'f',6)));
                allinfo_model->setItem(line_temp,2,new QStandardItem(uintToIPQstr(udp_p->iphdr.SrcIP)));
                allinfo_model->setItem(line_temp,3,new QStandardItem(uintToIPQstr(udp_p->iphdr.DstIP)));
                allinfo_model->setItem(line_temp,4,new QStandardItem("UDP"));
                allinfo_model->setItem(line_temp,5,new QStandardItem(QString::number(udp_p->pkthdr.caplen)));
                allinfo_model->setItem(line_temp,6,new QStandardItem("port:"+QString::number(ntohs(udp_p->udphdr.SrcPort))+" → " +
                                                                     QString::number(ntohs(udp_p->udphdr.DstPort))+"  Len=" +
                                                                     QString::number(ntohs(udp_p->udphdr.SegLen)-UDP_HLEN)));
                line_temp++;
                udp_p = udp_p->next;
            }
        }
    }
    //ARP____
    else if(ui->arp_op_btn->isChecked() == true){
        int line_temp = 0;
        while(arp_p){
            //port不存在的
            if(ui->assign_port_btn->isChecked() == true){
                mybox->show();
                mybox->setText("该协议不具备端口号");
                ui->all_port_btn->setChecked(true);
                //ui->assign_port_btn->setChecked(false);
                break;
            }
            //仅ip
            else if(ui->assign_ip_btn->isChecked() == true){
                mybox->show();
                mybox->setText("该协议不具备IP头");
                ui->all_ip_btn->setChecked(true);
                //ui->assign_ip_btn->setChecked(false);
                break;
            }
            else{
                temp_t = (double)arp_p->pkthdr.ts.ts_sec + ((double)(arp_p->pkthdr.ts.ts_usec)/1000000);
                allinfo_model->setItem(line_temp,0,new QStandardItem(QString::number(arp_p->Seq_num)));
                allinfo_model->setItem(line_temp,1,new QStandardItem(QString::number(temp_t-zero_t,'f',6)));
                allinfo_model->setItem(line_temp,2,new QStandardItem(ucharToMACQstr(arp_p->etherhdr.SrcMAC)));
                allinfo_model->setItem(line_temp,3,new QStandardItem(ucharToMACQstr(arp_p->etherhdr.DstMAC)));
                allinfo_model->setItem(line_temp,4,new QStandardItem("ARP"));
                allinfo_model->setItem(line_temp,5,new QStandardItem(QString::number(arp_p->pkthdr.caplen)));
                if(ntohs(arp_p->arphdr.ARPOP) == 1){  //请求
                    allinfo_model->setItem(line_temp,6,new QStandardItem("From "+uintToIPQstr(*((uint *)(arp_p->data + 6)))+
                                                                                " request:"+uintToIPQstr(*((uint *)(arp_p->data + 16)))));
                }
                else if (ntohs(arp_p->arphdr.ARPOP) == 2){    //应答
                    allinfo_model->setItem(line_temp,6,new QStandardItem("To " + uintToIPQstr(*((uint *)(arp_p->data + 16)))+" reply:"+
                                                                          uintToIPQstr(*((uint *)(arp_p->data + 6)))+
                                                                         "⇄" +ucharToMACQstr(arp_p->data)));
                }
                line_temp++;
            }
            arp_p = arp_p->next;
        }
    }

    //显示总体统计信息（表4）
    /*ETHERNET
     *    IP
     *        ICMP
     *        IGMP
     *        TCP
     *           HTTP
     *        UDP
     *           DHCP
     *           DNS
     *    ARP
    */
    //++++++++++++
}

void pkt_proc::on_assign_ip_btn_toggled(bool checked)
{
    if(checked == true)
        ui->ipaddr_input->setEnabled(1);
    else{
        ui->ipaddr_input->setEnabled(0);
        ui->ipaddr_input->clear();
    }
}

void pkt_proc::on_assign_port_btn_toggled(bool checked)
{
    if(checked == true)
        ui->port_input->setEnabled(1);
    else{
        ui->port_input->setEnabled(0);
        ui->port_input->clear();
    }
}
