#include "pkt_proc.h"
#include "ui_pkt_proc.h"

pkt_proc::pkt_proc(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::pkt_proc)
{
    ui->setupUi(this);
    mybox = new QMessageBox(this);
    content_model = new QStandardItemModel();
    initWidget();  //调用一波初始化
}

pkt_proc::~pkt_proc()
{
    pcap_close(source_pcap_t);
    delete ui;
}

//进行一些初始化操作
void pkt_proc::initWidget()
{
    //设置总览中的表格相关信息(表一)
    QStandardItemModel *allinfo_model = new QStandardItemModel();
    allinfo_model->setHorizontalHeaderItem(0,new QStandardItem(QObject::tr("时间")));
    allinfo_model->setHorizontalHeaderItem(1,new QStandardItem(QObject::tr("源地址")));
    allinfo_model->setHorizontalHeaderItem(2,new QStandardItem(QObject::tr("目的地址")));
    allinfo_model->setHorizontalHeaderItem(3,new QStandardItem(QObject::tr("协议")));
    allinfo_model->setHorizontalHeaderItem(4,new QStandardItem(QObject::tr("长度")));
    allinfo_model->setHorizontalHeaderItem(5,new QStandardItem(QObject::tr("信息")));
    ui->overviewTable->setModel(allinfo_model);
    ui->overviewTable->setSelectionBehavior(QAbstractItemView::SelectRows);//设置为整行选择
    ui->overviewTable->setEditTriggers(QAbstractItemView::NoEditTriggers);//设置为禁止编辑
    ui->overviewTable->setColumnWidth(0,80);
    ui->overviewTable->setColumnWidth(1,120);
    ui->overviewTable->setColumnWidth(2,120);
    ui->overviewTable->setColumnWidth(3,50);
    ui->overviewTable->setColumnWidth(4,50);
    ui->overviewTable->setColumnWidth(5,170);
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
    allpkt_temp = (pcappkt_t *)malloc(sizeof(pcappkt_t));
    Header_allpkt = allpkt_temp;
    pcap_loop(source_pcap_t,-1,pcap_callback_t,NULL);
    //显示到总览表
    pcappkt_t *p;
    int i=0;
    p = Header_allpkt->nextpkt;
    while(p){
        allinfo_model->setItem(i,4,new QStandardItem(QString::number(p->pkthdr.caplen)));
        p = p->nextpkt;
        i++;
    }

    //设置数据内容表中的相关信息(表2)
    content_model->setHorizontalHeaderItem(0,new QStandardItem(QObject::tr("No.")));
    content_model->setHorizontalHeaderItem(1,new QStandardItem(QObject::tr("十六进制")));
    content_model->setHorizontalHeaderItem(2,new QStandardItem(QObject::tr("ASCII码")));
    ui->contentTable->setModel(content_model);
    ui->contentTable->setEditTriggers(QAbstractItemView::NoEditTriggers);//设置为禁止编辑
    ui->contentTable->setSelectionBehavior(QAbstractItemView::SelectRows);//设置为整行选择
    ui->contentTable->verticalHeader()->hide();//隐藏头
    ui->contentTable->setShowGrid(false);//隐藏表格线
    ui->contentTable->setColumnWidth(0,100);
    ui->contentTable->setColumnWidth(1,541);
    ui->contentTable->setColumnWidth(2,293);





    /*
    content_model->setItem(0,0,new QStandardItem("0000"));
    content_model->setItem(0,1,new QStandardItem("14  14  14  14  14  14  14  14    14  14  14  14  14  14  14  14"));
    content_model->setItem(0,2,new QStandardItem(". K L . . . . L  I [ . . . K P ."));
    content_model->item(0, 0)->setTextAlignment(Qt::AlignCenter);
    content_model->item(0, 1)->setTextAlignment(Qt::AlignCenter);
    content_model->item(0, 2)->setTextAlignment(Qt::AlignCenter);
    content_model->setItem(1,0,new QStandardItem("0010"));
    content_model->setItem(1,1,new QStandardItem("14  14  14  14  14  14  14  14    14  14  14  14  14  14  14  14"));
    content_model->setItem(1,2,new QStandardItem(". K L . . . . L  I [ . . . K P ."));
    content_model->item(1, 0)->setTextAlignment(Qt::AlignCenter);
    content_model->item(1, 1)->setTextAlignment(Qt::AlignCenter);
    content_model->item(1, 2)->setTextAlignment(Qt::AlignCenter);
    */

    /*
    pcap_pkthdr *pkthdr_temp = NULL;
    const uchar8_t *pktdata_temp;
    pcappkt_t *allpkt_temp;
    pktdata_temp = pcap_next(source_pcap_t, pkthdr_temp);
    qDebug() << pktdata_temp;
    allpkt_temp = (pcappkt_t *)malloc(sizeof(pcappkt_t)+pkthdr_temp->caplen);
    strcpy((char *)allpkt_temp->pktdate,(char *)pktdata_temp);
    allpkt_temp->pkthdr.len = pkthdr_temp->len;
    allpkt_temp->pkthdr.caplen = pkthdr_temp->caplen;
    allpkt_temp->pkthdr.seconds = pkthdr_temp->ts.tv_sec;
    allpkt_temp->pkthdr.u_seconds = pkthdr_temp->ts.tv_usec;
    allpkt_temp->nextpkt = NULL;
    Header_allpkt = allpkt_temp;

    while(1){
        pktdata_temp = pcap_next(source_pcap_t, pkthdr_temp);
        if(NULL == pktdata_temp) break;
        else{
            allpkt_temp->nextpkt = (pcappkt_t *)malloc(sizeof(pcappkt_t)+pkthdr_temp->caplen);
            allpkt_temp = allpkt_temp->nextpkt;
            strcpy((char *)allpkt_temp->pktdate,(char *)pktdata_temp);
            allpkt_temp->pkthdr.len = pkthdr_temp->len;
            allpkt_temp->pkthdr.caplen = pkthdr_temp->caplen;
            allpkt_temp->pkthdr.seconds = pkthdr_temp->ts.tv_sec;
            allpkt_temp->pkthdr.u_seconds = pkthdr_temp->ts.tv_usec;
            allpkt_temp->nextpkt = NULL;
        }
    }
    */

}

//返回按钮
void pkt_proc::on_tabWidget_tabBarClicked(int index)
{
    if(index == 2){
        QMessageBox::StandardButton rb = QMessageBox::question(this, "确认框", "确定要退出?", QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes);
        if(rb == QMessageBox::Yes){
            this->close();
            parentWidget()->show();
        }
        //ui->tabWidget->setCurrentWidget(ui->tab_1);
    }
}

//总览表点击事件
void pkt_proc::on_overviewTable_clicked(const QModelIndex &index)
{
    //首先遍历得到对应的数据包结构体指针
    pcappkt_t *p = Header_allpkt->nextpkt;
    for(int i = 0; i < index.row(); i++){
        p = p->nextpkt;
    }
    char *temp_q = data_ucharTostr(p->pktdata,p->pkthdr.caplen);//将字符类型转换为十六进制数据，并改格式补空格隔开每个字节
    int content_row; // 显示行数，每16字节一行
    if(p->pkthdr.caplen%16 == 0 )
        content_row = p->pkthdr.caplen/16;
    else content_row = p->pkthdr.caplen/16 + 1;

    char content_ch[content_row][64];//为显示到表中定义的二维数组
    for(int i=0; i<content_row; i++){
        for(int j=0 ; j<64; j++){
            content_ch[i][j] = ' ';
        }
    }//先将二维数组赋初值为字符空格
    uint32_t num_count = 0;//对一维字符串数据提取变为二维数组
    for(int i=0; i<content_row; i++){
        for(int j=0 ; j<64; j++){
            num_count++;
            content_ch[i][j] = temp_q[i*64+j];
            if(num_count == p->pkthdr.caplen*4)
                break;
        }
    }
    //一行一行提取数据并单行显示
    char temp_onerow[64];//一行数据
    char temp_no[4];//每行的头位置数
    for(int i=0; i<content_row; i++){
        //显示头位置数
        memcpy(temp_no,_4No_pro(i),4);
        content_model->setItem(i,0,new QStandardItem(temp_no));//显示到表中
        content_model->item(i, 0)->setTextAlignment(Qt::AlignCenter);//居中显示
        //显示一行数据
        memcpy(temp_onerow,content_ch[i],64);
        content_model->setItem(i,1,new QStandardItem(temp_onerow));//显示到表中
        content_model->item(i, 1)->setTextAlignment(Qt::AlignCenter);//居中显示
    }
    ui->headerTable->setText(QString::number(p->pkthdr.len));
}
