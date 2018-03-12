#include "pkt_proc.h"
#include "ui_pkt_proc.h"

pkt_proc::pkt_proc(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::pkt_proc)
{
    ui->setupUi(this);
    mybox = new QMessageBox(this);
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
    //显示到总览表
    QStandardItemModel *allinfo_model = new QStandardItemModel();
    allinfo_model->setHorizontalHeaderItem(0,new QStandardItem(QObject::tr("时间")));
    allinfo_model->setHorizontalHeaderItem(1,new QStandardItem(QObject::tr("源地址")));
    allinfo_model->setHorizontalHeaderItem(2,new QStandardItem(QObject::tr("目的地址")));
    allinfo_model->setHorizontalHeaderItem(3,new QStandardItem(QObject::tr("协议")));
    allinfo_model->setHorizontalHeaderItem(4,new QStandardItem(QObject::tr("长度")));
    allinfo_model->setHorizontalHeaderItem(5,new QStandardItem(QObject::tr("信息")));
    ui->overviewTable->setModel(allinfo_model);
    //先设置总览中的表格相关信息
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
    pcappkt_t *p;
    int i=0;
    p = Header_allpkt->nextpkt;
    while(p){
        allinfo_model->setItem(i,4,new QStandardItem(QString::number(p->pkthdr.caplen)));
        p = p->nextpkt;
        i++;
    }
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
    pcappkt_t *p = Header_allpkt->nextpkt;
    for(int i = 0; i < index.row(); i++){
        p = p->nextpkt;
    }
    //ui->headerTable->setText(QString::number(index.row()+1));
    ui->dataTable->setText(data_ucharTostr(p->pktdate,p->pkthdr.caplen));
    ui->headerTable->setText(QString::number(p->pkthdr.len));
}
