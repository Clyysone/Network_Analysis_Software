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
    content_model->setHorizontalHeaderItem(16,new QStandardItem(QObject::tr("ASCII码")));
    ui->contentTable->setModel(content_model);
    ui->contentTable->setEditTriggers(QAbstractItemView::NoEditTriggers);//设置为禁止编辑
    ui->contentTable->setSelectionBehavior(QAbstractItemView::SelectRows);//设置为整行选择
    ui->contentTable->setShowGrid(false);//隐藏表格线
    for(int i=0; i<16; i++)
        ui->contentTable->setColumnWidth(i,37);
    ui->contentTable->setColumnWidth(16,295);

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
    //清空内容不清除表头
    int row_cnt = content_model->rowCount();
    for(int i=0; i<row_cnt; i++){
        content_model->removeRow(i);
    }
    //首先遍历得到对应的数据包结构体指针
    pcappkt_t *p = Header_allpkt->nextpkt;
    for(int i = 0; i < index.row(); i++){
        p = p->nextpkt;
    }
    uint32_t pkt_length = p->pkthdr.caplen; //包的字节数
    uchar8_t *pkt_char = p->pktdata;
    uint32_t content_row; // 显示行数，每16字节一行
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
}
