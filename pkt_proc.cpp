#include "pkt_proc.h"
#include "ui_pkt_proc.h"

pkt_proc::pkt_proc(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::pkt_proc)
{
    ui->setupUi(this);
    mybox = new QMessageBox(this);
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
}

pkt_proc::~pkt_proc()
{
    pcap_close(source_pcap_t);
    delete ui;
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
