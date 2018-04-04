#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "pkt_proc.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    mybox = new QMessageBox(this);
    on_refresh_btn_clicked();
}

MainWindow::~MainWindow()
{
    delete ui;
}

//开始分析按钮
void MainWindow::on_start_btn_clicked()
{
    analyse_filename = ui->FileComboBox->currentText();
    if(analyse_filename == ""){
        mybox->show();
        mybox->setText("请先选择文件!(点击刷新)");
    }
    else{
        QFileInfo info("/Users/yanliang/Desktop/Clyysone/inbox/Bs_Pro/Graduation_pro/"+analyse_filename);//***有待修改***
        if(!info.exists()){
            mybox->show();
            mybox->setText("文件不存在!请刷新后重试。");
        }
        else{
            p = new pkt_proc(this);
            this->hide();
            p->show();
        }
    }
}
//帮助信息按钮
void MainWindow::on_help_btn_clicked()
{
    h = new help_info();
    h->show();
}
//刷新按钮
void MainWindow::on_refresh_btn_clicked()
{
    //qDebug() << QDir::currentPath();
    //QDir::setCurrent(qApp->applicationDirPath());
    QDir dir;
    dir.setPath("/Users/yanliang/Desktop/Clyysone/inbox/Bs_Pro/Graduation_pro");//***有待修改***
    QStringList filters; //只去读pcap后缀的文件
    filters << "*.pcap";
    dir.setNameFilters(filters);
    QFileInfoList list = dir.entryInfoList();
    ui->FileComboBox->clear();
    ui->FileComboBox->addItem("");
    if(list.length() != 0)
        for (int i = 0; i < list.size(); i++){
            ui->FileComboBox->addItem(list.at(i).fileName());
        }
    else{
        mybox->show();
        mybox->setText("很抱歉,没有发现pcap文件!(请查看帮助)");
    }
}
