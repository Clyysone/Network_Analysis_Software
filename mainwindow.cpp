#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "pkt_proc.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}
//开始分析按钮
void MainWindow::on_start_btn_clicked()
{
    p = new pkt_proc(this);
    this->hide();
    p->show();
}
//帮助信息按钮
void MainWindow::on_help_btn_clicked()
{
    h = new help_info();
    h->show();
}
