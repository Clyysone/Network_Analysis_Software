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

void MainWindow::on_start_btn_clicked()
{
    p = new pkt_proc(this);
    this->hide();
    p->show();
}
