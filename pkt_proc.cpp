#include "pkt_proc.h"
#include "ui_pkt_proc.h"

pkt_proc::pkt_proc(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::pkt_proc)
{
    ui->setupUi(this);

}

pkt_proc::~pkt_proc()
{
    delete ui;
}
//返回按钮
void pkt_proc::on_back_btn_clicked()
{
    this->close();
    parentWidget()->show();
}
