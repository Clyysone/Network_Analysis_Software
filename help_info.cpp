#include "help_info.h"
#include "ui_help_info.h"

help_info::help_info(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::help_info)
{
    ui->setupUi(this);
}

help_info::~help_info()
{
    delete ui;
}
