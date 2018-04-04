#include "mainwindow.h"
#include <QApplication>

//设置一些全局变量
QString analyse_filename; //待分析的文件名
All_list_hdr_t Alist_Hdr;
int line;
int flag_icmp;
int flag_tcp;
int flag_udp;
int flag_arp;
double zero_t;

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.show();
    return a.exec();
}


