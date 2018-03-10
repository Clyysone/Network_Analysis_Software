#include "mainwindow.h"
#include <QApplication>

//设置一些全局变量
QString analyse_filename;

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.show();

    return a.exec();
}
