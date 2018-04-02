#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QDir>
#include <QFileInfo>
#include <QFileInfoList>
#include <QMessageBox>
#include "pkt_proc.h"
#include "help_info.h"

extern QString analyse_filename;//待分析的文件名

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    void on_start_btn_clicked();

    void on_help_btn_clicked();

    void on_refresh_btn_clicked();

private:
    Ui::MainWindow *ui;
    pkt_proc *p;
    help_info *h;
    QMessageBox *mybox;
};

#endif // MAINWINDOW_H
