#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "pkt_proc.h"
#include "help_info.h"

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

private:
    Ui::MainWindow *ui;
    pkt_proc *p;
    help_info *h;
};

#endif // MAINWINDOW_H
