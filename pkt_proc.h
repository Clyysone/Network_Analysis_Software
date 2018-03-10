#ifndef PKT_PROC_H
#define PKT_PROC_H

#include <QDialog>
#include <pcap.h>

namespace Ui {
class pkt_proc;
}

class pkt_proc : public QDialog
{
    Q_OBJECT

public:
    explicit pkt_proc(QWidget *parent = 0);
    ~pkt_proc();

private slots:
    void on_back_btn_clicked();

private:
    Ui::pkt_proc *ui;
};

#endif // PKT_PROC_H
