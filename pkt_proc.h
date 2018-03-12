#ifndef PKT_PROC_H
#define PKT_PROC_H

#include <QDialog>
#include <pcap.h>
#include <QMessageBox>
#include "base_type.h"

extern QString analyse_filename;//待分析的文件名

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
    void on_tabWidget_tabBarClicked(int index);

private:
    Ui::pkt_proc *ui;
    pcap_t *source_pcap_t;
    char errbuf[PCAP_ERRBUF_SIZE];
    QMessageBox *mybox;
};

#endif // PKT_PROC_H
