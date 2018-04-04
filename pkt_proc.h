#ifndef PKT_PROC_H
#define PKT_PROC_H

#include <QDialog>
#include <QMessageBox>
#include <QTableWidget>
#include <QStandardItemModel>
#include <QTableWidget>
#include <QDebug>
#include <time.h>
#include "base_type.h"

extern QString analyse_filename;//待分析的文件名
extern All_list_hdr_t Alist_Hdr;
extern double zero_t;
extern int line;
extern int flag_icmp;
extern int flag_tcp;
extern int flag_udp;
extern int flag_arp;

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
    void analyse_pkt();

    void initWidget();

    void on_overviewTable_clicked(const QModelIndex &index);

    void on_back_btn_clicked();

    void on_statistics_btn_clicked();

private:
    Ui::pkt_proc *ui;
    pcap_t *source_pcap_t;
    char errbuf[PCAP_ERRBUF_SIZE];
    QMessageBox *mybox;
    QStandardItemModel *content_model;
    QStandardItemModel *allinfo_model;
    uint64_t time_sec;
};

#endif // PKT_PROC_H
