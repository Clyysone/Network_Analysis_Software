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
extern pcappkt_t *Header_allpkt;
extern pcappkt_t *allpkt_temp;

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
    void initWidget();
    void on_tabWidget_tabBarClicked(int index);

    void on_overviewTable_clicked(const QModelIndex &index);

private:
    Ui::pkt_proc *ui;
    pcap_t *source_pcap_t;
    char errbuf[PCAP_ERRBUF_SIZE];
    QMessageBox *mybox;
    QStandardItemModel *content_model;
    int time_sec;
};

#endif // PKT_PROC_H
