#ifndef HELP_INFO_H
#define HELP_INFO_H

#include <QDialog>

namespace Ui {
class help_info;
}

class help_info : public QDialog
{
    Q_OBJECT

public:
    explicit help_info(QWidget *parent = 0);
    ~help_info();

private:
    Ui::help_info *ui;
};

#endif // HELP_INFO_H
