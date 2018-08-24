#ifndef ICMPSEND_H
#define ICMPSEND_H

#include <QWidget>
#include <stdio.h>
#include <libnet.h>
#include <QDebug>
namespace Ui {
class Icmpsend;
}

class Icmpsend : public QWidget
{
    Q_OBJECT

public:
    explicit Icmpsend(QWidget *parent = 0);
    ~Icmpsend();

private slots:
    void on_sendpushButton_clicked();

    void on_pushButtonexit_clicked();

private:
    Ui::Icmpsend *ui;
};

#endif // ICMPSEND_H
