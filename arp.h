#ifndef ARP_H
#define ARP_H

#include <QWidget>
#include <stdio.h>
#include <libnet.h>
#include <QDebug>
namespace Ui {
class Arp;
}

class Arp : public QWidget
{
    Q_OBJECT

public:
    explicit Arp(QWidget *parent = 0);
    ~Arp();

private slots:
    void on_pushButton_clicked();

    void on_pushButtonexit_clicked();

private:
    Ui::Arp *ui;
};

#endif // ARP_H
