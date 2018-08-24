#ifndef PINGSET_H
#define PINGSET_H

#include <QWidget>
#include <stdio.h>
#include <libnet.h>
#include <QDebug>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include "widget.h"
namespace Ui {
class Pingset;
}

class Pingset : public QWidget
{
    Q_OBJECT

public:
    explicit Pingset(QWidget *parent = 0);
    ~Pingset();

private slots:
    void on_pingpushButton_clicked();

private:
    Ui::Pingset *ui;
};

#endif // PINGSET_H
