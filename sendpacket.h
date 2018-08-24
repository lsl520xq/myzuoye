#ifndef SENDPACKET_H
#define SENDPACKET_H

#include <QWidget>
#include <QDebug>
#include "arp.h"
#include "udpsend.h"
#include "icmpsend.h"
namespace Ui {
class SendPacket;
}

class SendPacket : public QWidget
{
    Q_OBJECT

public:
    explicit SendPacket(QWidget *parent = 0);
    ~SendPacket();

private slots:
    void on_selectcomboBox_currentTextChanged(const QString &arg1);

    void on_surepushButton_clicked();

    void on_exitpushButton_clicked();

private:
    Ui::SendPacket *ui;
    Arp *arps;
    Udpsend *udps;
    Icmpsend *icmps;

};

#endif // SENDPACKET_H
