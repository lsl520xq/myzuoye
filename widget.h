#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>
#include <QMessageBox>
#include <QListWidget>
#include <QThread>
#include <stdio.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <QDebug>
#include "threaders.h"
#include "ipthresders.h"
#include <QByteArray>
#include <QListWidgetItem>
#include <QtCore>
#include <QTextCodec>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QTime>
#include <QSqlError>
#include <QSqlDriver>
#include <QSqlRecord>
#include <QSqlQueryModel>
#include "sendpacket.h"
#include "pingset.h"
namespace Ui {
class Widget;
}

class Widget:public QWidget
{
    Q_OBJECT

public:
    explicit Widget(QWidget *parent = 0);
    ~Widget();

   threaders *mythreas;
    QSqlDatabase db;
   void arp_protocol_packet_callback(QString caplength,const u_char* packet_content,QString name1);
   void ip_protocol_packet_callback(QString caplength,const u_char* packet_content,QString name1);
   void weizhi(QString caplength,const u_char* packet_content);
   void ARP_Analysis(int caplength, u_char* PacketContens);
   void TCP_Analysis(int caplength, u_char* PacketContens);
   void UDP_Analysis(int caplength, u_char* PacketContens);
   void ICMP_Analysis(int caplength, u_char* PacketContens);
   void IGMP_Analysis(int caplength, u_char* PacketContens);
   void analyspacket(QString text,QString packetse,int lengths);
   QString ips_toQstring(int ip);




public slots:
    void Packetmsg(QString caplength,QString Length,const u_char* pktData,QString names);
private slots:
    void on_tableWidget_cellClicked(int row, int column);

    void on_pushButton_3_clicked();

    void on_pushButton_2_clicked();

    void on_flitepushButton_clicked();

    void on_libnetpushButton_clicked();

    void on_pingpushButton_clicked();

    void on_driverpushButton_clicked();

private:
    Ui::Widget *ui;
    SendPacket *send;


signals:
    void ipdatasr(QString ipee);
     void ipdatads(QString ipee);


};

#endif // WIDGET_H
