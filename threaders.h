#ifndef THREADERS_H
#define THREADERS_H
#include <QThread>
#include <stdio.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <QSqlDatabase>
#include <QMessageBox>
#include <QSqlQuery>
#include <QWidget>
class threaders : public QThread
{
     Q_OBJECT
public:
    threaders();
    void run();
   static void ethernet_protocol_packet_callback(u_char *argument,const struct pcap_pkthdr* packet_header,
                                           const u_char* packet_content);
    static void ip_protocol_packet_callback(const u_char* packet_content);
    static void arp_protocol_packet_callback(const u_char* packet_content);


   static QString SrcMAC;
   static u_int caplens;
   static QString caplength;
   static QString Length;
   static QString ipnames;
  // static  QSqlDatabase db2;
   //static QSqlQuery query2;
signals:
    // 线程的信号
    void Signalpacket(QString,QString,const u_char*,QString nameip);

};

#endif // THREADERS_H
