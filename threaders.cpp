#include "threaders.h"
#include <QDebug>
pcap_t* pcap_handle;   //libpcap句柄
char error_content[PCAP_ERRBUF_SIZE];
char *net_interface;     //网络接口
bpf_u_int32 net_mask; //子网掩码
bpf_u_int32 net_ip;
const u_char* data;
bool stop;
QString fliter;
QSqlDatabase db2;
  QString threaders::SrcMAC = "";
  u_int threaders::caplens =0;
  QString threaders::caplength = "";
  QString threaders::Length = "";
  QString threaders::ipnames="未找到地理位置";
 // QSqlDatabase threaders::db2;
 // QSqlQuery threaders::query2;

threaders::threaders()
{

}
//arp协议数据格式
struct arp_header
{
    u_int16_t arp_yinjian_type;
    u_int16_t arp_protocol_typa;
    u_int8_t arp_yinjian_leneth;
    u_int8_t arp_protocol_length;
    u_int16_t arp_op_code;
    u_int8_t arp_s_ethernet_address[6];
    u_int8_t arp_s_IP_address[4];
    u_int8_t arp_d_ethernet_address[6];
    u_int8_t arp_d_IP_address[4];

};
struct udp_protocol
{
   u_int16_t udp_src_host;
   u_int16_t udp_des_host;
   u_int16_t udp_length;
   u_int16_t udp_check;

};
struct ether_header
{
    u_int8_t ether_dhost[6];
    u_int8_t ether_shost[6];  //以太网
    u_int16_t ether_type;
};
struct ip_header
{
#ifdef WORDS_BIGENDIAN
    u_int8_t ip_banben:4,
ip_head_length:4;
#else
    u_int8_t ip_head_length:4,
ip_banben:4;
#endif
    u_int8_t service_TOS;
    u_int16_t total_length;
    u_int16_t index;
    u_int16_t pianyi;
    u_int8_t TTL;
    u_int8_t ip_protlcol;
    u_int16_t head_check;
    struct in_addr ip_sr;
    struct in_addr ip_des;

};
void threaders::ip_protocol_packet_callback(const u_char *packet_content)
{
        struct ip_header *ip_protocol;  //ip协议变量
        QSqlQuery query2(db2);
        sockaddr_in ina;//2181696010
        QString ip_namess;
        ip_protocol=(struct ip_header*)(packet_content+14);
      ip_namess=inet_ntoa(ip_protocol->ip_sr);

      QByteArray baty=ip_namess.toLatin1();const char *ip1=( const char*)baty.data();
       ina.sin_addr.s_addr = inet_addr(ip1);
      qDebug()<<"intip"<<ina.sin_addr.s_addr;

    // query2(db2);
      QString desquery=QString("select * from ip where ip_e='%1'" ).arg(3470645739);
      query2.exec(desquery);
      while (query2.next()) {
           ipnames=query2.value(2).toString();
           qDebug()<<"ipnames"<<ipnames;
      }
           // inet_ntoa(ip_protocol->ip_des);
}
void threaders::arp_protocol_packet_callback(const u_char *packet_content)
{
    struct arp_header *arp_protocol;  //arp协议变量
    QSqlQuery query2(db2);
    sockaddr_in ina;
    QString ip_namess;
    struct in_addr sr_ip_address;
   /*QSqlDatabase db3 =QSqlDatabase::addDatabase("QSQLITE","db3");
   db3.setDatabaseName("db_ip.db"); //设置数据库名
     if(!db3.open()){

         // QMessageBox::warning(this,tr("db2失败"),tr("login sql shibai!!"),QMessageBox::No);
         qDebug()<<"db3失败";

     }else{

        // QMessageBox::warning(this,tr("db2succese"),tr("login sql succses!!"),QMessageBox::Yes);
         qDebug()<<"db3succese";
     }
     */
    //struct in_addr ds_ip_address;
    arp_protocol=(struct arp_header*)(packet_content+14);
     memcpy((void*)&sr_ip_address,(void*)&arp_protocol->arp_s_IP_address,sizeof(struct in_addr));
    ip_namess=inet_ntoa(sr_ip_address);
    QByteArray baty=ip_namess.toLatin1();const char *ip1=( const char*)baty.data();
     ina.sin_addr.s_addr = inet_addr(ip1);
    qDebug()<<"intip"<<ina.sin_addr.s_addr;
    //query2(db2);
    QString desquery=QString("select * from ip where ip_e='%1'" ).arg(ina.sin_addr.s_addr);
    query2.exec(desquery);
    while (query2.next()) {
         ipnames=query2.value(2).toString();
    }
         //memcpy((void*)&ds_ip_address,(void*)&arp_protocol->arp_d_IP_address,sizeof(struct in_addr));

}

void threaders::ethernet_protocol_packet_callback(u_char *argument,const struct pcap_pkthdr* packet_header,
                                       const u_char* packet_content){

  struct ip_header *ip_protocol;  //ip协议变量
   u_short ethernet_type;

   struct ether_header *ethernet_protocol; //以太网协议

   ethernet_protocol=(struct ether_header*)packet_content;
   ethernet_type=ntohs(ethernet_protocol->ether_type);
   QStringList ffl;
   ffl=fliter.split("&");
   if(ffl[0]=="")
   {
       Length = QString::number(packet_header->len);
      caplength = QString::number(packet_header->caplen);
      switch (ethernet_type) {
          case 0x0800:

              ip_protocol_packet_callback(packet_content);
              break;
          case 0x0806:

              arp_protocol_packet_callback(packet_content);
              break;
          case 0x8035:

              arp_protocol_packet_callback(packet_content);
              break;
          }
       data=packet_content;
   }
   else if(ffl[0]=="ARP")
   {
       if(ethernet_type==0x0806)
       {
           Length = QString::number(packet_header->len);
          caplength = QString::number(packet_header->caplen);
          data=packet_content;
       }
   }else if(ffl[0]=="UDP"||ffl[0]=="TCP"||ffl[0]=="ICMP"||ffl[0]=="IGMP")
   {
       if(ethernet_type==0x0800)
       {
         ip_protocol=(struct ip_header*)(packet_content+14);
         switch (ip_protocol->ip_protlcol) {
             case 6:
             if(ffl[0]=="TCP")
             {
                 Length = QString::number(packet_header->len);
                caplength = QString::number(packet_header->caplen);
              data=packet_content;
             }
                 break;
             case 17:
             if(ffl[0]=="UDP"||ffl[1]!="")
             {
                 QString llf;
                 llf=ffl[1];
                 int sh=llf.toInt();
                 struct udp_protocol *udpheader;
                 udpheader=(struct udp_protocol*)(packet_content+34);
                   u_int16_t srchost;
                    srchost=ntohs(udpheader->udp_src_host);
                    if(ffl[1]!="")
                    {
                        if(sh==srchost)
                        {
                            Length = QString::number(packet_header->len);
                           caplength = QString::number(packet_header->caplen);
                         data=packet_content;
                        }
                    }
                    else{
                 Length = QString::number(packet_header->len);
                caplength = QString::number(packet_header->caplen);
              data=packet_content;
                    }
             }
                 break;
             case 1:
             if(ffl[0]=="ICMP")
             {
                 Length = QString::number(packet_header->len);
                caplength = QString::number(packet_header->caplen);
              data=packet_content;
             }
                 break;

             case 2:
             if(ffl[0]=="IGMP")
             {
                 Length = QString::number(packet_header->len);
                caplength = QString::number(packet_header->caplen);
              data=packet_content;
             }
                 break;
             }
       }
   }



pcap_breakloop(pcap_handle);


}

void threaders::run()
{
     db2=QSqlDatabase::addDatabase("QSQLITE","db2");
    db2.setDatabaseName("db_ip.db"); //设置数据库名
      if(!db2.open()){

          // QMessageBox::warning(this,tr("db2失败"),tr("login sql shibai!!"),QMessageBox::No);
          qDebug()<<"db3失败";

      }else{

         // QMessageBox::warning(this,tr("db2succese"),tr("login sql succses!!"),QMessageBox::Yes);
          qDebug()<<"db3succese";
      }

    while (1)
    {
        // 捕获数据包
        if(!stop)
        {
       pcap_loop(pcap_handle,-1,ethernet_protocol_packet_callback,NULL);

       emit Signalpacket(caplength,Length,data,ipnames);
       }
        // 发送信号

    }

     // qDebug()<<"123";
     // this->exec();
}


