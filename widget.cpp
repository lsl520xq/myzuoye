#include "widget.h"
#include "ui_widget.h"
extern pcap_t* pcap_handle;   //libpcap句柄
extern char error_content[PCAP_ERRBUF_SIZE];
extern char *net_interface;     //网络接口
extern bpf_u_int32 net_mask; //子网掩码
extern bpf_u_int32 net_ip;
extern bool stop;
pcap_if_t *alldrivers;
pcap_if_t *d;


 QString annyTTL;
 QString icmp_srcips;
 int icmp_le;
 QString chuan_times;


static int packet_number=1;

static int packetnumber=0;
extern QString fliter;

u_char charmaps[] = {
    (u_char)'\000', (u_char)'\001', (u_char)'\002', (u_char)'\003',
    (u_char)'\004', (u_char)'\005', (u_char)'\006', (u_char)'\007',
    (u_char)'\010', (u_char)'\011', (u_char)'\012', (u_char)'\013',
    (u_char)'\014', (u_char)'\015', (u_char)'\016', (u_char)'\017',
    (u_char)'\020', (u_char)'\021', (u_char)'\022', (u_char)'\023',
    (u_char)'\024', (u_char)'\025', (u_char)'\026', (u_char)'\027',
    (u_char)'\030', (u_char)'\031', (u_char)'\032', (u_char)'\033',
    (u_char)'\034', (u_char)'\035', (u_char)'\036', (u_char)'\037',
    (u_char)'\040', (u_char)'\041', (u_char)'\042', (u_char)'\043',
    (u_char)'\044', (u_char)'\045', (u_char)'\046', (u_char)'\047',
    (u_char)'\050', (u_char)'\051', (u_char)'\052', (u_char)'\053',
    (u_char)'\054', (u_char)'\055', (u_char)'\056', (u_char)'\057',
    (u_char)'\060', (u_char)'\061', (u_char)'\062', (u_char)'\063',
    (u_char)'\064', (u_char)'\065', (u_char)'\066', (u_char)'\067',
    (u_char)'\070', (u_char)'\071', (u_char)'\072', (u_char)'\073',
    (u_char)'\074', (u_char)'\075', (u_char)'\076', (u_char)'\077',(u_char)'\100',
    (u_char)'\101', (u_char)'\102', (u_char)'\103', (u_char)'\104',//65-72
    (u_char)'\105', (u_char)'\106', (u_char)'\107', (u_char)'\110',
    (u_char)'\111', (u_char)'\112', (u_char)'\113', (u_char)'\114',//73-80
    (u_char)'\115', (u_char)'\116', (u_char)'\117', (u_char)'\120',
    (u_char)'\121', (u_char)'\122', (u_char)'\123', (u_char)'\124',//81-88
    (u_char)'\125', (u_char)'\126', (u_char)'\127', (u_char)'\130',
    (u_char)'\131', (u_char)'\132', (u_char)'\133', (u_char)'\134',
    (u_char)'\135', (u_char)'\136', (u_char)'\137',
    (u_char)'\140', (u_char)'\141', (u_char)'\142', (u_char)'\143',
    (u_char)'\144', (u_char)'\145', (u_char)'\146', (u_char)'\147',
    (u_char)'\150', (u_char)'\151', (u_char)'\152', (u_char)'\153',
    (u_char)'\154', (u_char)'\155', (u_char)'\156', (u_char)'\157',
    (u_char)'\160', (u_char)'\161', (u_char)'\162', (u_char)'\163',
    (u_char)'\164', (u_char)'\165', (u_char)'\166', (u_char)'\167',
    (u_char)'\170', (u_char)'\171', (u_char)'\172', (u_char)'\173',
    (u_char)'\174', (u_char)'\175', (u_char)'\176', (u_char)'\177',
    (u_char)'\200', (u_char)'\201', (u_char)'\202', (u_char)'\203',
    (u_char)'\204', (u_char)'\205', (u_char)'\206', (u_char)'\207',
    (u_char)'\210', (u_char)'\211', (u_char)'\212', (u_char)'\213',
    (u_char)'\214', (u_char)'\215', (u_char)'\216', (u_char)'\217',
    (u_char)'\220', (u_char)'\221', (u_char)'\222', (u_char)'\223',
    (u_char)'\224', (u_char)'\225', (u_char)'\226', (u_char)'\227',
    (u_char)'\230', (u_char)'\231', (u_char)'\232', (u_char)'\233',
    (u_char)'\234', (u_char)'\235', (u_char)'\236', (u_char)'\237',
    (u_char)'\240', (u_char)'\241', (u_char)'\242', (u_char)'\243',
    (u_char)'\244', (u_char)'\245', (u_char)'\246', (u_char)'\247',
    (u_char)'\250', (u_char)'\251', (u_char)'\252', (u_char)'\253',
    (u_char)'\254', (u_char)'\255', (u_char)'\256', (u_char)'\257',
    (u_char)'\260', (u_char)'\261', (u_char)'\262', (u_char)'\263',
    (u_char)'\264', (u_char)'\265', (u_char)'\266', (u_char)'\267',
    (u_char)'\270', (u_char)'\271', (u_char)'\272', (u_char)'\273',
    (u_char)'\274', (u_char)'\275', (u_char)'\276', (u_char)'\277',
    (u_char)'\300', (u_char)'\301', (u_char)'\302', (u_char)'\303',
    (u_char)'\304', (u_char)'\305', (u_char)'\306', (u_char)'\307',
    (u_char)'\310', (u_char)'\311', (u_char)'\312', (u_char)'\313',
    (u_char)'\314', (u_char)'\315', (u_char)'\316', (u_char)'\317',
    (u_char)'\320', (u_char)'\321', (u_char)'\322', (u_char)'\323',
    (u_char)'\324', (u_char)'\325', (u_char)'\326', (u_char)'\327',
    (u_char)'\330', (u_char)'\331', (u_char)'\332', (u_char)'\333',
    (u_char)'\334', (u_char)'\335', (u_char)'\336', (u_char)'\337',
    (u_char)'\340', (u_char)'\341', (u_char)'\342', (u_char)'\343',
    (u_char)'\344', (u_char)'\345', (u_char)'\346', (u_char)'\347',
    (u_char)'\350', (u_char)'\351', (u_char)'\352', (u_char)'\353',
    (u_char)'\354', (u_char)'\355', (u_char)'\356', (u_char)'\357',
    (u_char)'\360', (u_char)'\361', (u_char)'\362', (u_char)'\363',
    (u_char)'\364', (u_char)'\365', (u_char)'\366', (u_char)'\367',
    (u_char)'\370', (u_char)'\371', (u_char)'\372', (u_char)'\373',
    (u_char)'\374', (u_char)'\375', (u_char)'\376', (u_char)'\377',
};

 struct ether_header
 {
    u_int8_t ether_dhost[6];
    u_int8_t ether_shost[6];  //以太网
    u_int16_t ether_type;
 };
 //ip协议数据格式
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
 struct icmp_huixian_header
 {
    u_int8_t icmp_type;
    u_int8_t icmp_code;
    u_int16_t icmp_chek;
    u_int16_t icmp_index;
    u_int16_t icmp_ids;
 };
 struct icmp_yanma_header
 {
 u_int8_t icmp_type;
    u_int8_t icmp_code;
    u_int16_t icmp_chek;
    u_int16_t icmp_index;
    u_int16_t icmp_ids;
 u_int32_t icmp_ziwangyanma;
 };
 struct icmp_time_header
 {
    u_int8_t icmp_type;
    u_int8_t icmp_code;
    u_int16_t icmp_chek;
    u_int16_t icmp_index;
    u_int16_t icmp_ids;
    u_int32_t send_time;
    u_int32_t recieve_time;
    u_int32_t chuansong_time;

 };
 struct icmp_notarrive
 {
  u_int8_t icmp_type;
    u_int8_t icmp_code;
    u_int16_t icmp_chek;
 u_int8_t icmp_weiyong[4];
 u_int8_t icmp_ip[20];
 u_int8_t icmp_data_host[8];

 };
 struct icmp_timeout
 {
  u_int8_t icmp_type;
    u_int8_t icmp_code;
    u_int16_t icmp_chek;
 u_int8_t icmp_weiyong[4];
 u_int8_t icmp_ip[20];
 u_int8_t icmp_datas[8];

 };
 struct icmp_chongdingxiang
 {
 u_int8_t icmp_type;
    u_int8_t icmp_code;
    u_int16_t icmp_chek;
 u_int8_t icmp_getaway_ip[4];
 u_int8_t icmp_ip[20];
 u_int8_t icmp_datas[8];
 };
 struct icmp_fenpian
 {
 u_int8_t icmp_type;
    u_int8_t icmp_code;
    u_int16_t icmp_chek;
    u_int16_t icmp_wei;
    u_int16_t icmp_mtu;
 u_int8_t icmp_ip[20];
 u_int8_t icmp_datas[8];
 };
 struct icmp_geteway_tonggao
 {
   u_int8_t icmp_type;
    u_int8_t icmp_code;
    u_int16_t icmp_chek;
   u_int8_t icmp_dizhishu;
   u_int8_t icmp_dizhi_length;
   u_int16_t icmp_live_time;
   u_int8_t icmp_geteway_address[4];
   u_int8_t icmp_geteway_youxian[4];

 };
 struct udp_protocol
 {
    u_int16_t udp_src_host;
    u_int16_t udp_des_host;
    u_int16_t udp_length;
    u_int16_t udp_check;

 };
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
 //TCP协议数据格式
 struct tcp_header
 {
     u_int16_t tcp_src_host;
     u_int16_t tcp_des_host;
     u_int32_t tcp_id;
     u_int32_t tcp_ack;
 #ifdef WORDS_BIGENDIAN
     u_int8_t tcp_offset:4,
         tcp_reserved:4;
 #else
     u_int8_t tcp_reserved:4,
         tcp_offset:4;
 #endif
     u_int8_t tcp_flags;
     u_int16_t tcp_windowssize;
     u_int16_t tcp_checks;
     u_int16_t tcp_urgent_pointer;

 };
 struct igmp_header
 {
    u_int8_t igmp_vesion:4,
        igmp_type:4;
    u_int8_t igmp_null;
    u_int16_t igmp_cheks;
    u_int32_t igmp_group_address;

 };

Widget::Widget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Widget)
{
    ui->setupUi(this);
  char m[20];

   // net_interface=pcap_lookupdev(error_content);
                    int zt=pcap_findalldevs(&alldrivers,error_content);
                    if(zt==-1)
                    {
                        qDebug()<<"pcap_findalldevserror"<<error_content;
                    }else{
                        d=alldrivers;
                        while(d){

                     //   qDebug()<<"shuchuall"<<d->name;
                        for(int it=0;it<strlen(d->name);it++)
                        {

                         m[it]=*(d->name+it);


                       //   qDebug()<<"d1"<<m[it];
                        }
                        QString driv= QString(QLatin1String(m));
                      //  ui->drivertextBrowser->setText(driv);
                        d=d->next;
                        ui->drivertableWidget_->insertRow(0);
                        QTableWidgetItem *drii = new QTableWidgetItem(driv);



                        ui->drivertableWidget_->setItem(0,0,drii);


                        }
                    }


   // pcap_lookupnet(net_interface,&net_ip,&net_mask,error_content);
   // pcap_handle=pcap_open_live(net_interface,BUFSIZ,1,0,error_content);

   // if(pcap_handle==NULL)
      //  {
       // qDebug()<<"cuowu ";
       // qDebug()<<error_content;

     //  }
   //  qDebug()<<net_interface;
     //db2=new QSqlDatabase();

      db=QSqlDatabase::addDatabase("QSQLITE");
        db.setHostName("lsl-virtual-machine");
        db.setDatabaseName("lsl4.db");
        db.setUserName("root");
        db.setPassword("951264457");
        if(!db.open()){
           QMessageBox::warning(this,tr("失败"),tr("login sql shibai!!"),QMessageBox::Yes);

        }
        else {
             QMessageBox::warning(this,tr("succses"),tr("login sql succses!!"),QMessageBox::Yes);
        }
        QSqlQuery query;
            query.exec("create table packets(id INTEGER PRIMARY KEY autoincrement,packet nvarchar(20),ids int,len int)"); //id自动增加

    stop=true;



    mythreas=new threaders();
    mythreas->start();
   // ipthresders *myipthred;
   // myipthred=new ipthresders();
   // myipthred->start();

   // for(int i=0;i<20;i++){
    connect(mythreas,SIGNAL(Signalpacket(QString,QString,const u_char *,QString)),
            this,SLOT(Packetmsg(QString,QString,const u_char*,QString)));
   // }
    //ui->tableWidget->sortByColumn(0,Qt::AscendingOrder);

   // char *packsss;
   // QString pp="234";
    //int l=5;
    //packsss[0]='\000';
  //  for(int i1=0;i1<256;i1++)
   //  {
     //    qDebug()<<"charmaps"<<charmaps[i1];
    // }

}

void Widget::ip_protocol_packet_callback(QString caplength,const u_char* packet_content,QString name1)
{
    struct ip_header *ip_protocol;  //ip协议变量
    u_int head_length;
    u_int pianyi;
    u_char tos;
    u_int16_t checks;
    QString srip;
    QString dsip;
    QString type;
    sockaddr_in srcina;
    sockaddr_in desina;
    QString namess="未找到地理位置";
    ip_protocol=(struct ip_header*)(packet_content+14);

    checks=ntohs(ip_protocol->head_check);
    head_length=ip_protocol->ip_head_length*4;
    tos=ip_protocol->service_TOS;
    pianyi=ip_protocol->pianyi; 
   srip=inet_ntoa(ip_protocol->ip_sr);
     dsip=inet_ntoa(ip_protocol->ip_des);
      //desina.sin_addr.s_addr = inet_addr(dsip);
     // srcina.sin_addr.s_addr = inet_addr(srip);
   // emit ipdatasr(srip);
    // emit ipdatads(dsip);
    switch (ip_protocol->ip_protlcol) {
    case 6:
         type="TCP";
         //tcp_callback(argument,packet_header,packet_content);
        break;
    case 17:
          type="UDP";
        //udp_callback(argument,packet_header,packet_content);
        break;
    case 1:
          type="ICMP";
    //icmp_callback(argument,packet_header,packet_content);
        break;
    case 2:
         type="IGMP";
        //iGmp_callback(argument,packet_header,packet_content);
        break;
    default:
    type="未知IP协议，待研究";
    break;

    }
    QTableWidgetItem *protocols = new QTableWidgetItem(type);
    QTableWidgetItem *sip = new QTableWidgetItem(srip);
    QTableWidgetItem *dip = new QTableWidgetItem(dsip);
 QTableWidgetItem *ipname = new QTableWidgetItem(name1);
    ui->tableWidget->setItem(0,0,protocols);
    ui->tableWidget->setItem(0,3,sip);
    ui->tableWidget->setItem(0,4,dip);
     ui->tableWidget->setItem(0,6,ipname);


}



void Widget::arp_protocol_packet_callback(QString caplength,const u_char* packet_content,QString name1)
{

    struct arp_header *arp_protocol;  //arp协议变量
     QString type;
    u_short yingjian_type;
    u_short protocol_type;
    u_char yingjian_length;
    u_char protocol_length;
    u_short op_code;
    struct in_addr sr_ip_address;
    struct in_addr ds_ip_address;
    QString srip;
    QString dsip;
    arp_protocol=(struct arp_header*)(packet_content+14);

    yingjian_type=ntohs(arp_protocol->arp_yinjian_type);
    protocol_type=ntohs(arp_protocol->arp_protocol_typa);
    yingjian_length=arp_protocol->arp_yinjian_leneth;
    protocol_length=arp_protocol->arp_protocol_length;
    op_code=ntohs(arp_protocol->arp_op_code);
   // qDebug()<<"arpcode"<<op_code;
     type="ARP";
    switch (op_code) {
    case 1:
       type="ARP";
        break;
    case 2:
         type="ARP";
        break;
    case 3:
         type="RARP";
        break;
    case 4:
         type="RARP";
        break;
    }
    memcpy((void*)&sr_ip_address,(void*)&arp_protocol->arp_s_IP_address,sizeof(struct in_addr));
    srip=inet_ntoa(sr_ip_address);

    memcpy((void*)&ds_ip_address,(void*)&arp_protocol->arp_d_IP_address,sizeof(struct in_addr));
    dsip=inet_ntoa(ds_ip_address);

    QTableWidgetItem *protocols = new QTableWidgetItem(type);
    QTableWidgetItem *sip = new QTableWidgetItem(srip);
    QTableWidgetItem *dip = new QTableWidgetItem(dsip);
     QTableWidgetItem *ipname = new QTableWidgetItem(name1);
    ui->tableWidget->setItem(0,0,protocols);
    ui->tableWidget->setItem(0,3,sip);
    ui->tableWidget->setItem(0,4,dip);
    ui->tableWidget->setItem(0,6,ipname);

}
void Widget::weizhi(QString caplength,const u_char* packet_content)
{
    QString type;
    type="未知协议，待研究";
    QTableWidgetItem *protocols = new QTableWidgetItem(type);
    ui->tableWidget->setItem(0,0,protocols);

}
QString Widget::ips_toQstring(int ip){
    int i=0;
    QString ips;
    QString s;
    while(i<4)
    {
        int a=(ip>>(i*8)&0xff);
       // qDebug()<<"a"<<a;
        s= QString::number(a, 10);
                if(i>0)
                {
                    ips+="."+s;
                }else
                {
                    ips=s;
                }
                i++;
    }
    return s;
}

void Widget::Packetmsg(QString caplength,QString Length,const u_char* pktData,QString names)
{
 packetnumber++;
 QSqlQuery query;
 QString packetadd;
 QString packetadd16;
 query.prepare("INSERT INTO packets(packet,ids,len) VALUES(:packet,:ids,:len)"); //准备执行SQL查询

for(int i=0;i<Length.toInt();i++)
{
 QString t = QString::number(pktData[i]);
 //qDebug()<<"pktDataii"<<i<<pktData[i];
  //qDebug()<<"t"<<i<<t;
 packetadd+=t+"|";
 packetadd16+=QString::number(pktData[i],16);

 }

// qDebug()<<"packetadd"<<packetadd;
  query.bindValue(":packet", packetadd);
  query.bindValue(":ids", packetnumber);
  query.bindValue(":len", Length.toInt());
  bool success=query.exec();
 if(!success)
 {
   QSqlError lastError=query.lastError();
   qDebug()<<lastError.driverText()<<QString(QObject::tr("插入失败"));
 }
   //qDebug()<<"charu";
 /*
   query.exec("SELECT * FROM packets");
 while (query.next())
 {
     int ids = query.value(2).toInt();
     QString packet = query.value(1).toString();
     int lens=query.value(3).toInt();
   //  qDebug()<<"id"<<ids;
    // qDebug()<<"packet"<<packet;
    // qDebug()<<"length"<<lens;
    
 }*/


    QString pnumb=QString::number(packetnumber);
    ui->cutextBrowser_->setText(pnumb);
    QString numberS;
    u_int16_t ethernet_type;
    //QString type;

   // u_char *mac_string;


    struct ether_header *ethernet_protocol;
    ethernet_protocol=(struct ether_header*)pktData;

    QString DesMAC;
    QString SRCMAC;

 SRCMAC=QString("%1%2%3%4%5%6").arg(ethernet_protocol->ether_shost[0]).arg(ethernet_protocol->ether_shost[1])
         .arg(ethernet_protocol->ether_shost[2]).arg(ethernet_protocol->ether_shost[3])
         .arg(ethernet_protocol->ether_shost[4]).arg(ethernet_protocol->ether_shost[5]);

 DesMAC=QString("%1%2%3%4%5%6").arg(ethernet_protocol->ether_dhost[0]).arg(ethernet_protocol->ether_dhost[1])
         .arg(ethernet_protocol->ether_dhost[2]).arg(ethernet_protocol->ether_dhost[3])
         .arg(ethernet_protocol->ether_dhost[4]).arg(ethernet_protocol->ether_dhost[5]);


  QTableWidgetItem *desmacs = new QTableWidgetItem(DesMAC);
  QTableWidgetItem *srcmacs = new QTableWidgetItem(SRCMAC);
  QTableWidgetItem *length = new QTableWidgetItem(caplength);

  ui->tableWidget->insertRow(0);
  ui->tableWidget->setItem(0,1,srcmacs);
  ui->tableWidget->setItem(0,2,desmacs);
 ui->tableWidget->setItem(0,5,length);

  numberS=QString::number(packetnumber);
  ui->numbertextBrowser->setText(numberS);
  ethernet_type=ntohs(ethernet_protocol->ether_type);
    if(ethernet_type==0X0800)
    {
       ip_protocol_packet_callback(caplength,pktData,names);
    }
    else if(ethernet_type==0X0806)
    // else if(ethernet_type==0X0806&&fliters!="UDP"&&fliters!="TCP"&&fliters!="ICMP"&&fliters!="IGMP")
    {

      arp_protocol_packet_callback(caplength,pktData,names);
    }else if(ethernet_type==0X8035)
    {

       arp_protocol_packet_callback(caplength,pktData,names);
    }else
    {
        weizhi(caplength,pktData);
    }

}
void Widget::ARP_Analysis(int caplength,u_char* PacketContens)
{
     QString t;
    for(int u=0;u<caplength;u++)
    {
    t+= QString::number(PacketContens[u],16);
    }
    ui->protocoltextBrowser->clear();
     ui->detailtextBrowser->clear();
     //QString t=QString(QLatin1String(PacketContens));
     ui->protocoltextBrowser->insertPlainText(t);
     struct arp_header *arp_protocol;  //arp协议变量
 //static int arp_replay;
 //static int arp_recieve;

     u_short yingjian_type;
     u_short protocol_type;
     u_char yingjian_length;
     u_char protocol_length;
     u_short op_code;
     u_char *mac_string;
     struct in_addr sr_ip_address;
     struct in_addr ds_ip_address;
     arp_protocol=(struct arp_header*)(PacketContens+14);
     yingjian_type=ntohs(arp_protocol->arp_yinjian_type);
     protocol_type=ntohs(arp_protocol->arp_protocol_typa);
     yingjian_length=arp_protocol->arp_yinjian_leneth;
     protocol_length=arp_protocol->arp_protocol_length;
     op_code=ntohs(arp_protocol->arp_op_code);


    // printf("硬件类型是：%d\n",yingjian_type);
     QString yjdp = QString::number(yingjian_type);
     ui->detailtextBrowser->insertPlainText("硬件类型是：:"+yjdp+"\n");
      //printf("协议类型是：%d\n",protocol_type);
      QString xydp = QString::number(protocol_type);
      ui->detailtextBrowser->insertPlainText("协议类型是：:"+xydp+"\n");
     // printf("硬件地址长度是：%d\n",yingjian_length);
      QString yjdpl = QString::number(yingjian_length);
      ui->detailtextBrowser->insertPlainText("硬件地址长度是：:"+yjdpl+"\n");

     // printf("协议地址长度是：%d\n",yingjian_length);
      QString xydpl = QString::number(yingjian_length);
      ui->detailtextBrowser->insertPlainText("协议地址长度是：:"+xydpl+"\n");
      //printf("操作码是:%d\n",op_code);
     // QString opdd = QString::number(op_code);



      QString DesMAC;
      QString SRCMAC;

   SRCMAC=QString("%1%2%3%4%5%6").arg(arp_protocol->arp_s_ethernet_address[0]).arg(arp_protocol->arp_s_ethernet_address[1])
           .arg(arp_protocol->arp_s_ethernet_address[2]).arg(arp_protocol->arp_s_ethernet_address[3])
           .arg(arp_protocol->arp_s_ethernet_address[4]).arg(arp_protocol->arp_s_ethernet_address[5]);
     ui->detailtextBrowser->insertPlainText("源mac地址是:"+SRCMAC+"\n");

   DesMAC=QString("%1%2%3%4%5%6").arg(arp_protocol->arp_d_ethernet_address[0]).arg(arp_protocol->arp_d_ethernet_address[1])
           .arg(arp_protocol->arp_d_ethernet_address[2]).arg(arp_protocol->arp_d_ethernet_address[3])
           .arg(arp_protocol->arp_d_ethernet_address[4]).arg(arp_protocol->arp_d_ethernet_address[5]);
   ui->detailtextBrowser->insertPlainText("目的mac地址是:"+DesMAC+"\n");

     switch (op_code) {
     case 1:
        // printf("这是ARP查询协议\n");
        ui->detailtextBrowser->insertPlainText("这是ARP查询协议");
         break;
     case 2:
        // printf("这是ARP应答协议\n");
        ui->detailtextBrowser->insertPlainText("这是ARP应答协议");
         break;
     case 3:
        // printf("这是RARP查询协议\n");
        ui->detailtextBrowser->insertPlainText("这是RARP查询协议");
         break;
     case 4:
        // printf("这是RARP应答协议\n");
         ui->detailtextBrowser->insertPlainText("这是RARP应答协议");
         break;
     }
}
void Widget::TCP_Analysis(int caplength,u_char* PacketContens)
{
    QString t;
   for(int u=0;u<caplength;u++)
   {
   t+= QString::number(PacketContens[u],16);
   }
    ui->protocoltextBrowser->clear();
     ui->detailtextBrowser->clear();

   /* for(int i=0;i<caplength;i++)
    {
         qDebug()<<PacketContens[i];
   QString t = QString::number(PacketContens[i]);
   ui->protocoltextBrowser->insertPlainText(t);

    }
*/
    // QString t=QString(QLatin1String(PacketContens));
     ui->protocoltextBrowser->insertPlainText(t);
    struct tcp_header *tcp_protocol;
    u_char flags;
    int header_length;
    u_short source_port;
    u_short destination_port;
    u_short windows;
    u_short urgent_pointer;
    u_int sequence;
    u_int acknowledgement;
    u_int16_t checks;
    tcp_protocol=(struct tcp_header*)(PacketContens+34);
    source_port=ntohs(tcp_protocol->tcp_src_host);
    destination_port=ntohs(tcp_protocol->tcp_des_host);
    sequence=ntohl(tcp_protocol->tcp_id);
    acknowledgement=ntohl(tcp_protocol->tcp_ack);
    header_length=tcp_protocol->tcp_offset*4;
    windows=ntohs(tcp_protocol->tcp_windowssize);
    checks=ntohs(tcp_protocol->tcp_checks);
    urgent_pointer=ntohs(tcp_protocol->tcp_urgent_pointer);
    flags=tcp_protocol->tcp_flags;

    QString sp = QString::number(source_port);
    ui->detailtextBrowser->insertPlainText("源端口号是:"+sp+"\n");
    QString dp = QString::number(destination_port);
    ui->detailtextBrowser->insertPlainText("源端口号是:"+dp+"\n");

    switch (destination_port) {
    case 21:ui->detailtextBrowser->insertPlainText("上层协议是FTP协议\n"); break;
    case 23:ui->detailtextBrowser->insertPlainText("上层协议是TELENT协议\n"); break;
    case 25:ui->detailtextBrowser->insertPlainText("上层协议是SMTP协议\n"); break;
    case 80:ui->detailtextBrowser->insertPlainText("上层协议是HTTP协议\n"); break;
    case 110:ui->detailtextBrowser->insertPlainText("上层协议是P0P3协议\n"); break;
    }
    QString s = QString::number(sequence);
    ui->detailtextBrowser->insertPlainText("序列号是:"+s+"\n");

    QString sc = QString::number(acknowledgement);
    ui->detailtextBrowser->insertPlainText("确认序号是:"+sc+"\n");
    QString cc = QString::number(header_length);
    ui->detailtextBrowser->insertPlainText("首部长度是:"+cc+"\n");
    QString bb = QString::number(tcp_protocol->tcp_reserved);
    ui->detailtextBrowser->insertPlainText("保留位是:"+bb+"\n");
    if(flags&0x80)ui->detailtextBrowser->insertPlainText("标记是:PSH\n");
     if(flags&0x10)ui->detailtextBrowser->insertPlainText("标记是:ACK\n");
      if(flags&0x02)ui->detailtextBrowser->insertPlainText("标记是:SYN\n");
       if(flags&0x20)ui->detailtextBrowser->insertPlainText("标记是:URG\n");
        if(flags&0x01)ui->detailtextBrowser->insertPlainText("标记是:FIN\n");
         if(flags&0x04)ui->detailtextBrowser->insertPlainText("标记是:RST\n");
         QString chu = QString::number(windows);
         ui->detailtextBrowser->insertPlainText("窗口大小是：:"+chu+"\n");
         QString jy = QString::number(checks);
         ui->detailtextBrowser->insertPlainText("检验和是：:"+jy+"\n");
         QString jj = QString::number(urgent_pointer);
         ui->detailtextBrowser->insertPlainText("紧急指针是:"+jj+"\n");


}
void Widget::UDP_Analysis(int caplength,u_char* PacketContens)
{
    QString t;
   for(int u=0;u<caplength;u++)
   {
   t+= QString::number(PacketContens[u],16);
   }
    ui->protocoltextBrowser->clear();
     ui->detailtextBrowser->clear();
    // QString t=QString(QLatin1String(PacketContens));
     ui->protocoltextBrowser->insertPlainText(t);

     struct udp_protocol *udpheader;
     udpheader=(struct udp_protocol*)(PacketContens+34);
       u_int16_t srchost;
       u_int16_t deshost;
       u_int16_t udplength;
       u_int16_t udpcheck;
     srchost=ntohs(udpheader->udp_src_host);
     deshost=ntohs(udpheader->udp_des_host);
     udplength=ntohs(udpheader->udp_length);
     udpcheck=ntohs(udpheader->udp_check);
   //  qDebug()<<"srchost"<<udpheader->udp_src_host;
    // printf("源端口号是:%d\n",srchost);
    // printf("目的端口号是:%d\n",deshost);
     QString sp = QString::number(srchost);
     ui->detailtextBrowser->insertPlainText("源端口号是:"+sp+"\n");
     QString dp = QString::number(deshost);
     ui->detailtextBrowser->insertPlainText("源端口号是:"+dp+"\n");
   //  printf("UDP长度是:%d\n",udplength);
     QString LEN = QString::number(udplength);
     ui->detailtextBrowser->insertPlainText("UDP长度是:"+LEN+"\n");
    // printf("UDP检验和是:%d\n",udpcheck);
     QString CHEK = QString::number(udpcheck);
     ui->detailtextBrowser->insertPlainText("UDP检验和是:"+CHEK+"\n");

     switch(deshost)
     {
     case 53:
    // printf("这是上层协议为域名服务\n");
     ui->detailtextBrowser->insertPlainText("这是上层协议为域名服务\n");
     break;
     case 137:
     //printf("这是上层协议为NETBIOS名字服务\n");
      ui->detailtextBrowser->insertPlainText("这是上层协议为NETBIOS名字服务\n");
     break;
     case 138:
    // printf("这是上层协议为NETBIOS数据报服务\n");
      ui->detailtextBrowser->insertPlainText("这是上层协议为NETBIOS数据报服务\n");

     break;
     case 139:
    // printf("这是上层协议为NETBIOS会话服务\n");
      ui->detailtextBrowser->insertPlainText("这是上层协议为NETBIOS会话服务\n");
     break;
     default:
         ui->detailtextBrowser->insertPlainText("not find\n");
         break;
     }
}

void Widget::ICMP_Analysis(int caplength,u_char* PacketContens)
{
    QString t;
   for(int u=0;u<caplength;u++)
   {
   t+= QString::number(PacketContens[u],16);
   }
    ui->protocoltextBrowser->clear();
     ui->detailtextBrowser->clear();
    // QString t=QString(QLatin1String(PacketContens));
     ui->protocoltextBrowser->insertPlainText(t);
     icmp_le=caplength;
  struct ip_header *ip_protocol;  //ip协议变量

     ip_protocol=(struct ip_header*)(PacketContens+14);
   icmp_srcips=inet_ntoa(ip_protocol->ip_sr);
     struct icmp_huixian_header *icmp_huixian;
     struct icmp_yanma_header *icmp_yanma;
     struct icmp_time_header *icmp_time;
     struct icmp_notarrive *icmp_nothost;
     struct icmp_timeout *icmptimeout;
     struct icmp_chongdingxiang *icmpchong;
     struct icmp_geteway_tonggao *icmptonggao;
     struct icmp_fenpian *icmpfenpian;
     icmp_huixian=(struct icmp_huixian_header*)(PacketContens+14+20);

     u_int16_t chek;
     u_int16_t index;
     u_int16_t id;
     u_int32_t yanma;
     u_int32_t sendtm;
     u_int32_t recievetm;
     u_int32_t chuansongtm;
     char *data;
     u_int16_t livetime;
     u_int16_t weiyong;
     u_int16_t nextMTU;
     QString chekss;
     u_int16_t chek1;
     u_int16_t index1;
     u_int16_t id1;
     // for(int i=0;i<lengths;i++)
     // {
       //   qDebug()<<"charpackets"<<pack[i];
     // }
    // printf("icmp类型是:%d\n",icmp_huixian->icmp_type);
       QString sc1= QString::number(icmp_huixian->icmp_type);
    //   qDebug()<<"type is"<<sc1;
     ui->detailtextBrowser->insertPlainText("icmp类型是:"+sc1+"\n");
    // printf("icmp代码是:%d\n",icmp_huixian->icmp_code);
      QString sc2= QString::number(icmp_huixian->icmp_code);
     //  qDebug()<<"type is"<<sc2;
     ui->detailtextBrowser->insertPlainText("icmp代码是:"+sc2+"\n");
     chek1=ntohs(icmp_huixian->icmp_chek);
     index1=ntohs(icmp_huixian->icmp_index);
     id1=ntohs(icmp_huixian->icmp_ids);
     QString chekss1= QString::number(chek1);
     // qDebug()<<"chekss is"<<chekss1;
     QString scdex1= QString::number(index1);
   //  qDebug()<<"scdex1 is"<<scdex1;
       QString scid1= QString::number(id1);
  //   qDebug()<<"scid1 is"<<scid1;


   if(icmp_huixian->icmp_type==0){
     ui->detailtextBrowser->insertPlainText("这是icmp回显应答\n");
     chek=ntohs(icmp_huixian->icmp_chek);
     index=ntohs(icmp_huixian->icmp_index);
     id=ntohs(icmp_huixian->icmp_ids);
     QString chekss= QString::number(chek);
      ui->detailtextBrowser->insertPlainText("检验和是:"+chekss+"\n");
     QString scdex= QString::number(index);
      ui->detailtextBrowser->insertPlainText("标识符是:"+scdex+"\n");
       QString scid= QString::number(id);
     ui->detailtextBrowser->insertPlainText("序号是:"+scid+"\n");


     }
    if(icmp_huixian->icmp_type==3){
       ui->detailtextBrowser->insertPlainText("icmp目的不可达\n");

     if(icmp_huixian->icmp_code==0){//printf("网络不可达\n");
         ui->detailtextBrowser->insertPlainText("网络不可达\n");}
     if(icmp_huixian->icmp_code==1){//printf("主机不可达\n");
          ui->detailtextBrowser->insertPlainText("主机不可达\n");}
      if(icmp_huixian->icmp_code==2){//printf("协议不可达\n");
          ui->detailtextBrowser->insertPlainText("协议不可达\n");}
      if(icmp_huixian->icmp_code==3){//printf("端口不可达\n");
          ui->detailtextBrowser->insertPlainText("端口不可达\n");
     icmp_nothost=(struct icmp_notarrive*)(PacketContens+34);
     chek=ntohs(icmp_nothost->icmp_chek);


     //printf("检验和是:%d\n",chek);
     QString cheksss= QString::number(chek);
     ui->detailtextBrowser->insertPlainText("检验和是:"+cheksss+"\n");
     //printf("数据最后8个字节为:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",*data,*(data+1),*(data+2),*(data+3),*(data+4),*(data+5),*(data+6),*(data+7));

   QString datas1=QString("%1%2%3%4%5%6%7%8").arg(icmp_nothost->icmp_data_host[0]).arg(icmp_nothost->icmp_data_host[1])
            .arg(icmp_nothost->icmp_data_host[2]).arg(icmp_nothost->icmp_data_host[3])
            .arg(icmp_nothost->icmp_data_host[4]).arg(icmp_nothost->icmp_data_host[5]).arg(icmp_nothost->icmp_data_host[6])
            .arg(icmp_nothost->icmp_data_host[7]);
     ui->detailtextBrowser->insertPlainText("数据最后8个字节为:"+datas1+"\n");
      }
     if(icmp_huixian->icmp_code==4){//printf("需要进行分片但设置了不分片比特DF\n");
         ui->detailtextBrowser->insertPlainText("需要进行分片但设置了不分片比特DF\n");
         icmpfenpian=(struct icmp_fenpian*)(PacketContens+34);
         chek=ntohs(icmpfenpian->icmp_chek);
         weiyong=ntohs(icmpfenpian->icmp_wei);
         nextMTU=ntohs(icmpfenpian->icmp_mtu);
        // data=icmpfenpian->icmp_data;
         //printf("检验和是:%d\n",chek);
          QString chekssss= QString::number(chek);
          ui->detailtextBrowser->insertPlainText("检验和是:"+chekssss+"\n");
        // printf("未用是:%d\n",weiyong);
           QString weiyongs= QString::number(weiyong);
          ui->detailtextBrowser->insertPlainText("未用是:"+weiyongs+"\n");
        // printf("下一站网络的MTU是:%d\n",nextMTU);
          QString nextMTUs= QString::number(nextMTU);
          ui->detailtextBrowser->insertPlainText("下一站网络的MTU是:"+nextMTUs+"\n");
        // printf("数据最后8个字节为:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",*data,*(data+1),*(data+2),*(data+3),*(data+4),*(data+5),*(data+6),*(data+7));
          QString datas2=QString("%1%2%3%4%5%6%7%8").arg(icmpfenpian->icmp_datas[0]).arg(icmpfenpian->icmp_datas[1])
                   .arg(icmpfenpian->icmp_datas[2]).arg(icmpfenpian->icmp_datas[3])
                   .arg(icmpfenpian->icmp_datas[4]).arg(icmpfenpian->icmp_datas[5]).arg(icmpfenpian->icmp_datas[6])
                   .arg(icmpfenpian->icmp_datas[7]);
           ui->detailtextBrowser->insertPlainText("数据最后8个字节为:"+datas2+"\n");
         }
     if(icmp_huixian->icmp_code==5){//printf("源站选路失败\n");
           ui->detailtextBrowser->insertPlainText("源站选路失败\n");}
      if(icmp_huixian->icmp_code==6){//printf("目的网络不认识\n");
           ui->detailtextBrowser->insertPlainText("目的网络不认识\n");}
     if(icmp_huixian->icmp_code==7){//printf("目的主机不认识\n");
           ui->detailtextBrowser->insertPlainText("目的主机不认识\n");}
      if(icmp_huixian->icmp_code==8){//printf("源主机被隔离\n");
           ui->detailtextBrowser->insertPlainText("源主机被隔离\n");}
      if(icmp_huixian->icmp_code==9){//printf("目的网络被强制禁止\n");
           ui->detailtextBrowser->insertPlainText("目的网络被强制禁止\n");}
      if(icmp_huixian->icmp_code==10){//printf("目的主机被强制禁止\n");
           ui->detailtextBrowser->insertPlainText("目的主机被强制禁止\n");}
     if(icmp_huixian->icmp_code==11){//printf("由于服务类型TOS，网络不可达\n");
           ui->detailtextBrowser->insertPlainText("由于服务类型TOS，网络不可达\n");}
      if(icmp_huixian->icmp_code==12){//printf("由于服务类型TOS，主机不可达\n");
           ui->detailtextBrowser->insertPlainText("由于服务类型TOS，主机不可达\n");}
      if(icmp_huixian->icmp_code==13){//printf("由于过滤，通信被强制禁止\n");
           ui->detailtextBrowser->insertPlainText("由于过滤，通信被强制禁止\n");}
    if(icmp_huixian->icmp_code==14){//printf("主机越权\n");
           ui->detailtextBrowser->insertPlainText("主机越权\n");}
     if(icmp_huixian->icmp_code==15){//printf("优先权中止生效\n");
           ui->detailtextBrowser->insertPlainText("优先权中止生效\n");}



     }
    if(icmp_huixian->icmp_type==4){//printf("icmp源站被抑制\n");
           ui->detailtextBrowser->insertPlainText("icmp源站被抑制\n");
         }
     if(icmp_huixian->icmp_type==5){//printf("icmp重定向\n");
         ui->detailtextBrowser->insertPlainText("icmp重定向\n");

    if(icmp_huixian->icmp_code==0){//printf("对网络重定向\n");
          ui->detailtextBrowser->insertPlainText("对网络重定向\n");
         }
     if(icmp_huixian->icmp_code==1){//printf("对主机重定向\n");
          ui->detailtextBrowser->insertPlainText("对主机重定向\n");
     icmpchong=(struct icmp_chongdingxiang*)(PacketContens+34);
     chek=ntohs(icmpchong->icmp_chek);
   //  data=icmpchong->icmp_getaway_ip;
    // printf("应该使用的路由器IP地址:%02x:%02x:%02x:%02x\n",*data,*(data+1),*(data+2),*(data+3));
    // QString datas3=QString("%1%2%3%4").arg(*data,*(data+1),*(data+2),*(data+3));
     QString datas3=QString("%1%2%3%4").arg(icmpchong->icmp_getaway_ip[0]).arg(icmpchong->icmp_getaway_ip[1])
              .arg(icmpchong->icmp_getaway_ip[2]).arg(icmpchong->icmp_getaway_ip[3]);

      ui->detailtextBrowser->insertPlainText("应该使用的路由器IP地址:"+datas3+"\n");
    // data=icmpchong->icmp_data;
    // printf("检验和是:%d\n",chek);
       QString chekssssd= QString::number(chek);
        ui->detailtextBrowser->insertPlainText("检验和是:"+chekssssd+"\n");
     //printf("数据最后8个字节为:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",*data,*(data+1),*(data+2),*(data+3),*(data+4),*(data+5),*(data+6),*(data+7));
        QString datas4=QString("%1%2%3%4%5%6%7%8").arg(icmpchong->icmp_datas[0]).arg(icmpchong->icmp_datas[1])
                 .arg(icmpchong->icmp_datas[2]).arg(icmpchong->icmp_datas[3])
                 .arg(icmpchong->icmp_datas[4]).arg(icmpchong->icmp_datas[5]).arg(icmpchong->icmp_datas[6])
                 .arg(icmpchong->icmp_datas[7]);
      ui->detailtextBrowser->insertPlainText("数据最后8个字节为:"+datas4+"\n");
     }
      if(icmp_huixian->icmp_code==2){//printf("对服务类型和网络重定向\n");
          ui->detailtextBrowser->insertPlainText("对服务类型和网络重定向\n");}
      if(icmp_huixian->icmp_code==3){//printf("对服务类型和主机重定向\n");
         ui->detailtextBrowser->insertPlainText("对服务类型和主机重定向\n");
        }

     }
     if(icmp_huixian->icmp_type==8){//printf("icmp回显请求\n");
         ui->detailtextBrowser->insertPlainText("icmp回显请求\n");
     chek=ntohs(icmp_huixian->icmp_chek);
     index=ntohs(icmp_huixian->icmp_index);
     id=ntohs(icmp_huixian->icmp_ids);
     //printf("检验和是:%d\n",chek);
        QString chekssd= QString::number(chek);
       ui->detailtextBrowser->insertPlainText("检验和是:"+chekssd+"\n");
    // printf("标识符是:%d\n",index);
        QString indexss= QString::number(index);
       ui->detailtextBrowser->insertPlainText("标识符是:"+indexss+"\n");
    // printf("序号是:%d\n",id);
        QString idd= QString::number(id);
      ui->detailtextBrowser->insertPlainText("序号是:"+idd+"\n");
     }
   if(icmp_huixian->icmp_type==9){//printf("icmp路由器通告\n");
         ui->detailtextBrowser->insertPlainText("icmp路由器通告\n");
     icmptonggao=(struct icmp_geteway_tonggao*)(PacketContens+34);
     chek=ntohs(icmptonggao->icmp_chek);
     livetime=ntohs(icmptonggao->icmp_live_time);
    // printf("检验和是:%d\n",chek);
      QString chekssds= QString::number(chek);
      ui->detailtextBrowser->insertPlainText("检验和是:"+chekssds+"\n");
     //printf("地址数是:%d\n",icmptonggao->icmp_dizhishu);
        QString dizhis= QString::number(icmptonggao->icmp_dizhishu);
      ui->detailtextBrowser->insertPlainText("地址数是:"+dizhis+"\n");
     //printf("地址项长度是:%d\n",icmptonggao->icmp_dizhi_length);
        QString lenth= QString::number(icmptonggao->icmp_dizhi_length);
       ui->detailtextBrowser->insertPlainText("地址项长度是:"+lenth+"\n");
     //printf("生存时间是:%d\n",livetime);
        QString livetimes= QString::number(livetime);
      ui->detailtextBrowser->insertPlainText("生存时间是:"+livetimes+"\n");
    // data=icmptonggao->icmp_geteway_address;
     //printf("路由器地址:%02x:%02x:%02x:%02x\n",*data,*(data+1),*(data+2),*(data+3));
     QString datas5=QString("%1%2%3%4").arg(icmptonggao->icmp_geteway_address[0]).arg(icmptonggao->icmp_geteway_address[1])
              .arg(icmptonggao->icmp_geteway_address[2]).arg(icmptonggao->icmp_geteway_address[3]);
      ui->detailtextBrowser->insertPlainText("路由器地址:"+datas5+"\n");
     //data=icmptonggao->icmp_geteway_youxian;

    // printf("优先级为:%02x:%02x:%02x:%02x\n",*data,*(data+1),*(data+2),*(data+3));
     QString datas6=QString("%1%2%3%4").arg(icmptonggao->icmp_geteway_youxian[0]).arg(icmptonggao->icmp_geteway_youxian[1])
              .arg(icmptonggao->icmp_geteway_youxian[2]).arg(icmptonggao->icmp_geteway_youxian[3]);
      ui->detailtextBrowser->insertPlainText("优先级为:"+datas6+"\n");


     }
    if(icmp_huixian->icmp_type==10){//printf("icmp路由器请求\n");
         ui->detailtextBrowser->insertPlainText("icmp路由器请求\n");
       }
     if(icmp_huixian->icmp_type==11){//printf("icmp超时\n");
          ui->detailtextBrowser->insertPlainText("icmp超时\n");

     if(icmp_huixian->icmp_code==0){//printf("传输期间生存时间为0\n");
          ui->detailtextBrowser->insertPlainText("传输期间生存时间为0\n");
     icmptimeout=(struct icmp_timeout*)(PacketContens+34);
     chek=ntohs(icmptimeout->icmp_chek);
    // data=icmptimeout->icmp_data;
    // printf("检验和是:%d\n",chek);
       QString chekssa= QString::number(chek);
      ui->detailtextBrowser->insertPlainText("检验和是:"+chekssa+"\n");
     //printf("数据最后8个字节为:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",*data,*(data+1),*(data+2),*(data+3),*(data+4),*(data+5),*(data+6),*(data+7));
      QString datas7=QString("%1%2%3%4%5%6%7%8").arg(icmptimeout->icmp_datas[0]).arg(icmptimeout->icmp_datas[1])
               .arg(icmptimeout->icmp_datas[2]).arg(icmptimeout->icmp_datas[3])
               .arg(icmptimeout->icmp_datas[4]).arg(icmptimeout->icmp_datas[5]).arg(icmptimeout->icmp_datas[6])
               .arg(icmptimeout->icmp_datas[7]);
      ui->detailtextBrowser->insertPlainText("数据最后8个字节为:"+datas7+"\n");
     }
      if(icmp_huixian->icmp_code==1){//printf("在数据报组装期间生存时间为0\n");
          ui->detailtextBrowser->insertPlainText("在数据报组装期间生存时间为0\n");
     icmptimeout=(struct icmp_timeout*)(PacketContens+34);
     chek=ntohs(icmptimeout->icmp_chek);
    // data=icmptimeout->icmp_data;
     //printf("检验和是:%d\n",chek);
      QString chekswssa= QString::number(chek);
       ui->detailtextBrowser->insertPlainText("检验和是:"+chekswssa+"\n");
     //printf("数据最后8个字节为:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",*data,*(data+1),*(data+2),*(data+3),*(data+4),*(data+5),*(data+6),*(data+7));
       QString datas8=QString("%1%2%3%4%5%6%7%8").arg(icmptimeout->icmp_datas[0]).arg(icmptimeout->icmp_datas[1])
                .arg(icmptimeout->icmp_datas[2]).arg(icmptimeout->icmp_datas[3])
                .arg(icmptimeout->icmp_datas[4]).arg(icmptimeout->icmp_datas[5]).arg(icmptimeout->icmp_datas[6])
                .arg(icmptimeout->icmp_datas[7]);
      ui->detailtextBrowser->insertPlainText("数据最后8个字节为:"+datas8+"\n");
     }

     }
    if(icmp_huixian->icmp_type==12){//printf("icmp参数问题\n");
         ui->detailtextBrowser->insertPlainText("icmp参数问题\n");

       if(icmp_huixian->icmp_code==0){//printf("坏的IP首部\n");
          ui->detailtextBrowser->insertPlainText("坏的IP首部\n");
        }
       if(icmp_huixian->icmp_code==1){//printf("缺少必须的选项\n");
         ui->detailtextBrowser->insertPlainText("缺少必须的选项\n");
        }

    }
     if(icmp_huixian->icmp_type==13){//printf("icmp时间戳请求\n");
          ui->detailtextBrowser->insertPlainText("icmp时间戳请求\n");
     icmp_time=(struct icmp_time_header*)(PacketContens+34);
     chek=ntohs(icmp_time->icmp_chek);
     index=ntohs(icmp_time->icmp_index);
     id=ntohs(icmp_time->icmp_ids);
     sendtm=ntohl(icmp_time->send_time);
     recievetm=ntohl(icmp_time->recieve_time);
     chuansongtm=ntohl(icmp_time->chuansong_time);
    // printf("检验和是:%d\n",chek);
      QString chekqa= QString::number(chek);
     ui->detailtextBrowser->insertPlainText("检验和是:"+chekqa+"\n");
     //printf("标识符是:%d\n",index);
        QString indexq= QString::number(index);
     ui->detailtextBrowser->insertPlainText("标识符是:"+indexq+"\n");
    // printf("序号是:%d\n",id);
      QString idt= QString::number(id);
      ui->detailtextBrowser->insertPlainText("序号是:"+idt+"\n");
    // printf("发起时间戳为：%d\n",sendtm);
      QString sendtms= QString::number(sendtm);
       ui->detailtextBrowser->insertPlainText("发起时间戳为：:"+sendtms+"\n");
     //printf("接收时间戳为：%d\n",recievetm);
        QString recievetmh= QString::number(recievetm);
     ui->detailtextBrowser->insertPlainText("接收时间戳为：:"+recievetmh+"\n");
   //  printf("传送时间戳为：%d\n",chuansongtm);
      QString chuansongtmj= QString::number(chuansongtm);
      ui->detailtextBrowser->insertPlainText("传送时间戳为：:"+chuansongtmj+"\n");
    }
      if(icmp_huixian->icmp_type==14){//printf("icmp时间戳应答\n");
          ui->detailtextBrowser->insertPlainText("icmp时间戳应答\n");
     icmp_time=(struct icmp_time_header*)(PacketContens+34);
     chek=ntohs(icmp_time->icmp_chek);
     index=ntohs(icmp_time->icmp_index);
     id=ntohs(icmp_time->icmp_ids);
     sendtm=ntohl(icmp_time->send_time);
     recievetm=ntohl(icmp_time->recieve_time);
     chuansongtm=ntohl(icmp_time->chuansong_time);
      QString chekqo= QString::number(chek);
     ui->detailtextBrowser->insertPlainText("检验和是:"+chekqo+"\n");
  QString indexr= QString::number(index);
     ui->detailtextBrowser->insertPlainText("标识符是:"+indexr+"\n");
  QString ido= QString::number(id);
      ui->detailtextBrowser->insertPlainText("序号是:"+ido+"\n");
  QString sendtmo= QString::number(sendtm);
       ui->detailtextBrowser->insertPlainText("发起时间戳为：:"+sendtmo+"\n");
  QString recievetmo= QString::number(recievetm);
     ui->detailtextBrowser->insertPlainText("接收时间戳为：:"+recievetmo+"\n");
  QString chuansongtmo= QString::number(chuansongtm);
      ui->detailtextBrowser->insertPlainText("传送时间戳为：:"+chuansongtmo+"\n");
      chuan_times=chuansongtmo;
    }
      if(icmp_huixian->icmp_type==15){//printf("icmp信息请求\n");
            ui->detailtextBrowser->insertPlainText("icmp信息请求\n");}
     if(icmp_huixian->icmp_type==16){//printf("icmp信息应答\n");
         ui->detailtextBrowser->insertPlainText("icmp信息应答\n");}
     if(icmp_huixian->icmp_type==17){//printf("icmp地址掩码请求\n");
         ui->detailtextBrowser->insertPlainText("icmp地址掩码请求\n");
     icmp_yanma=(struct icmp_yanma_header*)(PacketContens+34);
     chek=ntohs(icmp_yanma->icmp_chek);
     index=ntohs(icmp_yanma->icmp_index);
     id=ntohs(icmp_yanma->icmp_ids);
     yanma=ntohl(icmp_yanma->icmp_ziwangyanma);
     QString chekql= QString::number(chek);
     ui->detailtextBrowser->insertPlainText("检验和是:"+chekql+"\n");
QString indexl= QString::number(index);
     ui->detailtextBrowser->insertPlainText("标识符是:"+indexl+"\n");
QString idl= QString::number(id);
      ui->detailtextBrowser->insertPlainText("序号是:"+idl+"\n");
     //printf("32位子网掩码是:%d\n",yanma);
      QString yanmal= QString::number(yanma);
      ui->detailtextBrowser->insertPlainText("32位子网掩码是:"+yanmal+"\n");
  }
      if(icmp_huixian->icmp_type==18){//printf("icmp地址掩码应答\n");
          ui->detailtextBrowser->insertPlainText("icmp地址掩码应答\n");
     icmp_yanma=(struct icmp_yanma_header*)(PacketContens+34);
     chek=ntohs(icmp_yanma->icmp_chek);
     index=ntohs(icmp_yanma->icmp_index);
     id=ntohs(icmp_yanma->icmp_ids);
     yanma=ntohl(icmp_yanma->icmp_ziwangyanma);
     QString chekv= QString::number(chek);
     ui->detailtextBrowser->insertPlainText("检验和是:"+chekv+"\n");
QString indexv= QString::number(index);
     ui->detailtextBrowser->insertPlainText("标识符是:"+indexv+"\n");
QString idv= QString::number(id);
      ui->detailtextBrowser->insertPlainText("序号是:"+idv+"\n");
QString yanmav= QString::number(yanma);
      ui->detailtextBrowser->insertPlainText("32位子网掩码是:"+yanmav+"\n");
   }



}
void Widget::IGMP_Analysis(int caplength,u_char* PacketContens)
{
    QString t;
   for(int u=0;u<caplength;u++)
   {
   t+= QString::number(PacketContens[u],16);
   }
    ui->protocoltextBrowser->clear();
     ui->detailtextBrowser->clear();
     //QString t=QString(QLatin1String(PacketContens));
     ui->protocoltextBrowser->insertPlainText(t);

     struct igmp_header *igmp_protocol;
     int vesion;
     u_int16_t checks;
     u_int address;
     igmp_protocol=(struct igmp_header*)(PacketContens+34);
     vesion=igmp_protocol->igmp_vesion*4;
     checks=ntohs(igmp_protocol->igmp_cheks);
     address=ntohl(igmp_protocol->igmp_group_address);
     //printf("4位版本是:%d\n",vesion);
      QString vesions= QString::number(vesion);
     ui->detailtextBrowser->insertPlainText("4位版本是:"+vesions+"\n");
    // printf("类型是:%d",igmp_protocol->igmp_type);
     QString types= QString::number(igmp_protocol->igmp_type);
      ui->detailtextBrowser->insertPlainText("类型是:"+types+"\n");
     //printf("检验和是:%d\n",checks);
       QString checkss= QString::number(checks);
       ui->detailtextBrowser->insertPlainText("检验和是:"+checkss+"\n");
     //printf("组地址是:%d\n",address);
        QString addressd= QString::number(address);
     ui->detailtextBrowser->insertPlainText("组地址是:"+addressd+"\n");
     if(igmp_protocol->igmp_type==1) ui->detailtextBrowser->insertPlainText("这是多播路由器发来的查询报文\n");
     if(igmp_protocol->igmp_type==2)ui->detailtextBrowser->insertPlainText("这是主机发来的查询报文\n");
}

Widget::~Widget()
{
     QSqlQuery query(db);

    bool succse=query.exec("delete from packets");
     if(succse){
          QMessageBox::warning(this,tr("退出"),tr("成功删除列表！"),QMessageBox::Yes);
     }
     pcap_freealldevs(alldrivers);
    delete ui;
}
void Widget::analyspacket(QString text,QString packetse,int lengths)
{
    int textid;
    u_char pack[1240];
    int packetmap;
    QString pp;
     QStringList pakkee=packetse.split("|");
     for(int i=0;i<pakkee.length();i++)
    {
        // int ii=0;
         pp=pakkee[i];
         packetmap=pp.toInt();
       // qDebug()<<"packetmap"<<packetmap;
         // qDebug()<<"map"<<pakkee[i];
        //for(int a=0;a<pp.length();a++)
        //{
     //     if(i!=0){

             pack[i]=charmaps[packetmap];
            //  ii++;
         // }
        //  qDebug()<<"packzhuan"<<pack[i];
        // }


     }

     struct ip_header *ip_protocol;  //ip协议变量

        ip_protocol=(struct ip_header*)(pack+14);
        annyTTL=QString::number(ip_protocol->TTL);
      //  qDebug()<<"ttls"<<annyTTL;


    if(text=="TCP"){textid=1;}
    if(text=="UDP"){textid=2;}
    if(text=="ARP"){textid=3;}
    if(text=="ICMP"){textid=4;}
    if(text=="IGMP"){textid=5;}
    switch (textid) {
    case 1:
    TCP_Analysis(lengths,pack);

        break;
    case 2:
    UDP_Analysis(lengths,pack);
        break;
    case 3:

    ARP_Analysis(lengths,pack);  break;
    case 4:
    ICMP_Analysis(lengths,pack);
        break;
    case 5:
    IGMP_Analysis(lengths,pack);
        break;
    default:
        break;
    }
}

void Widget::on_tableWidget_cellClicked(int row, int column)
{
    QString str=ui->tableWidget->item(row,column)->text();
   // qDebug()<<"这个是:";
   // qDebug()<<column;
    QList<QTableWidgetItem*>items=ui->tableWidget->selectedItems();

   int count=ui->tableWidget->rowCount();

   int rows=ui->tableWidget->row(items.at(0));//获取选中的行
   rows=packetnumber-rows;
   QTableWidgetItem*item=items.at(0);
   QString texts=item->text();//获取内容
   //qDebug()<<"selectrow"<<rows;
   //qDebug()<<"text"<<texts;
  // QStringList ssmac;
  // ssmac=srcmac.split(".");
   QSqlQuery query;
   //qDebug()<<"zhiding";
    query.exec("SELECT * FROM packets");
   query.seek((rows-1));
   int ids = query.value(2).toInt();
   QString packet = query.value(1).toString();
   int lens=query.value(3).toInt();
  // qDebug()<<"lensanni"<<lens;
   //qDebug()<<"kaishi"<<"packet"<<packet;
  // qDebug()<<"length"<<lens;

    analyspacket(texts,packet,lens);



}

void Widget::on_pushButton_3_clicked()
{
   stop=true;
   ui->pushButton_3->setVisible(false);
    ui->pushButton_2->setVisible(true);
}

void Widget::on_pushButton_2_clicked()
{
    stop=false;
    ui->pushButton_3->setVisible(true);
     ui->pushButton_2->setVisible(false);
}

void Widget::on_flitepushButton_clicked()
{
    QString flite=ui->flitetextEdit->toPlainText();
    qDebug()<<flite;
    fliter=flite;
     qDebug()<<"fliter"<<fliter;
}

void Widget::on_libnetpushButton_clicked()
{
    send=new SendPacket();
    send->show();
}

void Widget::on_pingpushButton_clicked()
{
    Pingset *pingw;
    pingw=new Pingset();
    pingw->show();
}

void Widget::on_driverpushButton_clicked()
{
    QString drs;
    drs=ui->drivertextEdit->toPlainText();
stop=true;
//pcap_close(pcap_handle);
    QByteArray ba=drs.toLatin1();
    char *drq=ba.data();
    net_interface=drq;
    pcap_handle=pcap_open_live(net_interface,BUFSIZ,1,0,error_content);

    if(pcap_handle==NULL)
        {
        QMessageBox::warning(this,tr("错误"),tr("换接口失败"),QMessageBox::Yes);
       qDebug()<<error_content;
         qDebug()<<net_interface;

       }else{
         QMessageBox::warning(this,tr("成功"),tr("换接口成功"),QMessageBox::Yes);
         stop=false;
         ui->driverpushButton->setVisible(false);

    }


}
