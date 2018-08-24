#include "arp.h"
#include "ui_arp.h"

Arp::Arp(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Arp)
{
    ui->setupUi(this);
   // if(desip!=""&&srcip!=""&&srcmac!=""&&desmac!=""&&opcode!="")
   // {


   //}
}

Arp::~Arp()
{
    delete ui;
}

void Arp::on_pushButton_clicked()
{

    QString desip;
    QString srcip;
    QString desmac;
    QString srcmac;
    QString opcode;
    QString driver1;
     desip=ui->desiptextEdit->toPlainText();
     srcip=ui->srciptextEdit->toPlainText();
     desmac=ui->desmactextEdit->toPlainText();
     srcmac=ui->srcmactextEdit->toPlainText();
     opcode=ui->opcodetextEdit->toPlainText();
     driver1=ui->drivertextEdit->toPlainText();
     QByteArray bag=driver1.toLatin1();

     int code;
     code=opcode.toInt();
     //u_char *hardware_destination;
     qDebug()<<"sssssssddd";

     QStringList ddmac;
     ddmac=desmac.split(".");
     for(int i=0;i<6;i++)
     {
         qDebug()<<"split"<<ddmac[i];
     }

     QByteArray baty=ddmac[0].toLatin1();unsigned char *pack1=( unsigned char*)baty.data();
      QByteArray baty1=ddmac[1].toLatin1();unsigned char *pack2=( unsigned char*)baty1.data();
       QByteArray baty2=ddmac[2].toLatin1();unsigned char *pack3=( unsigned char*)baty2.data();
        QByteArray baty3=ddmac[3].toLatin1();unsigned char *pack4=( unsigned char*)baty3.data();
         QByteArray baty4=ddmac[4].toLatin1();unsigned char *pack5=( unsigned char*)baty4.data();
          QByteArray baty5=ddmac[5].toLatin1();unsigned char *pack6=( unsigned char*)baty5.data();
          u_char hardware_destination[6]={*pack1,*pack2,*pack3,*pack4,*pack5,*pack6};
   /*  hardware_destination[0]=*(( unsigned char*)qstrdup(ddmac[0].toLatin1().data));
      hardware_destination[1]=*(( unsigned char*)qstrdup(ddmac[1].toLatin1().constData()));
       hardware_destination[2]=*(( unsigned char*)qstrdup(ddmac[2].toLatin1().constData()));
        hardware_destination[3]=*(( unsigned char*)qstrdup(ddmac[3].toLatin1().constData()));
         hardware_destination[4]=*(( unsigned char*)qstrdup(ddmac[4].toLatin1().constData()));
          hardware_destination[5]=*(( unsigned char*)qstrdup(ddmac[5].toLatin1().constData()));
          for(int i=0;i<6;i++)
          {
              qDebug()<<hardware_destination[i];
          }
  */
     // u_char *hardware_source;
      QStringList ssmac;
      ssmac=srcmac.split(".");
      QByteArray batys=ssmac[0].toLatin1();unsigned char *packs1=( unsigned char*)batys.data();
       QByteArray batys1=ssmac[1].toLatin1();unsigned char *packs2=( unsigned char*)batys1.data();
        QByteArray batys2=ssmac[2].toLatin1();unsigned char *packs3=( unsigned char*)batys2.data();
         QByteArray batys3=ssmac[3].toLatin1();unsigned char *packs4=( unsigned char*)batys3.data();
          QByteArray batys4=ssmac[4].toLatin1();unsigned char *packs5=( unsigned char*)batys4.data();
           QByteArray batys5=ssmac[5].toLatin1();unsigned char *packs6=( unsigned char*)batys5.data();
           u_char hardware_source[6]={*packs1,*packs2,*packs3,*packs4,*packs5,*packs6};
      /*hardware_source[0]=*(( unsigned char*)qstrdup(ssmac[0].toLatin1().constData()));
       hardware_source[1]=*(( unsigned char*)qstrdup(ssmac[1].toLatin1().constData()));
        hardware_source[2]=*(( unsigned char*)qstrdup(ssmac[2].toLatin1().constData()));
         hardware_source[3]=*(( unsigned char*)qstrdup(ssmac[3].toLatin1().constData()));
          hardware_source[4]=*(( unsigned char*)qstrdup(ssmac[4].toLatin1().constData()));
           hardware_source[5]=*(( unsigned char*)qstrdup(ssmac[5].toLatin1().constData()));*/

     //unsigned char* smac=NULL;
   //  smac=( unsigned char*)qstrdup(srcmac.toLatin1().constData());

int packet_size;  //存放数据包长度
 libnet_t *l;  //libnet句柄
 libnet_ptag_t protocol_tag;  //协议块标记
 //char *device="ens33";
  char *device=bag.data();
 char error_information[LIBNET_ERRBUF_SIZE]; //存放错误信息
 QByteArray ba=desip.toLatin1();
 char *dip=ba.data();
 char *destination_ip_str; //目的地ip
 destination_ip_str=dip;
 QByteArray bas=srcip.toLatin1();
 char *sip=bas.data();
  char *source_ip_str;
 source_ip_str=sip;
//源ip
 //u_char hardware_source[6]={0x30,0x10,0xb3,0x3f,0xe0,0x72}; //源mac地址

 u_long destination_ip;  //目的ip地址
 u_long source_ip;    //源ip地址

 l=libnet_init(LIBNET_LINK_ADV,device,error_information); //初始化libnet 链路层接口
// printf("device=%s\n",*device);
 qDebug()<<"device"<<device;

 destination_ip=libnet_name2addr4(l,destination_ip_str,LIBNET_RESOLVE); //把目的ip字符串转换成网络顺序字节
 //printf("destination_ip=%d\n",destination_ip);
 qDebug()<<"destination_ip"<<destination_ip;
 source_ip=libnet_name2addr4(l,source_ip_str,LIBNET_RESOLVE); //转换源ip
 //printf("destination_ip=%d\n",source_ip);
 qDebug()<<"source_ip"<<source_ip;

 protocol_tag=libnet_build_arp(ARPHRD_ETHER,ETHERTYPE_IP,6,4,code,
                               hardware_source,(u_int8_t*)&source_ip,hardware_destination,(u_int8_t*)&destination_ip,
                               NULL,0,l,0); //构造arp应答
// printf("protocol_tag=%d\n",protocol_tag);
 qDebug()<<"protocol_tag"<<protocol_tag;
 protocol_tag=libnet_autobuild_ethernet(hardware_destination,ETHERTYPE_ARP,l);//自动构造以太网头
//  printf("protocol_tag=%d\n",protocol_tag);
 qDebug()<<"protocol_tag"<<protocol_tag;
  packet_size=libnet_write(l);//发送ARP数据包
//  printf("已发送的arp数据包长度是：%d\n",packet_size);
  qDebug()<<"packet_size"<<packet_size;
  libnet_destroy(l);


}

void Arp::on_pushButtonexit_clicked()
{
    this->close();
}
