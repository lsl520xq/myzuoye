#include "pingset.h"
#include "ui_pingset.h"
extern QString annyTTL;
extern QString icmp_srcips;
extern int icmp_le;
extern QString chuan_times;

Pingset::Pingset(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Pingset)
{
    ui->setupUi(this);
}

Pingset::~Pingset()
{
    delete ui;

}

void Pingset::on_pingpushButton_clicked()
{
    QString desip;
    QString iploads="0";
    QString icmploads="0";
    bpf_u_int32 net_mask; //子网掩码
    bpf_u_int32 net_ip;

    struct in_addr addr;

     char error_content[PCAP_ERRBUF_SIZE];
    desip=ui->pingtextEdit->toPlainText();
    iploads=ui->IPloadtextEdit->toPlainText();

    QByteArray ba=desip.toLatin1();
    char *dip=ba.data();
    char *destination_ip_str; //目的地ip
    destination_ip_str=dip;
    u_short payload_length;
    u_int32_t icmploadlength;
     // QByteArray bas=srcip.toLatin1();
   // char *sip=bas.data();
    char *source_ip_str; //目的地ip
    //source_ip_str=sip;

    libnet_t *l = NULL;
       /* libnet句柄 */
       libnet_ptag_t protocol_tag;
       /* 协议标记 */
        qDebug()<<"cehng1";
       u_int8_t *loadicmp=0;


       /*for(int y=0;y<icmploads.length();y++)
       {
         loadicmp[y]=icmploads.toInt();//icmp負載
       }
       */
       //QString datas3=QString("%1%2%3%4").arg(icmpchong->icmp_getaway_ip[0]).arg(icmpchong->icmp_getaway_ip[1])
               // .arg(icmpchong->icmp_getaway_ip[2]).arg(icmpchong->icmp_getaway_ip[3]);
qDebug()<<"cehng2";
       if(icmploads.toInt()!=0)
       {
      icmploadlength=icmploads.length();
       }else{
           icmploadlength=0;
       }
       u_int8_t *payload_liu_wen_tao=0;
      /* for(int i=0;i<200;i++)
       {
           payload_liu_wen_tao[i]=i;
           qDebug()<<"payload_liu_wen_tao"<< payload_liu_wen_tao[i];
       }*/
       //= iploads.toInt();/*ip 负载 */
      /* for(int y1=0;y1<iploads.length();y1++)
       {
         payload_liu_wen_tao[y1]=iploads.toInt();//icmp負載
       }*/


        if(iploads.toInt()!=0)
        {
       payload_length=iploads.length();
        }else{
            payload_length=0;
        }
qDebug()<<"cehng3";
       //char *device =bag.data();
 char *device=pcap_lookupdev(error_content);
 qDebug()<<"device"<<device;
 if(!device)
   {
     qDebug()<<"pcap_lookupdev() error"<<error_content;
    // printf("pcap_lookupdev() error: %s\n", error_content);
     //exit(1);
   }
 int ret;
 ret= pcap_lookupnet(device,&net_ip,&net_mask,error_content);
 if(ret == -1)
   {
     //printf("pcap_lookupnet() error: %s\n", error_content);
     qDebug()<<"pcap_lookupdev() error"<<error_content;
     //exit(1);
   }

   addr.s_addr = net_ip;
   source_ip_str = inet_ntoa(addr);
       u_long source_ip = 0;

       u_long destination_ip = 0;

       char errbuf[LIBNET_ERRBUF_SIZE];

       int packet_length;
       /* 发送的数据包的长度 */
       l = libnet_init( LIBNET_RAW4, device, errbuf );
       qDebug()<<"cehng4";
       source_ip = libnet_name2addr4(l, source_ip_str, LIBNET_RESOLVE);

       destination_ip = libnet_name2addr4(l, destination_ip_str, LIBNET_RESOLVE);
qDebug()<<"cehng5";
qDebug()<<"loadicmp"<<loadicmp;
qDebug()<<"icmploadlength"<<icmploadlength;
qDebug()<<"payload_length"<<payload_length;
qDebug()<<"payload_liu_wen_tao"<<payload_liu_wen_tao;
          protocol_tag = libnet_build_icmpv4_echo(ICMP_ECHO,0,0,66,55,loadicmp,icmploadlength,l,0);
       protocol_tag = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H + payload_length,0,11,0,128,IPPROTO_ICMP,0,source_ip,destination_ip,payload_liu_wen_tao,payload_length,l,0);
       qDebug()<<"cehng6";
       packet_length = libnet_write(l);
       qDebug()<<"cehng7";


       qDebug()<<"发送一个ICMP回显请求数据包字节长度"<<packet_length;

       libnet_destroy(l);
      // QString annyTTL;
      // QString icmp_srcips;
      // int icmp_le;
      // QString chuan_times;
      for(int i=0;i<999;i++)
      {
          for(int a=0;a<999;a++)
          {

          }
      }
      qDebug()<<"annyTTL"<<annyTTL;
      qDebug()<<"icmp_srcips"<<icmp_srcips;
      qDebug()<<"icmp_le"<<icmp_le;
      qDebug()<<"chuan_times"<<chuan_times;
      if(icmp_srcips==destination_ip_str)
      {
          ui->pingtextBrowser->insertPlainText("源IP地址："+icmp_srcips+"  ");
          ui->pingtextBrowser->insertPlainText("TTL："+annyTTL);
           ui->pingtextBrowser->insertPlainText("字節數:"+icmp_le);
            ui->pingtextBrowser->insertPlainText("傳輸時間\n："+chuan_times);
      }

}
