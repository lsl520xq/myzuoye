#include "icmpsend.h"
#include "ui_icmpsend.h"

Icmpsend::Icmpsend(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Icmpsend)
{
    ui->setupUi(this);
}

Icmpsend::~Icmpsend()
{
    delete ui;
}

void Icmpsend::on_sendpushButton_clicked()
{
    QString desip;
    QString srcip;
    QString ip_indexs;
    QString ip_TTLs;
    QString icmp_protocols;
    QString icmp_indexs;
    QString icmp_ids;
    QString driver1;
    desip=ui->desiptextEdit->toPlainText();
    srcip=ui->srciptextEdit->toPlainText();
    ip_indexs=ui->ipindextextEdit->toPlainText();
    ip_TTLs=ui->ttltextEdit->toPlainText();
    icmp_protocols=ui->icmp_protocol_textEdit->toPlainText();
    icmp_indexs=ui->icmp_index_textEdit->toPlainText();
    icmp_ids=ui->icmp_id_textEdit->toPlainText();
    driver1=ui->drivertextEdit->toPlainText();

    int icmppro=icmp_protocols.toInt();
    int icmpindex=icmp_indexs.toInt();
    int icmpid=icmp_ids.toInt();

    int ipindex=ip_indexs.toInt();
    int ipttl=ip_TTLs.toInt();


     QByteArray bag=driver1.toLatin1();

    QByteArray ba=desip.toLatin1();
    char *dip=ba.data();
    char *destination_ip_str; //目的地ip
    destination_ip_str=dip;

    QByteArray bas=srcip.toLatin1();
    char *sip=bas.data();
    char *source_ip_str; //目的地ip
    source_ip_str=sip;

    libnet_t *l = NULL;
       /* libnet句柄 */
       libnet_ptag_t protocol_tag;
       /* 协议标记 */
       u_int8_t *payload_liu_wen_tao = 0;/* 负载 */

       u_short payload_length = 0;

       char *device =bag.data();

       u_long source_ip = 0;

       u_long destination_ip = 0;

       char errbuf[LIBNET_ERRBUF_SIZE];

       int packet_length;
       /* 发送的数据包的长度 */
       l = libnet_init( LIBNET_RAW4, device, errbuf );
       source_ip = libnet_name2addr4(l, source_ip_str, LIBNET_RESOLVE);

       destination_ip = libnet_name2addr4(l, destination_ip_str, LIBNET_RESOLVE);

       protocol_tag = libnet_build_icmpv4_echo(icmppro,0,0,icmpindex,icmpid,NULL,0,l,0);
       protocol_tag = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H + payload_length,0,ipindex,0,ipttl,IPPROTO_ICMP,0,source_ip,destination_ip,payload_liu_wen_tao,payload_length,l,0);
       packet_length = libnet_write(l);

      // printf("发送一个%d字节长度的ICMP回显请求数据包\n", packet_length);
       qDebug()<<"发送一个ICMP回显请求数据包字节长度"<<packet_length;

       libnet_destroy(l);
       /* 销毁libnet */

}

void Icmpsend::on_pushButtonexit_clicked()
{

}
