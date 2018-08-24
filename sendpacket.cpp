#include "sendpacket.h"
#include "ui_sendpacket.h"
QString selectprotocol;
SendPacket::SendPacket(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::SendPacket)
{

    ui->setupUi(this);
    ui->selectcomboBox->insertItem(0,"ARP");
    ui->selectcomboBox->insertItem(1,"UDP");
    ui->selectcomboBox->insertItem(2,"ICMP");
    //selectprotocol=ui->selectcomboBox->currentText();


}

SendPacket::~SendPacket()
{
    delete ui;
}

void SendPacket::on_selectcomboBox_currentTextChanged(const QString &arg1)
{
    selectprotocol=arg1;
    qDebug()<<"selectprotocol"<<selectprotocol;
}

void SendPacket::on_surepushButton_clicked()
{
    if(selectprotocol=="ARP")
    {
    arps=new Arp();
    arps->show();
    this->close();
    }else if(selectprotocol=="UDP")
    {
       udps=new Udpsend();
       udps->show();
        this->close();
    }else if(selectprotocol=="ICMP")
    {
        icmps=new Icmpsend();
        icmps->show();
        this->close();
    }

}

void SendPacket::on_exitpushButton_clicked()
{
    this->close();
}
