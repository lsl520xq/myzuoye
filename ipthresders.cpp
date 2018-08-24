/*#include "ipthresders.h"
#include <QMessageBox>
ipthresders::ipthresders()
{

}
void ipthresders::run(){

   // Widget *widgets;
   //  widgets=new Widget();
    // connect(widgets,SIGNAL(ipdatads(QString)),this,SLOT(showdeips(QString)));
     // connect(widgets,SIGNAL(ipdatasr(QString)),this,SLOT(showsrips(QString)));

}
*/
/*
void ipthresders::showdeips(QString ipdd){
    sockaddr_in ina;
    QString namess;
    QByteArray baty=ipdd.toLatin1();const char *ip1=( const char*)baty.data();
     ina.sin_addr.s_addr = inet_addr(ip1);
    qDebug()<<"intip"<<ina.sin_addr.s_addr;
QSqlQuery query2(db2);
    QString desquery=QString("select * from ip where ip_e='%1'" ).arg(ina.sin_addr.s_addr);
    query2.exec(desquery);
    while (query2.next()) {
         namess=query2.value(2).toString();
    }
    //QTableWidgetItem *names2 = new QTableWidgetItem(namess);
    //ui->tableWidget->setItem(0,7,names2);
}
void ipthresders::showsrips(QString ipss){
    sockaddr_in ina;
     QString namess;
    QByteArray baty=ipss.toLatin1();const char *ip1=( const char*)baty.data();
     ina.sin_addr.s_addr = inet_addr(ip1);
    qDebug()<<"intip"<<ina.sin_addr.s_addr;
    QString srcquery=QString("select * from ip where ip_e='%1'" ).arg(ina.sin_addr.s_addr);
        QSqlQuery query2(db2);
        query2.exec(srcquery);
          while (query2.next()) {
               namess=query2.value(2).toString();
          }

          // QTableWidgetItem *names1 = new QTableWidgetItem(namess);

        // ui->tableWidget->setItem(0,6,names1);
}
*/
