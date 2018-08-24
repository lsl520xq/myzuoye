/*#ifndef IPTHRESDERS_H
#define IPTHRESDERS_H


#include <QThread>
#include <QDebug>
#include <QSqlDatabase>

#include "widget.h"
class ipthresders : public QThread
{
        Q_OBJECT
public:
    ipthresders();
    void run();

  //  Widget *widgets;

private slots:
    void showdeips(QString ipdd);
    void showsrips(QString ipss);


};

#endif // IPTHRESDERS_H
*/
