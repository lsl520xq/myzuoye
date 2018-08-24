#ifndef UDPSEND_H
#define UDPSEND_H

#include <QWidget>

namespace Ui {
class Udpsend;
}

class Udpsend : public QWidget
{
    Q_OBJECT

public:
    explicit Udpsend(QWidget *parent = 0);
    ~Udpsend();

private:
    Ui::Udpsend *ui;
};

#endif // UDPSEND_H
