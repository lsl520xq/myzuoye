#include "udpsend.h"
#include "ui_udpsend.h"

Udpsend::Udpsend(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Udpsend)
{
    ui->setupUi(this);
}

Udpsend::~Udpsend()
{
    delete ui;
}
