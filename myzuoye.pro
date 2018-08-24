#-------------------------------------------------
#
# Project created by QtCreator 2016-11-14T14:34:30
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = myzuoye
TEMPLATE = app

QT +=sql
SOURCES += main.cpp\
        widget.cpp \
    threaders.cpp \
    sendpacket.cpp \
    arp.cpp \
    udpsend.cpp \
    icmpsend.cpp \
    ipthresders.cpp \
    pingset.cpp

HEADERS  += widget.h \
    threaders.h \
    sendpacket.h \
    arp.h \
    udpsend.h \
    icmpsend.h \
    ipthresders.h \
    pingset.h

FORMS    += widget.ui \
    sendpacket.ui \
    arp.ui \
    udpsend.ui \
    icmpsend.ui \
    pingset.ui
