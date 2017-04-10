#-------------------------------------------------
#
# Project created by QtCreator 2017-04-07T00:31:14
#
#-------------------------------------------------

QT       += core gui printsupport

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = proc_info
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    qcustomplot.cpp

HEADERS  += mainwindow.h \
    qcustomplot.h

FORMS    += mainwindow.ui

DISTFILES += \
    manifest.xml \
    manifest.rc

RC_FILE = manifest.rc


