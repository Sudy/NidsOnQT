#-------------------------------------------------
#
# Project created by QtCreator 2012-11-15T22:02:18
#
#-------------------------------------------------

QT       += core gui

TARGET = TestQT
TEMPLATE = app

LIBS += -lnids -lpcap -lnet -lgthread-2.0 -lsqlite3 -lpthread
SOURCES += main.cpp\
        mainwindow.cpp \
    rule.c \
    ids.c \
    response.c \
    nidsform.cpp \
    util.cpp \
    formrule.cpp \
    nidsthread.cpp

HEADERS  += mainwindow.h \
    protoheader.h \
    rule.h \
    ids.h \
    response.h \
    nidsform.h \
    util.h \
    formrule.h \
    nidsthread.h

FORMS    += mainwindow.ui \
    nidsform.ui \
    formrule.ui
