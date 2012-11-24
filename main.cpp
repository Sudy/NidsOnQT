#include <QtGui/QApplication>
#include "mainwindow.h"
#include "nidsthread.h"

extern "C"{

#include "rule.h"
#include "stdio.h"
}


int main(int argc, char *argv[])
{

    int iResult = initRuleList("nids.db","rule");

    if(0 != iResult){
        fprintf(stderr,"规则链表初始化错误\n");
        return 1;
    }

    QApplication a(argc, argv);
    MainWindow w;
    w.show();

    //开始一个新的线程
    NidsThread* nidsThread = new NidsThread();
    nidsThread->start ();

    return  a.exec();


}
