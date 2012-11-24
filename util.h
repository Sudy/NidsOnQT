#ifndef UTIL_H
#define UTIL_H
#include <sqlite3.h>
#include <QTableWidget>
#include <QComboBox>

typedef void (*function)(QTableWidget *, int,int ,char**);

//struct Args{
//    QTableWidget* pTable;
//    function pFunc;
//};

class Util
{
public:
    Util();
    static void insertTableRule(QTableWidget *pTableWidget, int nRow,int nCol,char **argv);
    static void insertTableNids(QTableWidget* pTableWidget,int nRow,int nCol, char **argv);
    static void executeSQL(char* pSQL,QTableWidget* pTable, function func);
    static void executeSQL (char* pSQL);
    static void setCombox (QComboBox* pCombox,QStringList itemList);
};

#endif // UTIL_H
