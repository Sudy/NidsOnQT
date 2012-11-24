#include "util.h"


#ifdef __cplusplus
extern "C"{
#endif

#include "rule.h"
#include "stdio.h"
#include "time.h"
extern sqlite3 *sqlitedb;

#ifdef __cplusplus
}
#endif



Util::Util(){}

void Util::executeSQL (char *pSQL,QTableWidget* pTable, function func){

    char* szErrMsg = 0;
    int nRow = 0,nColumn = 0;
    char **dbResult = 0;

    int ret = sqlite3_get_table(sqlitedb, pSQL, &dbResult, &nRow, &nColumn, &szErrMsg);

    fprintf(stderr,pSQL);

    if(NULL != szErrMsg)
    {
        sqlite3_free_table(dbResult);
        sqlite3_free (szErrMsg);
        return;
    }

    //执行插入列表函数
    (*func)(pTable,nRow,nColumn,dbResult);

    //释放空间
    //    sqlite3_free_table(dbResult);
}


void Util::executeSQL (char *pSQL){

    char* szErrMsg = 0;
    int rc = sqlite3_exec(sqlitedb, pSQL, NULL, NULL, &szErrMsg);

    if(rc != SQLITE_OK)
    {
        //fprintf(stderr,"%s",szErrMsg);
        sqlite3_free(szErrMsg);
        return;
    }
}


void Util::insertTableRule (QTableWidget *pTableWidget, int nRow,int nCol,char **argv){

    //列的索引
    int rowIndex = 0;

    //临时变量
    QString strTmp;

    while(rowIndex < nRow){
        //先插入一列
        pTableWidget->insertRow (rowIndex);

        //ID
        strTmp = QString("%1").arg (argv[(rowIndex + 1)*nCol + 0]);
        pTableWidget->setItem(rowIndex,0,new QTableWidgetItem(strTmp));

        //alarmtype
        switch(atoi(argv[(rowIndex + 1)*nCol + 1])){
        case ALARM_LOG:
            strTmp = "LOG";
            break;
        case ALARM_ALERT:
            strTmp = "ALERT";
            break;
        case ALARM_PASS:
            strTmp = "PASS";
            break;
        case ALARM_AKILL:
            strTmp = "KILL";
            break;
        }
        pTableWidget->setItem (rowIndex,1,new QTableWidgetItem(strTmp));

        //prototype
        switch(atoi(argv[(rowIndex + 1)*nCol  + 2])){
        case PROTCP:
            strTmp = "TCP";
            break;
        case PROUDP:
            strTmp = "UDP";
            break;
        case PROICMP:
            strTmp = "ICMP";
            break;
        case PROANY:
            strTmp = "ANY";
            break;
        }
        pTableWidget->setItem (rowIndex,2,new QTableWidgetItem(strTmp));

        //保存地址
        struct in_addr netaddr;
        //src
        unsigned int ipsrc = atoi(argv[(rowIndex + 1)*nCol  + 3]);
        netaddr.s_addr = ipsrc;
        strTmp = QString("%1:%2/%3").arg (\
                    inet_ntoa (netaddr)).arg (argv[(rowIndex + 1)*nCol  + 4]).arg (argv[(rowIndex + 1)*nCol  + 5]);
        pTableWidget->setItem (rowIndex,3,new QTableWidgetItem(strTmp));
        //dst

        unsigned int ipdst = atoi(argv[(rowIndex + 1)*nCol  + 6]);
        netaddr.s_addr = ipdst;

        strTmp = QString("%1:%2/%3").arg (\
                    inet_ntoa (netaddr)).arg (argv[(rowIndex + 1)*nCol  + 7]).arg (argv[(rowIndex + 1)*nCol  + 8]);
        pTableWidget->setItem (rowIndex,4,new QTableWidgetItem(strTmp));
        //content
        pTableWidget->setItem (rowIndex,5,new QTableWidgetItem(QString(argv[(rowIndex + 1)*nCol  + 9])));
        //errmsg
        pTableWidget->setItem (rowIndex,6,new QTableWidgetItem(QString(argv[(rowIndex + 1)*nCol  + 10])));

        rowIndex ++;
    }
}



void Util::insertTableNids(QTableWidget *pTableWidget, int nRow,int nCol,char **argv){

    int rowIndex = 0;
    QString strTmp;

    while(rowIndex < nRow){
        //先插入一列
        pTableWidget->insertRow(rowIndex);

        //获得时间
        time_t time = atoi(argv[(rowIndex + 1)*nCol  + 1]);
        pTableWidget->setItem(rowIndex,0,new QTableWidgetItem(QString(ctime(&time))));



        //alarmtype
        switch(atoi(argv[(rowIndex + 1)*nCol  + 2])){
        case ALARM_LOG:
            strTmp = "LOG";
            break;
        case ALARM_ALERT:
            strTmp = "ALERT";
            break;
        case ALARM_PASS:
            strTmp = "PASS";
            break;
        case ALARM_AKILL:
            strTmp = "KILL";
            break;
        }
        pTableWidget->setItem (rowIndex,1,new QTableWidgetItem(strTmp));
        //prototype
        switch(atoi(argv[(rowIndex + 1)*nCol  + 3])){
        case PROTCP:
            strTmp = "TCP";
            break;
        case PROUDP:
            strTmp = "UDP";
            break;
        case PROICMP:
            strTmp = "ICMP";
            break;
        case PROANY:
            strTmp = "ANY";
            break;
        }
        pTableWidget->setItem (rowIndex,2,new QTableWidgetItem(strTmp));

        for (int i = 3;i < 6; i++)
            pTableWidget->setItem(rowIndex,i,new QTableWidgetItem(QString(argv[(rowIndex + 1)*nCol + i + 1])));
        rowIndex ++;
    }

}

void Util::setCombox (QComboBox* pCombox,QStringList itemList){
    int count = itemList.count ();
    int i = 0;
    while(i < count){
        pCombox->addItem (itemList.at (i));
        i++;
    }
}
