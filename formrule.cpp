#include "formrule.h"
#include "ui_formrule.h"
#include "util.h"

extern "C"{
#include "rule.h"
#include "stdio.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
}

FormRule::FormRule(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::FormRule)
{

    ui->setupUi(this);
    QStringList strListProto,strListAlarm;
    strListProto<<"ANY"<<"TCP"<<"UDP"<<"ICMP";
    strListAlarm<<"ALL"<<"LOG"<<"ALARM"<<"PASS"<<"KILL";

    Util::setCombox (ui->comboBoxProto,strListProto);
    Util::setCombox (ui->comboBoxAlarm,strListAlarm);

    Util::setCombox (ui->comboBoxProto_2,strListProto);
    Util::setCombox (ui->comboBoxAlarm_2,strListAlarm);

    //table的表头
    QStringList strListTableHead;
    strListTableHead<<"ID"<<"Type"<<"Proto"<<"Src"
                   <<"Dst"<<"Content"<<"ErrMsg";
    //设置表头宽度
    ui->tableRule->setColumnCount (7);
    ui->tableRule->setColumnWidth (0,30);
    ui->tableRule->setColumnWidth (1,60);
    ui->tableRule->setColumnWidth (2,60);
    ui->tableRule->setColumnWidth (3,170);
    ui->tableRule->setColumnWidth (4,170);
    ui->tableRule->setColumnWidth (5,100);
    //ui->tableRule->setColumnWidth (6,120);

    //设置表头
    ui->tableRule->setHorizontalHeaderLabels (strListTableHead);
    //最后一列补全空白
    ui->tableRule->horizontalHeader()->setStretchLastSection(true);

    //frame 默认隐藏
    ui->frame->hide ();
}



FormRule::~FormRule()
{
    delete ui;
}

void FormRule::on_btnAddRule_clicked()
{   //隐藏
    ui->frame->show ();
}


void FormRule::on_btnOK_clicked()
{
    QTableWidget* pTable = ui->tableRule;
    QString strTmp;
    int prototype,alarmtype;//协议类型

    //ip,端口,掩码
    QString strSrcIP,strSrcPort,strSrcMask;
    QString strDstIP,strDstPort,strDstMask;
    QString strContent,strErrMsg;

    unsigned int isrcIP,idstIP;
    //定义两个位置
    int pos1 = 0,pos2 = 0;
    int i = 0;

    //保存存入数据库的参数
    char *argv[11];
    //动态申请空间
    for(i = 0;i < 11;i++)
        argv[i] =  new char[20];


    //插入到开始位置
    ui->tableRule->insertRow (0);

    //预警类型
    strTmp = ui->comboBoxAlarm->currentText ();
    alarmtype = ui->comboBoxAlarm->currentIndex ();
    sprintf(argv[1],"%d",alarmtype);
    pTable->setItem (0,1,new QTableWidgetItem(strTmp));

    //协议类型
    strTmp =ui->comboBoxProto->currentText ();
    prototype = ui->comboBoxProto->currentIndex ();
    sprintf(argv[2],"%d",prototype);
    pTable->setItem (0,2,new QTableWidgetItem(strTmp));

    //源地址，端口，掩码
    strTmp = ui->lineEditSrc->text ();
    pos1 = strTmp.indexOf (":");
    pos2 = strTmp.indexOf ("/");
    //如果存在端口
    if( -1 != pos1){
        //表示ip地址
        strSrcIP = strTmp.left (pos1);
        strSrcPort = strTmp.mid (pos1+1,pos2-pos1-1);
    }else{
        strSrcIP = strTmp.left (pos2);
        strSrcPort = "0";
    }
    strSrcMask =  strTmp.mid (pos2+1,strTmp.length () - pos2);

    inet_aton (strSrcIP.toLocal8Bit ().data (),(struct in_addr*)&isrcIP);
    sprintf(argv[3],"%d",isrcIP);
    sprintf(argv[4],"%s",strSrcPort.toLocal8Bit ().data ());
    sprintf(argv[5],"%s",strSrcMask.toLocal8Bit ().data ());

    pTable->setItem (0,3,new QTableWidgetItem(strTmp));


    //目的地址，端口，掩码
    strTmp =ui->lineEditDst->text ();
    pos1 = strTmp.indexOf (":");
    pos2 = strTmp.indexOf ("/");
    //如果存在端口
    if( -1 != pos1){
        //表示ip地址
        strDstIP = strTmp.left (pos1);
        strDstPort = strTmp.mid (pos1+1,pos2-pos1-1);
    }else{
        strDstIP = strTmp.left (pos2);
        strDstPort = "0";
    }
    strDstMask =  strTmp.mid (pos2+1,strTmp.length () - pos2);

    inet_aton (strDstIP.toAscii ().data (),(struct in_addr*)&idstIP);
    sprintf(argv[6],"%d",idstIP);
    sprintf(argv[7],"%s",strDstPort.toLocal8Bit ().data ());
    sprintf(argv[8],"%s",strDstMask.toLocal8Bit ().data ());
    pTable->setItem (0,4,new QTableWidgetItem(strTmp));

    //content
    strTmp =ui->lineEditContent->text ();
    strContent = strTmp;
    if(strTmp.isEmpty ()){
        sprintf(argv[9],"%s","0");
    }else{
        sprintf(argv[9],strContent.toLocal8Bit ().data ());
    }
    pTable->setItem (0,5,new QTableWidgetItem(strTmp));
    //errmsg
    strTmp = ui->lineEditErrMsg->text ();
    strErrMsg = strTmp;
    if(strTmp.isEmpty ()){
        sprintf(argv[10],"%s","0");
    }else{

        sprintf(argv[10],"%s",strErrMsg.toLocal8Bit ().data ());
    }
    pTable->setItem (0,6,new QTableWidgetItem(strTmp));

    //加入到链表中
    int id = addNewRule (11,argv);
    if(-1 != id)
        pTable->setItem (0,0,new QTableWidgetItem(QString("%1").arg (id)));
    //释放内存
    for(i = 0; i < 11;i++)
        delete argv[i];
}

void FormRule::on_btnCancel_clicked()
{
    ui->frame->hide ();
}

void FormRule::on_comboBoxProto_currentIndexChanged(int index)
{
    int item = ui->comboBoxProto->currentIndex ();
    switch(item){
    case 0:
    case 1:
    case 3:
        //设置为可写
        ui->lineEditContent->setReadOnly (false);
        break;
    case 2:
        //设置为只读
        ui->lineEditContent->setReadOnly (true);
        break;
    default:break;
    }
}

void FormRule::on_comboBoxAlarm_2_currentIndexChanged(int index)
{

    char pSQL[100];

    //删除所有行
    for(int i = 0; i < ui->tableRule->rowCount();i++)
    {
        ui->tableRule->removeRow(0);
    }

    if(index != 0){
        sprintf(pSQL,"SELECT * FROM rule WHERE alarmtype = %d",index);
    }
    //选择所有
    else{
        sprintf(pSQL,"SELECT * FROM rule;");
    }
    Util::executeSQL (pSQL,ui->tableRule,Util::insertTableRule);
}

void FormRule::on_comboBoxProto_2_currentIndexChanged(int index)
{
    char pSQL[100];

    //删除所有行
    for(int i = 0; i < ui->tableRule->rowCount();i++)
    {
        ui->tableRule->removeRow(0);
    }
    if(index != 0){
        sprintf(pSQL,"SELECT * FROM rule WHERE protype = %d",index);
    }else{
        sprintf(pSQL,"SELECT * FROM rule;");
    }
    Util::executeSQL (pSQL,ui->tableRule,Util::insertTableRule);
}

void FormRule::on_btnDelRule_clicked()
{
    //获取当前列
    int curRow = ui->tableRule->currentRow ();
    QTableWidgetItem* qitem =  ui->tableRule->item(curRow,0);
    //获取当前列的索引
    int index = qitem->text().toInt ();
    //从链表中删除
    delRule (index);
    //从列表中删除
    ui->tableRule->removeRow (curRow);
}
