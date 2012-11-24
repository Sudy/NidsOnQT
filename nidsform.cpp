#include "nidsform.h"
#include "ui_nidsform.h"
#include "util.h"

extern "C"{
#include "rule.h"
#include "stdio.h"
}

NidsForm::NidsForm(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::NidsForm)
{
    ui->setupUi(this);
    QStringList strListProto,strListAlarm;
    strListProto<<"ANY"<<"TCP"<<"UDP"<<"ICMP";
    strListAlarm<<"ANY"<<"LOG"<<"ALARM"<<"PASS"<<"KILL";

    Util::setCombox (ui->comboBoxProto,strListProto);
    Util::setCombox (ui->comboBoxAlarm,strListAlarm);

    //table的表头
    QStringList strListTableHead;
    strListTableHead<<"ID"<<"Action"<<"Proto"
                   <<"Src"<<"Dst"<<"ErrMsg";
    //设置表头宽度
    ui->tableNids->setColumnCount (6);
    ui->tableNids->setColumnWidth (0,60);
    ui->tableNids->setColumnWidth (1,60);
    ui->tableNids->setColumnWidth (2,120);
    ui->tableNids->setColumnWidth (3,120);
    ui->tableNids->setColumnWidth (4,120);

    //设置表头
    ui->tableNids->setHorizontalHeaderLabels (strListTableHead);
    //最后一列补全空白
    ui->tableNids->horizontalHeader()->setStretchLastSection(true);

}


NidsForm::~NidsForm()
{
    delete ui;
}

void NidsForm::on_comboBoxProto_currentIndexChanged(int index)
{
    char pSQL[1024];

    //删除所有行
    for(int i = 0; i < ui->tableNids->rowCount();i++)
    {
        ui->tableNids->removeRow(0);
    }
    if(index != 0){
        sprintf(pSQL,"SELECT * FROM log WHERE protype = %d",index);
    }
    else{
        sprintf(pSQL,"SELECT * FROM log;");
    }
    Util::executeSQL (pSQL,ui->tableNids,Util::insertTableNids);
}

void NidsForm::on_comboBoxAlarm_currentIndexChanged(int index)
{

    char pSQL[1024];

    //删除所有行
    for(int i = 0; i < ui->tableNids->rowCount();i++)
    {
        ui->tableNids->removeRow(0);
    }
    if(index != 0){
        sprintf(pSQL,"SELECT * FROM log WHERE alarmtype = %d",index);
    }
    else{
        sprintf(pSQL,"SELECT * FROM log;");
    }
    Util::executeSQL (pSQL,ui->tableNids,Util::insertTableNids);
}
