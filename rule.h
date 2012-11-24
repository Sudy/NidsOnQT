#ifndef __RULE_H__
#define __RULE_H__

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>


#include <sqlite3.h>



//预警类型
#define ALARM_LOG    1
#define ALARM_ALERT  2
#define ALARM_PASS   3
#define ALARM_AKILL  4

//协议类型
#define PROANY  0
#define PROTCP  1
#define PROUDP  2
#define PROICMP 3

//任意端口和任意ip
#define PORTANY 0
#define IPANY   0


#define ERROR -1

//规则格式
struct rule{
u_int  ruleID;    //规则编号
u_char alarmtype; //预警类型
u_char protype;   //协议类型
u_int  saddr;     //源地址
u_int  smask;     //源掩码
u_short  sport;   //源端口
u_int  daddr;     //目的地址
u_int  dmask;     //目的掩码
u_short dport;    //目的端口
char*   content;  //包含内容
char*   errmsg;   //预警信息
};


//规则链表
struct ruleNode{
    struct rule data;
    struct ruleNode* next;
};

//全局变量
//struct ruleNode* ruleTCP;
//struct ruleNode* ruleIP;
//sqlite3 *sqlitedb;
//char* dbname;
//char* tablename;

 int initRuleList(char* db,char* table);
 int addNewRule(int argc,char **argv);
 int delRule(int index);
 void closeDB();
#endif
