#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "rule.h"
//#include "pthread.h"


/**********************全局变量********************/
//规则链表头节点
struct ruleNode* ruleTCP;
struct ruleNode* ruleIP;
sqlite3* sqlitedb;
char* dbname;
char* tablename;

 //pthread_mutex_t mutexTCP = PTHREAD_MUTEX_INITIALIZER;
 //pthread_mutex_t mutexIP = PTHREAD_MUTEX_INITIALIZER;
/************************************************/

/**********************************************************
  创建新的节点，将信息复制到节点中
**********************************************************/
void createNewNode(struct ruleNode* newRule,int arg,char **argv){

    newRule->next = NULL;
    newRule->data.ruleID   = atoi(argv[0]);
    newRule->data.alarmtype = atoi(argv[1]);
    newRule->data.protype =  atoi(argv[2]);
    newRule->data.saddr = atoi(argv[3]);
    newRule->data.smask = atoi(argv[5]);
    newRule->data.sport = atoi(argv[4]);
    newRule->data.daddr = atoi(argv[6]);
    newRule->data.dmask = atoi(argv[8]);
    newRule->data.dport = atoi(argv[7]);

    newRule->data.content = (char*)malloc(strlen(argv[9]) + 1);
    strcpy(newRule->data.content,argv[9]);

    newRule->data.errmsg = (char*)malloc(strlen(argv[10]) + 1);
    strcpy(newRule->data.errmsg,argv[10]);
}


/**********************************************************
  插入到链表中（从数据库读取或者新建的规则)
**********************************************************/
void insertToList(int argc,char **argv){
    struct ruleNode *newRule = (struct ruleNode*)
            malloc (sizeof(struct ruleNode));
    createNewNode(newRule,argc,argv);

    //如果是TCP协议

    if(PROTCP == newRule->data.protype){
        //pthread_mutex_lock (&mutexTCP);
        newRule->next = ruleTCP->next;
        ruleTCP->next = newRule;
        //pthread_mutex_unlock (&mutexTCP);
    }
    //如果是任意协议
    else if(PROANY == newRule->data.protype){
        struct ruleNode *newRule2 = (struct ruleNode*)
                malloc (sizeof(struct ruleNode));
        createNewNode(newRule2,argc,argv);

        //pthread_mutex_lock (&mutexTCP);
        newRule->next = ruleTCP->next;
        ruleTCP->next = newRule;
        //pthread_mutex_unlock (&mutexTCP);

        //pthread_mutex_lock (&mutexIP);
        newRule2->next = ruleIP->next;
        ruleIP->next = newRule2;
        //pthread_mutex_unlock (&mutexIP);
    }else{
        //pthread_mutex_lock (&mutexIP);
        newRule->next = ruleIP->next;
        ruleIP->next = newRule;
        //pthread_mutex_unlock (&mutexIP);
    }
}

//从规则链表中到找到该节点并删除
int findRule(struct ruleNode* pHeader,int index,u_char* protype){

    /*******从列表中删除*****************/

    //保存当前节点和上一个节点
    struct ruleNode* pCurrent = pHeader->next;
    struct ruleNode* pPrevious = pHeader;

    while(NULL != pCurrent)
    {
        //如果找到该规则
        if(index == pCurrent->data.ruleID){
            //保存该协议类型
            protype = &pCurrent->data.protype;
            pPrevious->next = pCurrent->next;
            //释放内存空间
            if(NULL != pCurrent->data.errmsg)
                free(pCurrent->data.errmsg);
            if(NULL != pCurrent->data.content)
                free(pCurrent->data.content);
            free(pCurrent);
            return 1;
        }
        pPrevious = pCurrent;
        pCurrent = pCurrent->next;
    }
    //如果没有找到
    return 0;
}
//删除一条规则
int delRule(int index){

    //保存错误信息
    char *szErrMsg = 0;

    //从数据库中删除
    char pSQL[1024];
    sprintf(pSQL,"DELETE FROM RULE WHERE ruleID = %d;",index);

    //执行语句
    int rc = sqlite3_exec(sqlitedb, pSQL, 0, 0, &szErrMsg);

    if(rc != SQLITE_OK)
    {
        fprintf(stderr,"SQL Error:%s \n", szErrMsg);
        sqlite3_free(szErrMsg);
        return ERROR;
    }
    //如果错误信息不为空，释放空间
    if(NULL != szErrMsg){
        sqlite3_free(szErrMsg);
    }

    //从链表中删除
    u_char protype;
    //加锁
    //pthread_mutex_lock (&mutexTCP);
    int bfind = findRule (ruleTCP,index,&protype);
    //释放锁
    //pthread_mutex_unlock (&mutexTCP);


    //如果找到并且为任意类型则还需要在ruleIP中找
    if(1 == bfind && PROANY == protype ){
        //pthread_mutex_lock (&mutexIP);
        findRule (ruleIP,index,&protype);
        //pthread_mutex_unlock (&mutexIP);
        return 1;
    }//如果没有找到,到ruleIP中找
    //pthread_mutex_lock (&mutexIP);
    findRule (ruleIP,index,&protype);
    //pthread_mutex_unlock (&mutexIP);
    return 1;
}

int getMaxIdInDB(void *param, int argc, char **argv, char **szColName)
{
    //获得最大的ID
    int* maxruleID = (int*)param;
    *maxruleID = atoi (*argv);
    return 0;
}


int addNewRule(int argc,char **argv){

    /*************先将规则插入到数据库中********************/
    //数据库操作
    char pSQL[1024];
    //保存错误信息
    char *szErrMsg = 0;
    char szTmp[200];
    int i = 0;

    sprintf(pSQL,"INSERT INTO %s \
            (alarmtype, protype,saddr,\
             smask,sport,daddr,dmask,dport,\
             content,errmsg)VALUES(",\
                                   tablename);

            //此处从1开始，跳过编号0
            for(i = 1;i < argc-1;i++){

        sprintf(szTmp,"\"%s\",",argv[i]);
        strcat(pSQL,szTmp);
    }
    sprintf(szTmp,"\"%s\");",argv[argc-1]);
    strcat(pSQL,szTmp);
    fprintf(stderr,pSQL);

    // execute sql
    int rc = sqlite3_exec(sqlitedb, pSQL, 0, 0, &szErrMsg);

    if(rc != SQLITE_OK)
    {
        fprintf(stderr,"SQL Error:%s \n", szErrMsg);
        sqlite3_free(szErrMsg);
        return ERROR;
    }

    /************将规则插入到链表中***********************/
    //先找到数据库中最大的ruleID
    sprintf(pSQL,"SELECT MAX(ruleID) FROM %s",tablename);
    int maxruleID;
    rc = sqlite3_exec(sqlitedb, pSQL, getMaxIdInDB, &maxruleID, &szErrMsg);

    if(rc != SQLITE_OK)
    {
        fprintf(stderr,"SQL Error:%s \n", szErrMsg);
        sqlite3_free(szErrMsg);
        return ERROR;
    }

    //拷贝到argv[0]中
    sprintf(argv[0],"%d",maxruleID);

    //将新的规则插入到链表中
    insertToList(argc,argv);
    //如果错误信息不为空，释放空间
    if(NULL != szErrMsg){
        sqlite3_free(szErrMsg);
    }

    return maxruleID;
}

/******************************************************
  选择查询的回调函数
******************************************************/
int selectCallback(void *NotUsed, int argc, char** argv, char **szColName){
    //读取错误
    if(argc < 11)
        return -1;
    insertToList(argc,argv);
    return 0;
}

/******************************************************
  初始化规则列表，通过从数据库中读取数据
******************************************************/
int initRuleList(char* db,char* table){

    ruleIP = (struct ruleNode*)malloc(sizeof(struct ruleNode));
    ruleTCP = (struct ruleNode*)malloc(sizeof(struct ruleNode));

    if(NULL == ruleIP || NULL == ruleTCP)
        return ERROR;

    //保存数据库和数据库表
    dbname = (char*)malloc(strlen(db) + 1);
    strcpy(dbname,db);

    tablename = (char*)malloc(strlen(table) + 1);
    strcpy(tablename,table);

    //保存错误信息
    char *szErrMsg = 0;

    //打开数据库
    int rc = sqlite3_open(dbname, &sqlitedb);
    printf("%s",dbname);
    if(rc)
    {
        fprintf(stderr,"Can't open database\n");
        return ERROR;
    } else {
        printf("Open database successfully\n");
    }

    // prepare our sql statements
    char pSQL[1024];
    sprintf(pSQL,"SELECT * FROM %s;",tablename);

    fprintf(stderr,"%s\n",pSQL);


    // execute sql
    rc = sqlite3_exec(sqlitedb, pSQL, selectCallback, 0, &szErrMsg);


    if(rc != SQLITE_OK)
    {
        fprintf(stderr,"SQL Error:%s \n", szErrMsg);
        sqlite3_free(szErrMsg);
        return ERROR;
    }
    //如果错误信息不为空，释放空间
    if(NULL != szErrMsg){
        sqlite3_free(szErrMsg);
    }
    return 0;
}

void closeDB(){
    if(sqlitedb){
        sqlite3_close(sqlitedb);
    }
    if(dbname){
        free(dbname);
    }
    if(tablename){
        free(tablename);
    }
}
