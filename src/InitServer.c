#include"../head/SERVER.h"
int initServer()
{
    int scan;
    CLN_num=0;
    logflag=0;
    strcpy(CHECK,"ZY");
    strcpy(SIGN_IN,"SI");//登陆码
    strcpy(REGISTER,"RE");//注册码
    strcpy(MESSAGE,"ME");//信息发送码
    strcpy(TALK_TO,"TA");//通信目标地址码
    strcpy(SIGN_OUT,"SO");//注销登录码
    strcpy(REPWD,"RP");
    ///FIll the Three CHAR full With A ：TA + A = TAA
    time_t t;
    CHECK_HASH = DJBHash("ZYX",3);///应用进入时登陆检测是否已经注册
    printf("ZYX%d\n",CHECK_HASH);
    SIGN_IN_HASH = DJBHash("SIA",3);///登陆码
    printf("SIA%d\n",SIGN_IN_HASH);
    REGISTER_HASH = DJBHash("REA",3);///注册码
    printf("REA%d\n",REGISTER_HASH);
    MESSAGE_HASH = DJBHash("RME",3);///信息发送码
    printf("RME%d\n",MESSAGE_HASH);
    TALK_TO_HASH = DJBHash("TAA",3);///通信目标地址码
    printf("TAA%d\n",TALK_TO_HASH);
    SIGN_OUT_HASH = DJBHash("STO",3);///注销
    printf("STO%d\n",SIGN_OUT_HASH);
    CONTACT_HASH = DJBHash("RCO",3);///联系人码
    printf("RCO%d\n",CONTACT_HASH);
    REPWD_HASH = DJBHash("RPA",3);
    printf("RPA%d\n",REPWD_HASH);
    VERUPD_HASH = DJBHash("UPD",3);
    printf("UPD%d\n",VERUPD_HASH);
    ADDUSER_HASH = DJBHash("ADD",3);
    printf("ADD%d\n",ADDUSER_HASH);
    ADSUSER_HASH = DJBHash("ADS",3);
    printf("ADS%d\n",READDU_HASH);
    HEARTBEAT_HASH = DJBHash("HBA",3);
    printf("RCO%d\n",READDU_HASH);


    ///***********socket初始化***********************
    WSADATA wsaData;
    while(1)
    {
        if(!WSAStartup(MAKEWORD(2,2),&wsaData) )
        {
            printf("SOCKET ESTABLISHED SUCCESS!\n");
            break;
        }
        else
        {
            printf("socket not established! If continue to establish? Yes press 1;No press 0");
            scanf("%d",&scan);
            if(scan==0)
                exit(0);
            else if(scan==1)
                continue;
            else
            {
                printf("Input err! Late exit!");
                exit(0);
            }
        }
    }
    ///*************************************************
    SOCKADDR_IN my_addr; //服务器网络地址结构体
    memset(&my_addr,0,sizeof(my_addr)); //数据初始化--清零
    my_addr.sin_family=AF_INET; //设置为IP通信
    my_addr.sin_addr.s_addr=htonl(INADDR_ANY);//服务器IP地址--允许连接到所有本地地址上
    my_addr.sin_port=htons(3566); //服务器端口号 /*创建服务器端套接字--IPv4协议，面向连接通信，TCP协议*/
    if((server_sockfd=socket(AF_INET,SOCK_STREAM,0))==INVALID_SOCKET)
    {
        perror("socket");    /*将套接字绑定到服务器的网络地址上*/
        return -1;
    }
    if (bind(server_sockfd,(struct sockaddr *)&my_addr,sizeof(struct sockaddr))==SOCKET_ERROR)
    {
        perror("bind");
        return -1;
    }
    MySqlInit();///MySQL INIT



    ///*******在线用户链表头初始化********
    do
    {
        onlineUserHead=(struct OnlineUserHead *)malloc(sizeof(struct OnlineUserHead));
        onlineIotHead=(struct OnlineUserHead *)malloc(sizeof(struct OnlineUserHead));
    }
    while(onlineUserHead==NULL&&onlineIotHead==NULL);
    strcpy(onlineUserHead->DATE,"\0");
    onlineUserHead->OnlineUserNum=0;
    onlineUserHead->next=NULL;
    strcpy(onlineIotHead->DATE,"\0");
    onlineIotHead->OnlineUserNum=0;
    onlineIotHead->next=NULL;
    ///LogFile
    loginfo=fopen("Loginfo.info","a+");
      //获取终端当前默认颜色，用于后续所有打印的默认颜色配置
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbiInfo;
    GetConsoleScreenBufferInfo(h, &csbiInfo);
    g_default_color = csbiInfo.wAttributes;

    do
    {
        RegistedUserHead=(struct OnlineUserHead *)malloc(sizeof(struct OnlineUserHead));///跟Online同样的方式储存
        RegistedIotHead=(struct OnlineUserHead *)malloc(sizeof(struct OnlineUserHead));
    }
    while(RegistedUserHead==NULL&&RegistedIotHead==NULL);
    strcpy(RegistedUserHead->DATE,"\0");
    RegistedUserHead->OnlineUserNum=0;
    RegistedUserHead->next=NULL;
    strcpy(RegistedIotHead->DATE,"\0");
    RegistedIotHead->OnlineUserNum=0;
    RegistedIotHead->next=NULL;
    CLN a;
    memset(&a,0,sizeof(CLN));
    char *head = "SELECT * FROM user";
    char *head_iot = "SELECT * FROM iotnode";
    char query[50] = "";
    MYSQL_RES *res;
    MYSQL_ROW row;
    sprintf(query, "%s", head);
    if (mysql_real_query(&mysql, query, strlen(query)))
    {
        printf("\nFailed to Get UserInfo: %s\n", mysql_error(&mysql));
        return -1;
    }
    res = mysql_store_result(&mysql);
    while ((row = mysql_fetch_row(res)))
    {
        strcpy(a.USERID,row[1]);
        strcpy(a.USERPASSWORD, row[3]);
        a.USERKEY_ID=atoi(row[0]);
        strcpy(a.info,row[4]) ;
        AddtoLocal(a);
    }
    mysql_free_result(res);
    ///...................................................
    memset(query,0,50*sizeof(char));
    sprintf(query, "%s", head_iot);
    MYSQL_RES *res_iot;
    MYSQL_ROW row_iot;
    if (mysql_real_query(&mysql, query, strlen(query)))
    {
        printf("\nFailed to Get IotInfo: %s\n", mysql_error(&mysql));
        return -1;
    }
    res_iot = mysql_store_result(&mysql);
    while ((row_iot = mysql_fetch_row(res_iot)))
    {
        strcpy(a.USERID,row_iot[1]);
        strcpy(a.USERPASSWORD, row_iot[3]);
        a.USERKEY_ID=atoi(row_iot[0]);
        strcpy(a.info,row_iot[4]) ;
        strcpy(a.checkcode,row_iot[2]);
        AddtoLocal(a);
    }
    mysql_free_result(res_iot);
    printf("\nLocal Database IotDevices Get %d\n",RegistedIotHead->OnlineUserNum);
    printf("\nLocal Database Users Get %d\n",RegistedUserHead->OnlineUserNum);
    FILE* updversion=fopen("update","r");
    if(updversion)
    {
        fgets(app_version,4,updversion);
        fclose(updversion);
        app_version[3]='\0';
        printf("APP版本-%s\n",app_version);
    }
    else
    {
        printf("更新文件读取失败!");
        return -1;
    }
    ///*************************************
    return 1;
}
