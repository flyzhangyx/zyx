#ifndef SERVER_H_INCLUDED
#define SERVER_H_INCLUDED
#include <stdio.h>
#include <WinSock2.h>
#include <windows.h>
#include <conio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <direct.h>
#include <time.h>
#include "mysql.h"
#include "stpool.h"
#include "../head/libThreadPool.h"
#define msleep Sleep


#define BUFSIZE 512
//��װ����ɫ��ӡ�ӿ�
#define COLOR_YELLOW 14
#define log_debug(format, args...)      SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), g_default_color);\
                                            printf("[DBG][%s:%d] " #format "\n", __func__,__LINE__,##args)

#define log_info(format, args...)       SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), COLOR_YELLOW);\
                                            printf("[INF][%s:%d] " #format "\n", __func__,__LINE__,##args)

#define log_error(format, args...)       SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), COLOR_RED);\
                                            printf("[ERR][%s:%d] " #format "\n", __func__,__LINE__,##args)
///**************�����û��ڵ�****************
struct user
{
    SOCKET USER_socket;
    SOCKADDR_IN USER_socket_udp;
    //SOCKADDR_IN USER_ADDR;
    char USERID[12];
    int USERKEY_ID;
    char USERPASSWORD[33];
    //char DATE[513];
    char info[100];
    struct user *next;
};
typedef struct user * USER;
 struct contact
{
    char checkcode[18];
    char USERID[12];
    char USERPASSWORD[33];
    char TalktoID[12];
    char info[10];
}contact ;
typedef struct contact * Contact;
 struct message
{
    char checkcode[18];
    char USERID[12];
    char USERPASSWORD[33];
    char TalktoID[12];
    char data[513];
} ;
typedef struct message * Message;
struct OnlineUserHead
{
    char DATE[100];
    char TIME[18];
    char info[100];
    int OnlineUserNum;
    USER  next;
};
///*******************************************
struct OnlineUserHead * onlineUserHead;
struct OnlineUserHead * RegistedUserHead;
struct OnlineUserHead * onlineIotHead;
struct OnlineUserHead * RegistedIotHead;
///*****************Send�ӿ�**********************
typedef struct
{
    char checkcode[18];
    char USERID[12];
    char USERPASSWORD[33];
    char TalktoID[12];
    char REUSERPASSWORD[33];
    char DATA[513];
    char save[100];
} sendbag;
///********�����ӿ�*************
typedef struct
{
    SOCKET remote_socket;
    SOCKADDR_IN ADDR;
    char USERID[12];
    int USERKEY_ID;
    char USERPASSWORD[33];
    char checkcode[18];
    char DATE[100];
    char TalktoID[12];
    char REUSERPASSWORD[33];
    char data[513];
    char info[100];//[0]�Ƿ�ע����¼,N_Y;
} CLN;
typedef struct
{
	OVERLAPPED overlapped;
	WSABUF WSADATABUF;
	char RECBUFFER[sizeof(sendbag) ];
	int BufferLen;
	int OpCode;
}PER_IO_OPERATEION_DATA, *LPPER_IO_OPERATION_DATA, *LPPER_IO_DATA, PER_IO_DATA;

typedef struct
{
    CLN a;
    char filename[32];
    char file_lx[8];
    char file_path[32];
} tcp_send_interface;

///*****************************
///*******��������**************
#ifdef STPOOL
int talk(struct sttask*);
#else
int talk(LPVOID);
#endif // STPOOL
DWORD WINAPI fun(LPVOID);
DWORD WINAPI Check_alive(LPVOID);
DWORD WINAPI UdpPackResolve(LPVOID);
DWORD WINAPI file_tcp_thread(LPVOID);
DWORD WINAPI CreateDailyMsgdbThread();
DWORD WINAPI ServerWorkThread(LPVOID lpParam);
int StartThread(CLN* );
int AcceptClient();
int initServer();
int newOnlineUserOrIotDev(CLN);
int delete_out_user(CLN);
USER FindOnlineUserOrIot(int,char*,int);
int SIGNIN(CLN*);
int AddtoLocal(CLN);
int Check_Id_Pwd(int,CLN);
int UserRegiter(CLN*);
int Register(CLN*,int);
int UserRePwd(CLN );
void RequestIotDevices(CLN*);
void RequestIotEvent(CLN*);
void logwrite(char*);
int IoTtalk(char*,char*,CLN*);
int Stringcut(char* str,int m,int n,char *des);
int BitmapSize(FILE*);
int bitmapfigure(CLN*,FILE*,char*);
int UdpInit(int);
int file_tcp_send(CLN*,FILE*,char*,char*);
int MySqlInit();
USER FindRegisterUserOrIotNode(int,char*,int);
void generateRandString(char*dest,unsigned int len);
int IotRegister(CLN* ,int);
void PrintAllUserAndIotDevice();
int NewUserFriend(CLN,int);
int NewUserIot (CLN,int);
int CmpDate(int year, int month, int day);
int NewUserMsgTableInSQL();
int UserRequestMessage(CLN *,int , char* ,char*,struct tm*);
int UserReqFriendRel(CLN*);
int NewUserMsgStorage(CLN,int);
int IotUpdateStatus(CLN a,int EvtClass,int status);
int UserGetIotData(CLN);
int UserReqIotRel(CLN*);
void CreateDailyMsgdb();
void CopyCln2Sendbag(CLN a,sendbag *Sendbag);
void CopySendbag2Cln(sendbag Sendbag,CLN *a);
unsigned int DJBHash(char* str, unsigned int len);
///*****************************
///***************�����־��**********************
char CHECK[3];///Ӧ�ý���ʱ��½����Ƿ��Ѿ�ע��
char SIGN_IN[3];///��½��
char REGISTER[3];///ע����
char MESSAGE[3];///��Ϣ������
char TALK_TO[3];///ͨ��Ŀ���ַ��
char SIGN_OUT[3];///ע��
char CONTACT[3];///��ϵ����
char REPWD[3];
unsigned int CHECK_HASH;///Ӧ�ý���ʱ��½����Ƿ��Ѿ�ע��
unsigned int SIGN_IN_HASH;///��½��
unsigned int REGISTER_HASH;///ע����
unsigned int MESSAGE_HASH;///��Ϣ������
unsigned int TALK_TO_HASH;///ͨ��Ŀ���ַ��
unsigned int SIGN_OUT_HASH;///ע��
unsigned int CONTACT_HASH;///��ϵ����
unsigned int REPWD_HASH;///����
unsigned int VERUPD_HASH ;///APP����
unsigned int ADDUSER_HASH;///����û�
unsigned int READDU_HASH;///�ظ�����û�
///************************************************
///**********ȫ�ֱ���****************
SOCKET server_sockfd;//TCP���������׽���
SOCKET server_sockfd_udp;//UDP���������׽���
HANDLE CLN_thread[200];
int CLN_num;
int warnfile;
int logflag;
FILE* REGISTERlocal;
FILE* loginfo;
MYSQL mysql, *sock;
#ifdef STPOOL
stpool_t * ThreadPool;
#else
threadPool_t *ThreadPool;
#endif // STPOOL
int g_default_color ;
char app_version[4];
///**********************************
#endif // SERVER_H_INCLUDED
