#include"../head/SERVER.h"
#ifdef STPOOL
int talk(struct sttask *ptask)
#else
int talk(LPVOID b)
#endif
{
    int len,signIN=0,creat_check_alive=0;
    #ifdef STPOOL
    if(ptask->task_arg==NULL)
    {
        printf("ERR");
        return 0;
    }
    CLN* a=(CLN*)ptask->task_arg;
    #else
    CLN* a = (CLN*)b;
    #endif
    char IoTdata[30]="";
    char logcat[256]="";
    char Contacta[20];
    char Messagea[20];
    char rec[15]="";
    sendbag RecDataStruct;
    char sendbuf[sizeof(sendbag)]= {0};
    char tag[4],tag1[18]="ZYXX1226";
    memset(tag,0,3);
    memset(&RecDataStruct,0,sizeof(sendbag));
    sleep(1);
    return 0;
    CopyCln2Sendbag(*a,&RecDataStruct);
    SOCKET c=a->remote_socket;
    strncpy(tag,RecDataStruct.checkcode,3);
    memset(logcat,0,100*sizeof(char));
    strcpy(logcat,inet_ntoa(a->ADDR.sin_addr));
    strcat(logcat,"|");
    strcat(logcat,RecDataStruct.checkcode);
    logwrite(logcat);
    int isRedo=0;
    ///**********************验证是否为合法用户***************************
    if(!strcmp(tag,"ZYX")&&a->info[1]!='Y')
    {
        if(!strcmp(tag1,a->checkcode))
        {
            printf("\nNOMAL CLIENT:|%s\n",inet_ntoa(a->ADDR.sin_addr));
            a->info[1]='Y';
            return 1;
        }
        else
        {
            printf("\nOLD VERSION CLIENT:|%s\n",inet_ntoa(a->ADDR.sin_addr));
            memset(&RecDataStruct,0,sizeof(sendbag));
            memset(sendbuf,0,sizeof(sendbag));
            strcpy(RecDataStruct.checkcode,"UPD");
            strcpy(RecDataStruct.DATA,app_version);
            RecDataStruct.save[99]='\n';
            memcpy(sendbuf,&RecDataStruct,sizeof(RecDataStruct));
            len=send(c,sendbuf,sizeof(sendbag),0);
            return 1;
        }
    }
    if(a->info[1]!='Y')
    {
        printf("\nIllegal CLIENT:|%s\n",inet_ntoa(a->ADDR.sin_addr));
        closesocket(c);
        //printf("Free\n");
        free(a);
        return 0;
    }
    signIN = (a->info[0]=='Y');//whether User had Signed in

    ///************************循环接受用户请求******************************

    if(signIN&&a->info[0]!='N'&&!creat_check_alive)
    {
        creat_check_alive=1;
        //CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)Check_alive,a,0,NULL);
    }

    if(!strcmp(tag,REGISTER))
    {
//                    strcpy(a->USERID,RecDataStruct.USERID);
//                    strcpy(a->USERPASSWORD,RecDataStruct.USERPASSWORD);
        if (Register(a,0)==1)
        {
            printf("\n注册成功\n");
            memset(&RecDataStruct,0,sizeof(sendbag));
            memset(sendbuf,0,sizeof(sendbag));
            strcpy(RecDataStruct.checkcode,"RE");
            RecDataStruct.save[99]='\n';
            memcpy(sendbuf,&RecDataStruct,sizeof(RecDataStruct));
            len=send(c,sendbuf,sizeof(RecDataStruct),0);
            if(len==SOCKET_ERROR||len==0)
            {
                printf("\n连接%I64d退出\n",c);
                closesocket(c);
                return 0;
            }
        }
        else
        {
            printf("\n注册失败\n");
            memset(&RecDataStruct,0,sizeof(sendbag));
            memset(sendbuf,0,sizeof(sendbag));
            strcpy(RecDataStruct.checkcode,"Re");
            RecDataStruct.save[99]='\n';
            memcpy(sendbuf,&RecDataStruct,sizeof(RecDataStruct));
            len=send(c,sendbuf,sizeof(sendbag),0);
            if(len==SOCKET_ERROR||len==0)
            {
                printf("\n连接%I64d退出\n",c);
                closesocket(c);
                return 0;
            }
        }
    }
    ///****************************登录请求***********************************
    else if(!strcmp(tag,SIGN_IN))
    {
        printf("\n%s/%s/\n",a->USERID,a->USERPASSWORD);
        if (SIGNIN(a)==1)
        {
            printf("\n登陆成功\n");
            signIN=1;
            a->info[0]='Y';
            memset(&RecDataStruct,0,sizeof(sendbag));
            memset(sendbuf,0,sizeof(sendbag));
            strcpy(RecDataStruct.checkcode,SIGN_IN);
            RecDataStruct.save[99]='\n';
            memcpy(sendbuf,&RecDataStruct,sizeof(RecDataStruct));
            len=send(c,sendbuf,sizeof(sendbag),0);
            if(len==SOCKET_ERROR||len==0)
            {
                printf("\n连接%I64d退出\n",c);
                closesocket(c);
                delete_out_user(*a);
                return 0;
            }
            //
        }
        else
        {
            printf("\n登录失败\n");
            memset(&RecDataStruct,0,sizeof(sendbag));
            memset(sendbuf,0,sizeof(sendbag));
            strcpy(RecDataStruct.checkcode,"Si");
            RecDataStruct.save[99]='\n';
            memcpy(sendbuf,&RecDataStruct,sizeof(RecDataStruct));
            len=send(c,sendbuf,sizeof(sendbag),0);
            if(len==SOCKET_ERROR||len==0)
            {
                printf("\n连接%I64d退出\n",c);
                closesocket(c);
                return 0;
            }
        }
    }
    ///****************************************************
    else if(!strcmp(tag,"RCO"))
    {
        UserReqFriendRel(a);
        UserReqIotRel(a);
        Sleep(1000);
    }
    else if(!strcmp(tag,"UPD"))
    {
        memset(&RecDataStruct,0,sizeof(sendbag));
        memset(sendbuf,0,sizeof(sendbag));
        strcpy(RecDataStruct.checkcode,"UPD");
        strcpy(RecDataStruct.DATA,app_version);
        RecDataStruct.save[99]='\n';
        memcpy(sendbuf,&RecDataStruct,sizeof(RecDataStruct));
        len=send(c,sendbuf,sizeof(sendbag),0);
    }
    else if(!strcmp(tag,"RME"))
    {
        /**REQUEST MESSAGE**/;
    }
    ///****************************************************
    else if(!strcmp(tag,REPWD))
    {
        if (UserRePwd(*a)==1)
        {
            printf("\n改密成功\n");
            memset(&RecDataStruct,0,sizeof(sendbag));
            memset(sendbuf,0,sizeof(sendbag));
            strcpy(RecDataStruct.checkcode,"RP");
            RecDataStruct.save[99]='\n';
            memcpy(sendbuf,&RecDataStruct,sizeof(RecDataStruct));
            len=send(c,sendbuf,sizeof(RecDataStruct),0);
            if(len==SOCKET_ERROR||len==0)
            {
                printf("\n连接%I64d退出\n",c);
                closesocket(c);
                free(a);
                return 0;
            }
        }
        else
        {
            printf("\n改密失败\n");
            memset(&RecDataStruct,0,sizeof(sendbag));
            memset(sendbuf,0,sizeof(sendbag));
            strcpy(RecDataStruct.checkcode,"Rp");
            RecDataStruct.save[99]='\n';
            memcpy(sendbuf,&RecDataStruct,sizeof(RecDataStruct));
            len=send(c,sendbuf,sizeof(sendbag),0);
            if(len==SOCKET_ERROR||len==0)
            {
                printf("\n连接%I64d退出\n",c);
                closesocket(c);
                free(a);
                return 0;
            }
        }
    }
    ///*****************************讨论to******************************
    else if(!strcmp(tag,"TAI")&&signIN)
    {
        if(Check_Id_Pwd(0,*a)!=-1)
        {
            USER talktouser=FindOnlineUserOrIot(0,RecDataStruct.TalktoID,0);
            if(talktouser==NULL)
            {
                memset(&RecDataStruct,0,sizeof(sendbag));
                memset(sendbuf,0,sizeof(sendbag));
                strcpy(RecDataStruct.checkcode,"TNI");//TA but not online
                RecDataStruct.save[99]='\n';
                memcpy(sendbuf,&RecDataStruct,sizeof(sendbag));
                len=send(c,sendbuf,sizeof(sendbag),0);
                if(len==SOCKET_ERROR||len==0)
                {
                    printf("\n连接%I64d退出\n",c);
                    closesocket(c);
                    delete_out_user(*a);
                    free(a);
                    return 0;
                }
            }
            else
            {
                //strcpy(talktouser.info,RecDataStruct.TalktoID);
                ///******如果是对物联设备CD=TA123457///******************************************************
                strcpy(IoTdata,"CMD");
                //strncat(IoTdata,a->USERID,11);
                strncat(IoTdata,RecDataStruct.DATA,26);
                //printf("%s",RecDataStruct.DATA);
                /*memcpy(sendbuf,&RecDataStruct,sizeof(RecDataStruct));*/
                len=send(talktouser->USER_socket,IoTdata,30*sizeof(char),0);
                // free(sendbuf);

                if(len==SOCKET_ERROR||len==0)
                {
                    printf("\n连接%I64d退出\n",c);
                    closesocket(talktouser->USER_socket);
                    return 0;
                }
                //memset(&RecDataStruct,0,sizeof(sendbag));
                memset(sendbuf,0,sizeof(sendbag));
                strcpy(RecDataStruct.checkcode,"TAi");
                strcpy(RecDataStruct.DATA,talktouser->info);
                RecDataStruct.save[99]='\n';
                memcpy(sendbuf,&RecDataStruct,sizeof(RecDataStruct));
                /*len=send(c,sendbuf,sizeof(sendbag),0);
                if(len==SOCKET_ERROR||len==0)
                {
                    printf("\n连接%I64d退出\n",c);
                    closesocket(c);
                    delete_out_user(*a);
                    return 0;
                }*/
            }
        }
    }
    else if(!strcmp(tag,TALK_TO)&&signIN)
    {
        if(Check_Id_Pwd(0,*a)!=-1)
        {
            USER talktouser=FindOnlineUserOrIot(0,RecDataStruct.TalktoID,0);
            if(talktouser==NULL)
            {
                USER find = FindRegisterUserOrIotNode(0,a->TalktoID,0);
                if(find==NULL)
                {
                    return 0;
                }
                NewUserMsgStorage(*a,find->USERKEY_ID);
                memset(&RecDataStruct,0,sizeof(sendbag));
                memset(sendbuf,0,sizeof(sendbag));
                strcpy(RecDataStruct.checkcode,"TAN");//TA but not online
                RecDataStruct.save[99]='\n';
                memcpy(sendbuf,&RecDataStruct,sizeof(sendbag));
                len=send(c,sendbuf,sizeof(sendbag),0);
                if(len==SOCKET_ERROR||len==0)
                {
                    printf("\n连接%I64d退出\n",c);
                    closesocket(c);
                    delete_out_user(*a);
                    free(a);
                    return 0;
                }
            }
            else
            {
                memset(sendbuf,0,sizeof(sendbag));
                strcpy(RecDataStruct.checkcode,"TAT");
                RecDataStruct.save[99]='\n';
                char temp[12]= {0};
                strcpy(temp,RecDataStruct.USERID);
                strcpy(RecDataStruct.USERID,RecDataStruct.TalktoID);
                strcpy(RecDataStruct.TalktoID,temp);
                memcpy(sendbuf,&RecDataStruct,sizeof(RecDataStruct));
                len=send(talktouser->USER_socket,sendbuf,sizeof(sendbag),0);
                if(len==SOCKET_ERROR||len==0)
                {
                    printf("\n连接%I64d退出\n",c);
                    closesocket(talktouser->USER_socket);
                    CLN d;
                    strcpy(d.USERID,a->TalktoID);
                    delete_out_user(d);
                }
                USER find = FindRegisterUserOrIotNode(0,a->TalktoID,0);
                if(find==NULL)
                {
                    return 0;
                }
                NewUserMsgStorage(*a,find->USERKEY_ID);
                memset(&RecDataStruct,0,sizeof(sendbag));
                memset(sendbuf,0,sizeof(sendbag));
                strcpy(RecDataStruct.checkcode,"TAS");
                strcpy(RecDataStruct.TalktoID,a->TalktoID);
                strcpy(RecDataStruct.USERID,a->USERID);
                RecDataStruct.save[99]='\n';
                memcpy(sendbuf,&RecDataStruct,sizeof(RecDataStruct));
                len=send(c,sendbuf,sizeof(sendbag),0);
                if(len==SOCKET_ERROR||len==0)
                {
                    printf("\n连接%I64d退出\n",c);
                    closesocket(c);
                    delete_out_user(*a);
                    free(a);
                    return 0;
                }
            }
        }
        else
        {
            printf("用户%s不存在",RecDataStruct.TalktoID);
            memset(&RecDataStruct,0,sizeof(sendbag));
            memset(sendbuf,0,sizeof(sendbag));
            strcpy(RecDataStruct.checkcode,"Taa");//TA but not online
            RecDataStruct.save[99]='\n';
            memcpy(sendbuf,&RecDataStruct,sizeof(RecDataStruct));
            len=send(c,sendbuf,sizeof(sendbag),0);
            if(len==SOCKET_ERROR||len==0)
            {
                printf("\n连接%I64d退出\n",c);
                closesocket(c);
                delete_out_user(*a);
                free(a);
                return 0;
            }
        }
    }







    //\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\//
    else if(!strcmp(tag,"ADD")&&signIN)
    {
        CLN d;
        char IoTdevice[5]="";
        int F=0;
        strcpy(d.USERID,RecDataStruct.TalktoID);
        if(Check_Id_Pwd(1,d)!=-1)
        {
            strncpy(IoTdevice,RecDataStruct.checkcode,4);
            IoTdevice[4]='\0';
            if(!strcmp(IoTdevice,"ADDI"))
            {
                F=1;
            }
            USER talktouser=FindOnlineUserOrIot(0,RecDataStruct.TalktoID,0);
            if(talktouser==NULL&&F!=1)
            {
                Message mes=(Message)malloc(sizeof(struct message));
                memset(mes,0,sizeof(contact));
                memset(mes,0,sizeof(contact));
                strcpy(mes->checkcode,"NCA");
                strcpy(mes->TalktoID,a->USERID);
                strcpy(mes->USERID,RecDataStruct.TalktoID);
                strcpy(mes->data,RecDataStruct.DATA);
                printf("用户%s不在线ADD",RecDataStruct.TalktoID);
                char talkto[30]= {'0'};
                strcpy(talkto,RecDataStruct.TalktoID);
                strcat(talkto,"/");
                strcat(talkto,RecDataStruct.TalktoID);
                strcat(talkto,"ME");
                memset(&RecDataStruct,0,sizeof(sendbag));
                memset(sendbuf,0,sizeof(sendbag));
                strcpy(RecDataStruct.checkcode,"ADN");
                //TA but not online
                strcpy(RecDataStruct.TalktoID,a->TalktoID);
                strcpy(RecDataStruct.USERID,a->USERID);
                RecDataStruct.save[99]='\n';
                memcpy(sendbuf,&RecDataStruct,sizeof(RecDataStruct));
                FILE* ss=fopen(talkto,"a+");///**********dakai
                fwrite(mes,sizeof(struct message),1,ss);
                fflush(ss);
                fclose(ss);
                free(mes);
                len=send(c,sendbuf,sizeof(sendbag),0);
                if(len==SOCKET_ERROR||len==0)
                {
                    printf("\n连接%I64d退出\n",c);
                    closesocket(c);
                    delete_out_user(*a);
                    return 0;
                }
            }
            else if(talktouser!=NULL&&F!=1)
            {

                //memset(&RecDataStruct,0,sizeof(sendbag));
                memset(sendbuf,0,sizeof(sendbag));
                strcpy(RecDataStruct.checkcode,"ADT");
                RecDataStruct.save[99]='\n';
                char temp[12]= {0};
                strcpy(temp,RecDataStruct.USERID);
                strcpy(RecDataStruct.USERID,RecDataStruct.TalktoID);
                strcpy(RecDataStruct.TalktoID,temp);
                RecDataStruct.save[99]='\n';
                memcpy(sendbuf,&RecDataStruct,sizeof(RecDataStruct));
                len=send(talktouser->USER_socket,sendbuf,sizeof(sendbag),0);
                if(len==SOCKET_ERROR||len==0)
                {
                    printf("\n连接%I64d退出\n",c);
                    closesocket(talktouser->USER_socket);
                    delete_out_user(d);
                    isRedo=1;
                    strcpy(temp,RecDataStruct.USERID);
                    strcpy(RecDataStruct.USERID,RecDataStruct.TalktoID);
                    strcpy(RecDataStruct.TalktoID,temp);
                }
                memset(&RecDataStruct,0,sizeof(sendbag));
                memset(sendbuf,0,sizeof(sendbag));
                strcpy(RecDataStruct.TalktoID,a->TalktoID);
                strcpy(RecDataStruct.USERID,a->USERID);
                strcpy(RecDataStruct.checkcode,"ADD");
                RecDataStruct.save[99]='\n';
                memcpy(sendbuf,&RecDataStruct,sizeof(RecDataStruct));
                len=send(c,sendbuf,sizeof(sendbag),0);
                if(len==SOCKET_ERROR||len==0)
                {
                    printf("\n连接%I64d退出\n",c);
                    closesocket(c);
                    delete_out_user(*a);
                    return 0;
                }
                ///********************

            }
            else if(F==1&&talktouser!=NULL)
            {
                char IoTcommand[30]="";
                strcpy(IoTcommand,"ADD");
                strncat(IoTcommand,a->USERID,20);
                len=send(talktouser->USER_socket,IoTcommand,30*sizeof(char),0);
                // free(sendbuf);
                if(len==SOCKET_ERROR||len==0)
                {
                    printf("\n连接%I64d退出\n",c);
                    closesocket(talktouser->USER_socket);
                    return 0;
                }
            }
        }
        else
        {
            printf("用户%s不存在ADD",RecDataStruct.TalktoID);
            //memset(&RecDataStruct,0,sizeof(sendbag));
            memset(sendbuf,0,sizeof(sendbag));
            strcpy(RecDataStruct.checkcode,"Add");//TA but not online
            RecDataStruct.save[99]='\n';
            memcpy(sendbuf,&RecDataStruct,sizeof(RecDataStruct));
            len=send(c,sendbuf,sizeof(sendbag),0);
            // free(sendbuf);
            if(len==SOCKET_ERROR||len==0)
            {
                printf("\n连接%I64d退出\n",c);
                closesocket(c);
                delete_out_user(*a);
                return 0;
            }
        }
    }
    ///*******************************************
    else if(!strcmp(tag,"ADS"))///****only reply****
    {

        Contact mes=(Contact)malloc(sizeof(struct contact));
        memset(mes,0,sizeof(contact));
        memset(sendbuf,0,sizeof(sendbag));
        strcpy(mes->checkcode,"RCO");
        strcpy(mes->TalktoID,RecDataStruct.TalktoID);
        strcpy(mes->USERID,RecDataStruct.USERID);
        RecDataStruct.save[99]='\n';
        memset(mes,0,sizeof(contact));
        strcpy(mes->checkcode,"RCO");
        strcpy(mes->TalktoID,RecDataStruct.USERID);
        strcpy(mes->USERID,RecDataStruct.TalktoID);
        ///**********dakai

        char talkto[30]= {'0'};
        strcpy(talkto,RecDataStruct.TalktoID);
        strcat(talkto,"/");
        strcat(talkto,RecDataStruct.TalktoID);
        strcat(talkto,"CO");
        FILE* ss=fopen(talkto,"a+");///**********dakai
        fwrite(mes,sizeof(struct contact),1,ss);
        fflush(ss);
        fclose(ss);
        strcpy(RecDataStruct.checkcode,"ADS");
        RecDataStruct.save[99]='\n';
        memcpy(sendbuf,&RecDataStruct,sizeof(RecDataStruct));
        len=send(c,sendbuf,sizeof(sendbag),0);
        if(len==SOCKET_ERROR||len==0)
        {
            printf("\n连接%I64d退出\n",c);
            closesocket(c);
            delete_out_user(*a);
            return 0;
        }
    }
    ///*********************************************
    else if(!strcmp(tag,"HB"))
    {
        memset(&RecDataStruct,0,sizeof(sendbag));
        memset(sendbuf,0,sizeof(sendbag));
        strcpy(RecDataStruct.checkcode,"HB");
        RecDataStruct.save[99]='\n';
        memcpy(sendbuf,&RecDataStruct,sizeof(RecDataStruct));
        len=send(c,sendbuf,sizeof(sendbag),0);
        // free(sendbuf);
        if(len==SOCKET_ERROR||len==0)
        {
            printf("\n连接%I64d退出\n",c);
            closesocket(c);
            return 0;
        }
    }
    else if(!strcmp(tag,"STO"))
    {
        memset(&RecDataStruct,0,sizeof(sendbag));
        memset(sendbuf,0,sizeof(sendbag));
        strcpy(RecDataStruct.checkcode,"STO");
        RecDataStruct.save[99]='\n';
        memcpy(sendbuf,&RecDataStruct,sizeof(RecDataStruct));
        len=send(a->remote_socket,sendbuf,sizeof(sendbag),0);
        if(len==SOCKET_ERROR||len==0)
        {
            printf("\n连接%I64d退出\n",c);
            closesocket(c);
            delete_out_user(*a);
            return 0;
        }
        delete_out_user(*a);
        printf("\n%s\n",RecDataStruct.checkcode);
        a->info[0]='N';
        creat_check_alive=0;
    }
///***************************************IOT**************************************

//    else
//    {
//        //printf("%s",RecDataStruct.USERID);
//        closesocket(c);
//        printf("\nIllegal user\n ");
//        return 0;
//    }

//    else
//    {
//        closesocket(c);
//        printf("\nIllegal user\n ");
//        return 0;
//    }
    return 0;
}

/*
else if(!strcmp("ZYXX1227",RecDataStruct.checkcode))
{
    ///************************************
    printf("\nNOMAL IoT_CLIENT:|%s\n",inet_ntoa(a->ADDR.sin_addr));///改
    //len=recv(c,rec,1*sizeof(char),0);
    //send(c,"123456789012345678901234567890",30*sizeof(char),0);
    recv(c,rec,12*sizeof(char),0);
    strncpy(a->USERID,rec,12);
    printf("%s",rec);
    a->USERID[11] ='\0';
    printf("--%s",a->USERID);
    recv(c,rec,10*sizeof(char),0);
    strncpy(a->USERPASSWORD,rec,10);
    a->USERPASSWORD[9]='\0';
    printf("/%s\n",a->USERPASSWORD);
    printf("\nUnecessary Regist\n");
    ///*************************************
    Register(a,1);
    if (SIGNIN(a)==1)
    {
        printf("\n登陆成功\n");
        signIN=1;
        strcpy(IoTdata,"SII");
        strcat(IoTdata,a->USERID);
        len=send(c,IoTdata,30*sizeof(char),0);
        if(len==SOCKET_ERROR||len==0)
        {
            printf("\n连接%I64d退出\n",c);
            closesocket(c);
            delete_out_user(*a);
            return 0;
        }
        strcpy(Contacta,a->USERID);
        strcat(Contacta,"CO");
        //usercontact=fopen(Contact,"a+");
        strcpy(Messagea,a->USERID);
        strcat(Messagea,"ME");
        ///*************进入
        IoTtalk(Contacta,Messagea,a);
        //
    }
    else
    {
        printf("\n登录失败\n");
        memset(&RecDataStruct,0,sizeof(sendbag));
        memset(sendbuf,0,sizeof(sendbag));
        strcpy(IoTdata,"Sii");
        strcat(IoTdata,a->USERID);
        len=send(c,IoTdata,30*sizeof(char),0);
        if(len==SOCKET_ERROR||len==0)
        {
            printf("\n连接%I64d退出\n",c);
            closesocket(c);
            return 0;
        }
        */
