#include "../head/SERVER.h"
#ifdef STPOOL
int talk(struct sttask *ptask)
#else
int talk(LPVOID b)
#endif
{
    int len, signIN = 0, creat_check_alive = 0;
#ifdef STPOOL
    if (ptask->task_arg == NULL)
    {
        printf("ERR");
        return 0;
    }
    CLN *a = (CLN *)ptask->task_arg;
#else
    CLN *a = (CLN *)b;
#endif
    char IoTdata[30] = "";
    char logcat[256] = "";
    char Contacta[20];
    char Messagea[20];
    char rec[15] = "";
    sendbag SendDataStruct;
    char sendbuf[sizeof(sendbag)] = {0};
    char tag[4], tag1[18] = "ZYXX1226";
    memset(tag, 0, 3);
    memset(&SendDataStruct, 0, sizeof(sendbag));
    sleep(1);
    return 0;
    CopyCln2Sendbag(*a, &SendDataStruct);
    SOCKET c = a->remote_socket;
    strncpy(tag, SendDataStruct.checkcode, 3);
    memset(logcat, 0, 100 * sizeof(char));
    strcpy(logcat, inet_ntoa(a->ADDR.sin_addr));
    strcat(logcat, "|");
    strcat(logcat, SendDataStruct.checkcode);
    logwrite(logcat);
    int isRedo = 0;
    if (!strcmp(tag, "ZYX") && a->info[1] != 'Y')
    {
        if (!strcmp(tag1, a->checkcode))
        {
            printf("\nNOMAL CLIENT:|%s\n", inet_ntoa(a->ADDR.sin_addr));
            a->info[1] = 'Y';
            return 1;
        }
        else
        {
            printf("\nOLD VERSION CLIENT:|%s\n", inet_ntoa(a->ADDR.sin_addr));
            memset(&SendDataStruct, 0, sizeof(sendbag));
            memset(sendbuf, 0, sizeof(sendbag));
            strcpy(SendDataStruct.checkcode, "UPD");
            strcpy(SendDataStruct.DATA, app_version);
            SendDataStruct.save[99] = '\n';
            memcpy(sendbuf, &SendDataStruct, sizeof(SendDataStruct));
            len = send(c, sendbuf, sizeof(sendbag), 0);
            return 1;
        }
    }
    if (a->info[1] != 'Y')
    {
        printf("\nIllegal CLIENT:|%s\n", inet_ntoa(a->ADDR.sin_addr));
        closesocket(c);
        //printf("Free\n");
        free(a);
        return 0;
    }
    signIN = (a->info[0] == 'Y'); //whether User had Signed in
    if (signIN && a->info[0] != 'N' && !creat_check_alive)
    {
        creat_check_alive = 1;
        //CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)Check_alive,a,0,NULL);
    }
    switch (DJBHash(tag, 3))
    {
    case 12: //HBA
    {
        memset(&SendDataStruct, 0, sizeof(sendbag));
        memset(sendbuf, 0, sizeof(sendbag));
        strcpy(SendDataStruct.checkcode, "HB");
        SendDataStruct.save[99] = '\n';
        memcpy(sendbuf, &SendDataStruct, sizeof(SendDataStruct));
        len = send(c, sendbuf, sizeof(sendbag), 0);
        // free(sendbuf);
        if (len == SOCKET_ERROR || len == 0)
        {

            closesocket(c);
            return 0;
        }
    }
    case 78032: //ZYX
        break;
    case 69858: //SIA
    {
        printf("\n%s/%s/\n", a->USERID, a->USERPASSWORD);
        if (SIGNIN(a) == 1)
        {
            signIN = 1;
            a->info[0] = 'Y';
            memset(&SendDataStruct, 0, sizeof(sendbag));
            memset(sendbuf, 0, sizeof(sendbag));
            strcpy(SendDataStruct.checkcode, SIGN_IN);
            SendDataStruct.save[99] = '\n';
            memcpy(sendbuf, &SendDataStruct, sizeof(SendDataStruct));
            len = send(c, sendbuf, sizeof(sendbag), 0);
            if (len == SOCKET_ERROR || len == 0)
            {
                closesocket(c);
                delete_out_user(*a);
                return 0;
            }
            //
        }
        else
        {
            memset(&SendDataStruct, 0, sizeof(sendbag));
            memset(sendbuf, 0, sizeof(sendbag));
            strcpy(SendDataStruct.checkcode, "Si");
            SendDataStruct.save[99] = '\n';
            memcpy(sendbuf, &SendDataStruct, sizeof(SendDataStruct));
            len = send(c, sendbuf, sizeof(sendbag), 0);
            if (len == SOCKET_ERROR || len == 0)
            {
                closesocket(c);
                return 0;
            }
        }
    }
    break;
    case 68637: //REA
    {
        if (Register(a, 0) == 1)
        {
            memset(&SendDataStruct, 0, sizeof(sendbag));
            memset(sendbuf, 0, sizeof(sendbag));
            strcpy(SendDataStruct.checkcode, "RE");
            SendDataStruct.save[99] = '\n';
            memcpy(sendbuf, &SendDataStruct, sizeof(SendDataStruct));
            len = send(c, sendbuf, sizeof(SendDataStruct), 0);
            if (len == SOCKET_ERROR || len == 0)
            {
                closesocket(c);
                return 0;
            }
        }
        else
        {
            memset(&SendDataStruct, 0, sizeof(sendbag));
            memset(sendbuf, 0, sizeof(sendbag));
            strcpy(SendDataStruct.checkcode, "Re");
            SendDataStruct.save[99] = '\n';
            memcpy(sendbuf, &SendDataStruct, sizeof(SendDataStruct));
            len = send(c, sendbuf, sizeof(sendbag), 0);
            if (len == SOCKET_ERROR || len == 0)
            {
                closesocket(c);
                return 0;
            }
        }
    }
    break;
    case 68905: //RME
        break;
    case 70683: //TAA
    {
        if (Check_Id_Pwd(0, *a) != -1)
        {
            USER talktouser = FindOnlineUserOrIot(0, SendDataStruct.TalktoID, 0);
            if (talktouser == NULL)
            {
                USER find = FindRegisterUserOrIotNode(0, a->TalktoID, 0);
                if (find == NULL)
                {
                    return 0;
                }
                NewUserMsgStorage(*a, find->USERKEY_ID);
                memset(&SendDataStruct, 0, sizeof(sendbag));
                memset(sendbuf, 0, sizeof(sendbag));
                strcpy(SendDataStruct.checkcode, "TAN"); //TA but not online
                SendDataStruct.save[99] = '\n';
                memcpy(sendbuf, &SendDataStruct, sizeof(sendbag));
                len = send(c, sendbuf, sizeof(sendbag), 0);
                if (len == SOCKET_ERROR || len == 0)
                {
                    closesocket(c);
                    delete_out_user(*a);
                    free(a);
                    return 0;
                }
            }
            else
            {
                memset(sendbuf, 0, sizeof(sendbag));
                strcpy(SendDataStruct.checkcode, "TAT");
                SendDataStruct.save[99] = '\n';
                char temp[12] = {0};
                strcpy(temp, SendDataStruct.USERID);
                strcpy(SendDataStruct.USERID, SendDataStruct.TalktoID);
                strcpy(SendDataStruct.TalktoID, temp);
                memcpy(sendbuf, &SendDataStruct, sizeof(SendDataStruct));
                len = send(talktouser->USER_socket, sendbuf, sizeof(sendbag), 0);
                if (len == SOCKET_ERROR || len == 0)
                {

                    closesocket(talktouser->USER_socket);
                    CLN d;
                    strcpy(d.USERID, a->TalktoID);
                    delete_out_user(d);
                }
                USER find = FindRegisterUserOrIotNode(0, a->TalktoID, 0);
                if (find == NULL)
                {
                    return 0;
                }
                NewUserMsgStorage(*a, find->USERKEY_ID);
                memset(&SendDataStruct, 0, sizeof(sendbag));
                memset(sendbuf, 0, sizeof(sendbag));
                strcpy(SendDataStruct.checkcode, "TAS");
                strcpy(SendDataStruct.TalktoID, a->TalktoID);
                strcpy(SendDataStruct.USERID, a->USERID);
                SendDataStruct.save[99] = '\n';
                memcpy(sendbuf, &SendDataStruct, sizeof(SendDataStruct));
                len = send(c, sendbuf, sizeof(sendbag), 0);
                if (len == SOCKET_ERROR || len == 0)
                {

                    closesocket(c);
                    delete_out_user(*a);
                    free(a);
                    return 0;
                }
            }
        }
        else
        {
            memset(&SendDataStruct, 0, sizeof(sendbag));
            memset(sendbuf, 0, sizeof(sendbag));
            strcpy(SendDataStruct.checkcode, "Taa"); //TA but not online
            SendDataStruct.save[99] = '\n';
            memcpy(sendbuf, &SendDataStruct, sizeof(SendDataStruct));
            len = send(c, sendbuf, sizeof(sendbag), 0);
            if (len == SOCKET_ERROR || len == 0)
            {
                closesocket(c);
                delete_out_user(*a);
                free(a);
                return 0;
            }
        }
    }
    break;
    case 70235: //STO
    {
        memset(&SendDataStruct, 0, sizeof(sendbag));
        memset(sendbuf, 0, sizeof(sendbag));
        strcpy(SendDataStruct.checkcode, "STO");
        SendDataStruct.save[99] = '\n';
        memcpy(sendbuf, &SendDataStruct, sizeof(SendDataStruct));
        len = send(a->remote_socket, sendbuf, sizeof(sendbag), 0);
        if (len == SOCKET_ERROR || len == 0)
        {

            closesocket(c);
            delete_out_user(*a);
            return 0;
        }
        delete_out_user(*a);
        printf("\n%s\n", SendDataStruct.checkcode);
        a->info[0] = 'N';
        creat_check_alive = 0;
    }
    break;
    case 72270: //UPD
    {
        memset(&SendDataStruct, 0, sizeof(sendbag));
        memset(sendbuf, 0, sizeof(sendbag));
        strcpy(SendDataStruct.checkcode, "UPD");
        strcpy(SendDataStruct.DATA, app_version);
        SendDataStruct.save[99] = '\n';
        memcpy(sendbuf, &SendDataStruct, sizeof(SendDataStruct));
        len = send(c, sendbuf, sizeof(sendbag), 0);
    }
    break;
    case 50094: //ADD
    {
        CLN d;
        char IoTdevice[5] = "";
        int F = 0;
        strcpy(d.USERID, SendDataStruct.TalktoID);
        if (Check_Id_Pwd(1, d) != -1)
        {
            strncpy(IoTdevice, SendDataStruct.checkcode, 4);
            IoTdevice[4] = '\0';
            if (!strcmp(IoTdevice, "ADDI"))
            {
                F = 1;
            }
            USER talktouser = FindOnlineUserOrIot(0, SendDataStruct.TalktoID, 0);
            if (talktouser == NULL && F != 1)
            {
                Message mes = (Message)malloc(sizeof(struct message));
                memset(mes, 0, sizeof(contact));
                memset(mes, 0, sizeof(contact));
                strcpy(mes->checkcode, "NCA");
                strcpy(mes->TalktoID, a->USERID);
                strcpy(mes->USERID, SendDataStruct.TalktoID);
                strcpy(mes->data, SendDataStruct.DATA);
                printf("�û�%s������ADD", SendDataStruct.TalktoID);
                char talkto[30] = {'0'};
                strcpy(talkto, SendDataStruct.TalktoID);
                strcat(talkto, "/");
                strcat(talkto, SendDataStruct.TalktoID);
                strcat(talkto, "ME");
                memset(&SendDataStruct, 0, sizeof(sendbag));
                memset(sendbuf, 0, sizeof(sendbag));
                strcpy(SendDataStruct.checkcode, "ADN");
                //TA but not online
                strcpy(SendDataStruct.TalktoID, a->TalktoID);
                strcpy(SendDataStruct.USERID, a->USERID);
                SendDataStruct.save[99] = '\n';
                memcpy(sendbuf, &SendDataStruct, sizeof(SendDataStruct));
                FILE *ss = fopen(talkto, "a+"); ///**********dakai
                fwrite(mes, sizeof(struct message), 1, ss);
                fflush(ss);
                fclose(ss);
                free(mes);
                len = send(c, sendbuf, sizeof(sendbag), 0);
                if (len == SOCKET_ERROR || len == 0)
                {

                    closesocket(c);
                    delete_out_user(*a);
                    return 0;
                }
            }
            else if (talktouser != NULL && F != 1)
            {

                //memset(&SendDataStruct,0,sizeof(sendbag));
                memset(sendbuf, 0, sizeof(sendbag));
                strcpy(SendDataStruct.checkcode, "ADT");
                SendDataStruct.save[99] = '\n';
                char temp[12] = {0};
                strcpy(temp, SendDataStruct.USERID);
                strcpy(SendDataStruct.USERID, SendDataStruct.TalktoID);
                strcpy(SendDataStruct.TalktoID, temp);
                SendDataStruct.save[99] = '\n';
                memcpy(sendbuf, &SendDataStruct, sizeof(SendDataStruct));
                len = send(talktouser->USER_socket, sendbuf, sizeof(sendbag), 0);
                if (len == SOCKET_ERROR || len == 0)
                {

                    closesocket(talktouser->USER_socket);
                    delete_out_user(d);
                    isRedo = 1;
                    strcpy(temp, SendDataStruct.USERID);
                    strcpy(SendDataStruct.USERID, SendDataStruct.TalktoID);
                    strcpy(SendDataStruct.TalktoID, temp);
                }
                memset(&SendDataStruct, 0, sizeof(sendbag));
                memset(sendbuf, 0, sizeof(sendbag));
                strcpy(SendDataStruct.TalktoID, a->TalktoID);
                strcpy(SendDataStruct.USERID, a->USERID);
                strcpy(SendDataStruct.checkcode, "ADD");
                SendDataStruct.save[99] = '\n';
                memcpy(sendbuf, &SendDataStruct, sizeof(SendDataStruct));
                len = send(c, sendbuf, sizeof(sendbag), 0);
                if (len == SOCKET_ERROR || len == 0)
                {

                    closesocket(c);
                    delete_out_user(*a);
                    return 0;
                }
                ///********************
            }
            else if (F == 1 && talktouser != NULL)
            {
                char IoTcommand[30] = "";
                strcpy(IoTcommand, "ADD");
                strncat(IoTcommand, a->USERID, 20);
                len = send(talktouser->USER_socket, IoTcommand, 30 * sizeof(char), 0);
                // free(sendbuf);
                if (len == SOCKET_ERROR || len == 0)
                {

                    closesocket(talktouser->USER_socket);
                    return 0;
                }
            }
        }
        else
        {
            printf("�û�%s������ADD", SendDataStruct.TalktoID);
            //memset(&SendDataStruct,0,sizeof(sendbag));
            memset(sendbuf, 0, sizeof(sendbag));
            strcpy(SendDataStruct.checkcode, "Add"); //TA but not online
            SendDataStruct.save[99] = '\n';
            memcpy(sendbuf, &SendDataStruct, sizeof(SendDataStruct));
            len = send(c, sendbuf, sizeof(sendbag), 0);
            // free(sendbuf);
            if (len == SOCKET_ERROR || len == 0)
            {

                closesocket(c);
                delete_out_user(*a);
                return 0;
            }
        }
    }
    break;
    case 50109: //ADS
    {
        Contact mes = (Contact)malloc(sizeof(struct contact));
        memset(mes, 0, sizeof(contact));
        memset(sendbuf, 0, sizeof(sendbag));
        strcpy(mes->checkcode, "RCO");
        strcpy(mes->TalktoID, SendDataStruct.TalktoID);
        strcpy(mes->USERID, SendDataStruct.USERID);
        SendDataStruct.save[99] = '\n';
        memset(mes, 0, sizeof(contact));
        strcpy(mes->checkcode, "RCO");
        strcpy(mes->TalktoID, SendDataStruct.USERID);
        strcpy(mes->USERID, SendDataStruct.TalktoID);
        ///**********dakai
        char talkto[30] = {'0'};
        strcpy(talkto, SendDataStruct.TalktoID);
        strcat(talkto, "/");
        strcat(talkto, SendDataStruct.TalktoID);
        strcat(talkto, "CO");
        FILE *ss = fopen(talkto, "a+"); ///**********dakai
        fwrite(mes, sizeof(struct contact), 1, ss);
        fflush(ss);
        fclose(ss);
        strcpy(SendDataStruct.checkcode, "ADS");
        SendDataStruct.save[99] = '\n';
        memcpy(sendbuf, &SendDataStruct, sizeof(SendDataStruct));
        len = send(c, sendbuf, sizeof(sendbag), 0);
        if (len == SOCKET_ERROR || len == 0)
        {

            closesocket(c);
            delete_out_user(*a);
            return 0;
        }
    }
    break;
    case 68585: //RCO
    {
        UserReqFriendRel(a);
        UserReqIotRel(a);
    }
    break;
    case 69000: //RPA
        if (UserRePwd(*a) == 1)
        {
            memset(&SendDataStruct, 0, sizeof(sendbag));
            memset(sendbuf, 0, sizeof(sendbag));
            strcpy(SendDataStruct.checkcode, "RP");
            SendDataStruct.save[99] = '\n';
            memcpy(sendbuf, &SendDataStruct, sizeof(SendDataStruct));
            len = send(c, sendbuf, sizeof(SendDataStruct), 0);
            if (len == SOCKET_ERROR || len == 0)
            {
                closesocket(c);
                free(a);
                return 0;
            }
        }
        else
        {
            memset(&SendDataStruct, 0, sizeof(sendbag));
            memset(sendbuf, 0, sizeof(sendbag));
            strcpy(SendDataStruct.checkcode, "Rp");
            SendDataStruct.save[99] = '\n';
            memcpy(sendbuf, &SendDataStruct, sizeof(SendDataStruct));
            len = send(c, sendbuf, sizeof(sendbag), 0);
            if (len == SOCKET_ERROR || len == 0)
            {
                closesocket(c);
                free(a);
                return 0;
            }
        }
        break;
    default:
        break;
    }
    return 0;
}

///*****************************����to******************************
// else if (!strcmp(tag, "TAI") && signIN)
// {
//     if (Check_Id_Pwd(0, *a) != -1)
//     {
//         USER talktouser = FindOnlineUserOrIot(0, SendDataStruct.TalktoID, 0);
//         if (talktouser == NULL)
//         {
//             memset(&SendDataStruct, 0, sizeof(sendbag));
//             memset(sendbuf, 0, sizeof(sendbag));
//             strcpy(SendDataStruct.checkcode, "TNI"); //TA but not online
//             SendDataStruct.save[99] = '\n';
//             memcpy(sendbuf, &SendDataStruct, sizeof(sendbag));
//             len = send(c, sendbuf, sizeof(sendbag), 0);
//             if (len == SOCKET_ERROR || len == 0)
//             {
//
//                 closesocket(c);
//                 delete_out_user(*a);
//                 free(a);
//                 return 0;
//             }
//         }
//         else
//         {
//             //strcpy(talktouser.info,SendDataStruct.TalktoID);
//             ///******����Ƕ������豸CD=TA123457///******************************************************
//             strcpy(IoTdata, "CMD");
//             //strncat(IoTdata,a->USERID,11);
//             strncat(IoTdata, SendDataStruct.DATA, 26);
//             //printf("%s",SendDataStruct.DATA);
//             /*memcpy(sendbuf,&SendDataStruct,sizeof(SendDataStruct));*/
//             len = send(talktouser->USER_socket, IoTdata, 30 * sizeof(char), 0);
//             // free(sendbuf);

//             if (len == SOCKET_ERROR || len == 0)
//             {
//
//                 closesocket(talktouser->USER_socket);
//                 return 0;
//             }
//             //memset(&SendDataStruct,0,sizeof(sendbag));
//             memset(sendbuf, 0, sizeof(sendbag));
//             strcpy(SendDataStruct.checkcode, "TAi");
//             strcpy(SendDataStruct.DATA, talktouser->info);
//             SendDataStruct.save[99] = '\n';
//             memcpy(sendbuf, &SendDataStruct, sizeof(SendDataStruct));
//             /*len=send(c,sendbuf,sizeof(sendbag),0);
//             if(len==SOCKET_ERROR||len==0)
//             {
//                 printf("\n����%I64d�˳�\n",c);
//                 closesocket(c);
//                 delete_out_user(*a);
//                 return 0;
//             }*/
//         }
//     }
// }
// else if (!strcmp(tag, TALK_TO) && signIN)
// {
// }
//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\//
