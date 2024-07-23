#include <stdio.h>
#include <string.h>
#include "CGMSEncryption.h"
#include "CGMSEncryption.c"

void VerifyEncryptionMatch_Length(int digit){

    unsigned char str[9999];
    unsigned char encrypted[9999];
    unsigned char decrypted[9999];
    int currentlen;
    int staticsize;//적절한 이름이 안떠오름
    int returnsize;

    bytesclear(str,9999);

    Set_AccessKey_Initial(digit);
    for(int i = 0; i< 9999; i++){ //Access Key는 받아오고, 입력되는 str의 길이 및 값을 random으로 읽어오도록 함 
        currentlen = i;
        staticsize = EncryptLen(i);
        RandomByteArray(str, currentlen); //제한된 길이의 결과값이 출력
        Encrypt_Initial(str,i, encrypted, staticsize);
        Decrypt_Initial(encrypted, staticsize, encrypted, &returnsize);

        if(currentlen == returnsize){

        }else {
            printf("Wrong Size, input, output (%d, %d)\r\n",currentlen,returnsize);
        }
    }
}

void VerifyEncryptionMatch(unsigned char* str, int strlength){
    int L4digit;
    int LLen[2] = {strlength, EncryptLen(strlength)};//원래길이, 보정된 길이를 담은 길이 배열. enum이 된다면 enum으로 origin_len, calibrated_len으로 구분지었을것
    int LLen_Client;
    int LLen_Client_Out;
    int LFuncRes;
    unsigned char LStr[ LLen[1] ];//보니깐 이상한 문자 들어가는건 여기서 32block으로 재산정을 해서 생긴 문젠듯. 그렇다면 초기화를 해 주던가 pkcs#7을 추가하던가 해서 해결해야지
    unsigned char encrypted[ LLen[1] ];
    unsigned char decrypted[ LLen[1] ];
    AES256Key InitialKey;
    bytesclear(LStr, LLen[1]);   //확장된 길이 초기화
    bytescpy(LStr, str, LLen[0]);//원본 길이까지는 원본 데이터 추가

    for(int i = 0; i< 10000; i++){
        L4digit = i;
        printf("4Digit number : %d",L4digit);
        LFuncRes = Set_AccessKey_Initial(L4digit);
        Get_AccessKey_Initial(InitialKey);
        if (LFuncRes  != KEYGEN_SUCCESS) {
            printf("Access Key 생성 오류 발생으로 인한 종료");
            exit;
        }

        LFuncRes = Encrypt_Initial(LStr, LLen[0], encrypted, LLen[1] );
        LLen_Client = LLen[1]; //물론 패딩이 없는 원본데이터 크기가 올 수가 없으므로 이렇게 처리
        LFuncRes = Decrypt_Initial(encrypted,LLen_Client, decrypted, &LLen_Client_Out);
        for(int j = 0; j<strlength; j++){
            if(LStr[j] != decrypted[j]){
                printf("복호화 불일치 오류 발생으로 인한 종료, index : %d \r\n",L4digit);
                j = strlength;
                i = 10000;
                printBytes(LStr, strlength);
                printBytes(decrypted, strlength);
                exit;                
            }
        }
        printf(" Pass\r\n");
        // printf("In ");
        // printBytes(LStr,strlength);
        // printf("Out ");
        // printBytes(decrypted,strlength);        
    }
}

int VerifyEncAndDecFunc(unsigned char* AppUUID, unsigned char* AuthUUID, unsigned char* DeviceUUID, unsigned char* str, int strlength){
    int L4digit;
    int LLen[2] = {strlength, EncryptLen(strlength)};//원래길이, 보정된 길이를 담은 길이 배열. enum이 된다면 enum으로 origin_len, calibrated_len으로 구분지었을것
    int LLen_Client;
    int LLen_Client_Out;
    int LFuncRes;
    unsigned char LStr[ LLen[1] ];//보니깐 이상한 문자 들어가는건 여기서 32block으로 재산정을 해서 생긴 문젠듯. 그렇다면 초기화를 해 주던가 pkcs#7을 추가하던가 해서 해결해야지
    unsigned char encrypted[ LLen[1] ];
    unsigned char decrypted[ LLen[1] ];

    AES256Key InitialKey;
    AES256Key FinalKey;

    bytesclear(LStr, LLen[1]);   //확장된 길이 초기화
    bytescpy(LStr, str, LLen[0]);//원본 길이까지는 원본 데이터 추가

    //Inital Access Key 
    printf("4Digit Access Number를 입력하세요 : ");
    scanf("%d",&L4digit);

    //Initial Access Key를 사용한 암,복호화    
    LFuncRes = Set_AccessKey_Initial(L4digit);
    Get_AccessKey_Initial(InitialKey);
    printf("\r\n-------------------------------------------------------- using Initial Access Key --------------------------------------------------------\r\n");
    if (LFuncRes  != KEYGEN_SUCCESS) {
        exit;
    }
        printCaptionedByte("\r\nInitial Access Key ",InitialKey, EncLen);
        printCaptionedByte("\r\nInitial Round Key ",RoundKey_Initial, RoundLen);
        printCaptionedByte("Input ",LStr, strlength);

    // LFuncRes = Encrypt_Initial(LStr, LLen[0], encrypted, LLen[1] );
    LFuncRes = Encrypt_Initial(LStr, LLen[0], encrypted, LLen[1] );
    switch(LFuncRes){
        case ENCRYPT_SUCCESS : 
            printCaptionedByte("Output ",encrypted, LLen[1]);
            break;

        case ENCRYPT_LENGTHUNMATCH : 
            printf("\r\n 입력의 길이가 적절하지 않습니다. \r\n");
            break;    

        default :   
            printf("\r\n 알수없는 오류가 발생하였습니다. . \r\n");
            break;
    }


    // 다른 기기, 프로그램에서 받는다고 가정을 하면, 받은 패킷의 크기를 가져와 사용하는 형태가 되어야 할 듯 함. 이 역활을 하는게 LLen_Client
    LLen_Client = LLen[1]; //물론 패딩이 없는 원본데이터 크기가 올 수가 없으므로 이렇게 처리
    LFuncRes = Decrypt_Initial(encrypted,LLen_Client, decrypted, &LLen_Client_Out);
    if (LFuncRes == DECRYPT_SUCCESS){
        printCaptionedByte("Decrypted ",decrypted, LLen_Client_Out);
        printf("Padding Length : %d\r\n",LLen_Client_Out);
    }

    //Final Access Key를 사용한 암,복호화
    printf("\r\n-------------------------------------------------------- using Final Access Key --------------------------------------------------------\r\n");
    printCaptionedByte("App    UUID ", AppUUID, BaseLen);
    printCaptionedByte("Auth   UUID ", AuthUUID, BaseLen);
    printCaptionedByte("Device UUID ", DeviceUUID, BaseLen);

    LFuncRes = Set_AccessKey_Final(AppUUID, AuthUUID, DeviceUUID); //사실 Expansion 실패하면 그 뒤에단계 모두 동작하지 않게 만들어야 하므로, 지금 코드들도 틀린 코드이다. 
    if (LFuncRes != KEYGEN_SUCCESS){
        exit;
    }
        Get_AccessKey_Final(FinalKey);
        printCaptionedByte("\r\nFinal Access Key ",FinalKey, EncLen);

        // 비교를 위해 lstr 다시 초기화
        bytesclear(LStr, LLen[1]);   //확장된 길이 초기화
        bytescpy(LStr, str, LLen[0]);//원본 길이까지는 원본 데이터 추가
        printCaptionedByte("Input ",LStr, strlength);

    LFuncRes = Encrypt_Final(LStr, LLen[0], encrypted, LLen[1] );
    switch(LFuncRes){
        case ENCRYPT_SUCCESS : 
            printCaptionedByte("Output ",encrypted, LLen[1]);
            break;

        case ENCRYPT_LENGTHUNMATCH : 
            printf("\r\n 입력의 길이가 적절하지 않습니다. \r\n");
            break;    

        default : 
            printf("\r\n 알수없는 오류가 발생하였습니다. . \r\n");
            break;
    }
    

    // 다른 기기, 프로그램에서 받는다고 가정을 하면, 받은 패킷의 크기를 가져와 사용하는 형태가 되어야 할 듯 함. 이 역활을 하는게 LLen_Client
    LLen_Client = LLen[1]; //물론 패딩이 없는 원본데이터 크기가 올 수가 없으므로 이렇게 처리
    LFuncRes = Decrypt_Final(encrypted,LLen_Client, decrypted, &LLen_Client_Out);
    if (LFuncRes == DECRYPT_SUCCESS){
        printCaptionedByte("Decrypted ",decrypted, LLen_Client_Out);
        printf("Padding Length : %d\r\n",LLen_Client_Out);
    }

    return 1;    
}

void VerifyEmptyInitialAccessKey(unsigned char* AppUUID, unsigned char* AuthUUID, unsigned char* DeviceUUID, unsigned char* str, int strlength){
    int L4digit;
    int LFuncRes;
    int LLen_Client;
    int LLen_Client_Out;
    int LLen[2] = {strlength, EncryptLen(strlength)};
    unsigned char LStr[ LLen[1] ];
    unsigned char encrypted[ LLen[1] ];
    unsigned char decrypted[ LLen[1] ];

    AES256Key InitialKey;

    bytesclear(LStr, LLen[1]);   //확장된 길이 초기화
    bytescpy(LStr, str, LLen[0]);//원본 길이까지는 원본 데이터 추가
    printf("\r\n-------------------------------------------------------- Empty Initial Access Key --------------------------------------------------------\r\n");
    Get_AccessKey_Initial(InitialKey);
    printBytes(InitialKey,EncLen);
    printBytes(RoundKey_Initial,RoundLen);
    printBytes(LStr, strlength);


    LFuncRes = Encrypt_Initial(LStr, LLen[0], encrypted, LLen[1] );
    switch(LFuncRes){
        case ENCRYPT_SUCCESS : 
            printCaptionedByte("Output ",encrypted, LLen[1]);
            break;

        case ENCRYPT_LENGTHUNMATCH : 
            printf("\r\n 입력의 길이가 적절하지 않습니다. \r\n");
            break;    

        default : 
            printf("\r\n 암호화에 실패하였습니다 . \r\n");
            break;
    }    

    LLen_Client = LLen[1]; //물론 패딩이 없는 원본데이터 크기가 올 수가 없으므로 이렇게 처리
    LFuncRes = Decrypt_Initial(encrypted,LLen_Client, decrypted, &LLen_Client_Out);
    if (LFuncRes == DECRYPT_SUCCESS){
        printCaptionedByte("Decrypted ",decrypted, LLen[1]);
        printf("Padding Length : %d\r\n",LLen_Client_Out);
    }  else {
        printf("\r\n 복호화에 실패하였습니다 . \r\n");
    }  

    printf("\r\n4Digit Access Number를 입력하세요 : ");
    scanf("%d",&L4digit);
    Set_AccessKey_Initial(L4digit);

    printf("\r\n-------------------------------------------------------- Set Initial Access Key --------------------------------------------------------\r\n");
    printBytes(AccessKey_Initial,EncLen);
    printBytes(RoundKey_Initial,RoundLen);
    printBytes(LStr, strlength);

    LFuncRes = Encrypt_Initial(LStr, LLen[0], encrypted, LLen[1] );
    switch(LFuncRes){
        case ENCRYPT_SUCCESS : 
            printCaptionedByte("Output ",encrypted, LLen[1]);
            break;

        case ENCRYPT_LENGTHUNMATCH : 
            printf("\r\n 입력의 길이가 적절하지 않습니다. \r\n");
            break;    

        default : 
            printf("\r\n 암호화에 실패하였습니다 . \r\n");
            break;
    }    

    LLen_Client = LLen[1]; //물론 패딩이 없는 원본데이터 크기가 올 수가 없으므로 이렇게 처리
    LFuncRes = Decrypt_Initial(encrypted,LLen_Client, decrypted, &LLen_Client_Out);
    if (LFuncRes == DECRYPT_SUCCESS){
        printCaptionedByte("Decrypted ",decrypted, LLen_Client_Out);
        printf("Padding Length : %d\r\n",LLen_Client_Out);
    }  else {
        printf("\r\n 복호화에 실패하였습니다 . \r\n");
    }      

}

void VerifyEmptyFinalAccessKey(unsigned char* AppUUID, unsigned char* AuthUUID, unsigned char* DeviceUUID, unsigned char* str, int strlength){
    int L4digit;
    int LFuncRes;
    int LLen_Client;
    int LLen_Client_Out;
    int LLen[2] = {strlength, EncryptLen(strlength)};
    unsigned char LStr[ LLen[1] ];
    unsigned char encrypted[ LLen[1] ];
    unsigned char decrypted[ LLen[1] ];

    AES256Key FinalKey;

    bytesclear(LStr, LLen[1]);   //확장된 길이 초기화
    bytescpy(LStr, str, LLen[0]);//원본 길이까지는 원본 데이터 추가
    printf("\r\n-------------------------------------------------------- Empty Final Access Key --------------------------------------------------------\r\n");
    Get_AccessKey_Final(FinalKey);
    printBytes(FinalKey,EncLen);
    printBytes(RoundKey_Final,RoundLen);
    printBytes(LStr, strlength);
    

    LFuncRes = Encrypt_Final(LStr, LLen[0], encrypted, LLen[1] );
    switch(LFuncRes){
        case ENCRYPT_SUCCESS : 
            printCaptionedByte("Output ",encrypted, LLen[1]);
            break;

        case ENCRYPT_LENGTHUNMATCH : 
            printf("\r\n 입력의 길이가 적절하지 않습니다. \r\n");
            break;    

        default : 
            printf("\r\n 암호화에 실패하였습니다 . \r\n");
            break;
    }    

    LLen_Client = LLen[1]; //물론 패딩이 없는 원본데이터 크기가 올 수가 없으므로 이렇게 처리
    LFuncRes = Decrypt_Final(encrypted,LLen_Client, decrypted, &LLen_Client_Out);
    if (LFuncRes == DECRYPT_SUCCESS){
        printCaptionedByte("Decrypted ",decrypted, LLen_Client_Out);
        printf("Padding Length : %d\r\n",LLen_Client_Out);
    }  else {
        printf("\r\n 복호화에 실패하였습니다 . \r\n");
    }  

    printCaptionedByte("App UUID", AppUUID, BaseLen);
    printCaptionedByte("Auth UUID", AuthUUID, BaseLen);
    printCaptionedByte("Device UUID", DeviceUUID, BaseLen);
    Set_AccessKey_Final(AppUUID, AuthUUID, DeviceUUID);
    printf("\r\n-------------------------------------------------------- Set Final Access Key --------------------------------------------------------\r\n");
    Get_AccessKey_Final(FinalKey);
    printBytes(FinalKey,EncLen);
    printBytes(RoundKey_Final,RoundLen);
    printBytes(LStr, strlength);

    LFuncRes = Encrypt_Final(LStr, LLen[0], encrypted, LLen[1] );
    switch(LFuncRes){
        case ENCRYPT_SUCCESS : 
            printCaptionedByte("Output ",encrypted, LLen[1]);
            break;

        case ENCRYPT_LENGTHUNMATCH : 
            printf("\r\n 입력의 길이가 적절하지 않습니다. \r\n");
            break;    

        default : 
            printf("\r\n 암호화에 실패하였습니다 . \r\n");
            break;
    }    

    LLen_Client = LLen[1]; //물론 패딩이 없는 원본데이터 크기가 올 수가 없으므로 이렇게 처리
    LFuncRes = Decrypt_Final(encrypted,LLen_Client, decrypted, &LLen_Client_Out);
    if (LFuncRes == DECRYPT_SUCCESS){
        printCaptionedByte("Decrypted ",decrypted, LLen_Client_Out);
        printf("Padding Length : %d\r\n",LLen_Client_Out);
    }  else {
        printf("\r\n 복호화에 실패하였습니다 . \r\n");
    }      

}

int main(void)
{

    int outputlen = 17;
    unsigned char str[17]={0x70, 0xf1, 0x4b, 0x8f, 0x9b, 0x9e, 0x2a, 0x42, 0x56, 0x84, 0xe5, 0xa9, 0x76, 0xfa, 0x2b, 0x1f, 0x03};
    // unsigned char str[16]={0xC8, 0x1A, 0xC6, 0x40, 0x5E, 0xA0, 0x4B, 0x6C, 0xAC, 0x58, 0x57, 0x15, 0x42, 0x94, 0x80, 0x34};


    
    // unsigned char str[outputlen];
    // unsigned char tmp[128] = { 0x39, 0x38, 0x61, 0x64, 0x33, 0x32, 0x39, 0x65, 0x63, 0x31, 0x35, 0x34, 0x65, 0x64, 0x62, 0x62, 
    //                            0x62, 0x63, 0x66, 0x30, 0x33, 0x61, 0x62, 0x34, 0x66, 0x39, 0x30, 0x32, 0x63, 0x66, 0x35, 0x63, 
    //                            0x38, 0x31, 0x61, 0x63, 0x36, 0x34, 0x30, 0x35, 0x65, 0x61, 0x30, 0x34, 0x62, 0x36, 0x63, 0x61, 
    //                            0x63, 0x35, 0x38, 0x35, 0x37, 0x31, 0x35, 0x34, 0x32, 0x39, 0x34, 0x38, 0x30, 0x33, 0x34, 0x34, 
    //                            0x63, 0x34, 0x38, 0x62, 0x32, 0x34, 0x34, 0x62, 0x61, 0x62, 0x36, 0x62, 0x32, 0x62, 0x36, 0x62, 
    //                            0x61, 0x62, 0x00, 0x62, 0x32, 0x62, 0x00, 0x64, 0x30, 0x61, 0x00, 0x61, 0x63, 0x62, 0x36, 0x36, // 0x61, 0x62, 0x65, 0x62, 0x32, 0x62, 0x65, 0x64, 0x30, 0x61, 0x63, 0x61, 0x63, 0x62, 0x36, 0x36,
    //                            0x66, 0x36, 0x38, 0x39, 0x33, 0x36, 0x32, 0x39, 0x64, 0x39, 0x61, 0x39, 0x66, 0x39, 0x63, 0x61, 
    //                            0x31, 0x61, 0x36, 0x61, 0x62, 0x61, 0x30, 0x62, 0x66, 0x62, 0x38, 0x62, 0x39, 0x61, 0x34, 
    //                         };

    unsigned char encrypted[16];
    unsigned char decrypted[16];
    AES256Key InitialKey;

    int Mode;

    

    unsigned char bytesforuuid1[20] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,};
    unsigned char bytesforuuid2[20] = {0x77, 0x78, 0x79, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x90, 0x91, 0x92,};
    unsigned char bytesforuuid3[20] = {0x11, 0x13, 0x15, 0x17, 0x19, 0x1B, 0x1D, 0x1F, 0x21, 0x23, 0x25, 0x27, 0x29, 0x2B, 0x2D, 0x2F,};

    

    unsigned char* packet = NULL;
    int packetlen = 0;

    AES128Key uuid1;
    AES128Key uuid2;
    AES128Key uuid3;

    bytesclear(uuid1, BaseLen);
    bytesclear(uuid2, BaseLen);
    bytesclear(uuid3, BaseLen);
    // bytesclear(str, outputlen);

    //각자의 길이까지에만 맞춰서 초기화
    // bytescpy(str, "sdbiosensor", TestStrLen);
    bytescpy(uuid1, bytesforuuid1, BaseLen);
    bytescpy(uuid2, bytesforuuid2, BaseLen);
    bytescpy(uuid3, bytesforuuid3, BaseLen);   

    printf("1. 암호화, 복호화 검증 시나리오\r\n");
    printf("2. Empty Access Key 시나리오(Initial)\r\n");
    printf("3. Empty Access Key 시나리오(Final)\r\n");
    printf("4. Initial Access Key에 따른 암호화/복호화 일치율 검사 \r\n");

    printf("Mode를 선택하세요 : ");
    scanf("%d",&Mode);   
 

    switch (Mode)
    {
        case 1 :
            // RandomByteArray(str, outputlen);                            //입력에는 난수를 생성
            VerifyEncAndDecFunc(uuid1, uuid2, uuid3, str, outputlen);   //암호화, 복호화 검증 시나리오
            break;
        case 2 :
            RandomByteArray(str, outputlen);
            VerifyEmptyInitialAccessKey(uuid1, uuid2, uuid3, str, outputlen);
            break;  
        case 3 : 
            RandomByteArray(str, outputlen);
            VerifyEmptyFinalAccessKey(uuid1, uuid2, uuid3, str, outputlen);
            break;
        case 4 : 
            RandomByteArray(str, outputlen);
            VerifyEncryptionMatch(str, outputlen);
            break;
        case 5 : 
            RandomByteArray(str, outputlen);
            printBytes(str, outputlen);
            break;
    
    default:
        break;
    }

    return 0;
}