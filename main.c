#include <stdio.h>
#include <string.h>
#include "CGMSEncryption.h"
#include "CGMSEncryption.c"

int VerifyEncAndDecFunc(unsigned char* AppUUID, unsigned char* AuthUUID, unsigned char* DeviceUUID, unsigned char* str, int strlength){
    int L4digit;
    int LLen[2] = {strlength, Multiply16(strlength)};//원래길이, 보정된 길이를 담은 길이 배열. enum이 된다면 enum으로 origin_len, calibrated_len으로 구분지었을것
    int LLen_Client;
    int LFuncRes;

    unsigned char LStr[ LLen[1] ];//보니깐 이상한 문자 들어가는건 여기서 32block으로 재산정을 해서 생긴 문젠듯. 그렇다면 초기화를 해 주던가 pkcs#7을 추가하던가 해서 해결해야지
    unsigned char encrypted[ LLen[1] ];
    unsigned char decrypted[ LLen[1] ];

    AES128Key InitialKey;
    AES256Key FinalKey;

    bytesclear(LStr, LLen[1]);   //확장된 길이 초기화
    bytescpy(LStr, str, LLen[0]);//원본 길이까지는 원본 데이터 추가


    //Inital Access Key 
    printf("4Digit Access Number를 입력하세요 : ");
    scanf("%d",&L4digit);

    //Initial Access Key를 사용한 암,복호화    
    LFuncRes = Set_AccessKey_Initial(L4digit, InitialKey);
    if (LFuncRes  == KEYGEN_SUCCESS) {
        printf("\r\n-------------------------------------------------------- using Initial Access Key --------------------------------------------------------\r\n");
        printCaptionedByte("Calibrate Initial Access Key by 4digit Key ",  InitialKey, BaseLen);
        printCaptionedByte("Span Round Key by Initial Access Key ", RoundKey_Initial, RoundLen);
    }
        printCaptionedByte("\r\nInput ",LStr, strlength);

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
    LFuncRes = Decrypt_Initial(encrypted,LLen_Client, decrypted, LLen_Client);
    if (LFuncRes == DECRYPT_SUCCESS){
        printCaptionedByte("Decrypted ",decrypted, LLen[1]);
    }

    //Final Access Key를 사용한 암,복호화
    printf("\r\n-------------------------------------------------------- using Final Access Key --------------------------------------------------------\r\n");
    printCaptionedByte("App    UUID ", AppUUID, BaseLen);
    printCaptionedByte("Auth   UUID ", AuthUUID, BaseLen);
    printCaptionedByte("Device UUID ", DeviceUUID, BaseLen);

    LFuncRes = Set_AccessKey_Final(AppUUID, AuthUUID, DeviceUUID,FinalKey); //사실 Expansion 실패하면 그 뒤에단계 모두 동작하지 않게 만들어야 하므로, 지금 코드들도 틀린 코드이다. 
    if (LFuncRes == KEYGEN_SUCCESS){
        printCaptionedByte("Span Final Access Key by UUIDs ", FinalKey, EncLen);
        printCaptionedByte("Span Round Key by Final Access Key ", RoundKey_Final, RoundLen);    
    }

        // 비교를 위해 lstr 다시 초기화
        bytesclear(LStr, LLen[1]);   //확장된 길이 초기화
        bytescpy(LStr, str, LLen[0]);//원본 길이까지는 원본 데이터 추가
        printCaptionedByte("\r\nInput ",LStr, strlength);

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
    LFuncRes = Decrypt_Final(encrypted,LLen_Client, decrypted, LLen_Client);
    if (LFuncRes == DECRYPT_SUCCESS){
        printCaptionedByte("Decrypted ",decrypted, LLen[1]);
    }

    return 1;    
}

int main(void)
{
    int Mode;
    int TestStrLen = 11;

    unsigned char str[TestStrLen];//={"sdbiosensorcgms1"};
    unsigned char bytesforuuid1[20] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,};
    unsigned char bytesforuuid2[20] = {0x77, 0x78, 0x79, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x90, 0x91, 0x92,};
    unsigned char bytesforuuid3[20] = {0x11, 0x13, 0x15, 0x17, 0x19, 0x1B, 0x1D, 0x1F, 0x21, 0x23, 0x25, 0x27, 0x29, 0x2B, 0x2D, 0x2F,};

    AES128Key uuid1;
    AES128Key uuid2;
    AES128Key uuid3;

    bytesclear(uuid1, BaseLen);
    bytesclear(uuid2, BaseLen);
    bytesclear(uuid3, BaseLen);
    bytesclear(str, 11);

    //각자의 길이까지에만 맞춰서 초기화
    bytescpy(str, "sdbiosensor", TestStrLen);
    bytescpy(uuid1, bytesforuuid1, BaseLen);
    bytescpy(uuid2, bytesforuuid2, BaseLen);
    bytescpy(uuid3, bytesforuuid3, BaseLen);    

    printf("1. 암호화, 복호화 검증 시나리오\r\n");
    printf("2. 차후 추가\r\n");
    printf("3. 차후 추가\r\n");

    printf("Mode를 선택하세요 : ");
    scanf("%d",&Mode);    
 

    switch (Mode)
    {
        case 1 :
            VerifyEncAndDecFunc(uuid1, uuid2, uuid3, str, TestStrLen); //암호화, 복호화 검증 시나리오
            break;
        case 2 :
            break;  
        case 3 : 
            break;
    
    default:
        break;
    }

    return 0;
}