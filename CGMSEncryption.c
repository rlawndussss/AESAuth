#include "CGMSEncryption.h"

int SetInitialAccessKey( int inputPincode ){
    int LRes = 0;//int LRes = KEYGEN_FAIL;
    unsigned char pinchar[4]  = {0,};
    unsigned char keychar[16] = {0x73, 0x64, 0x62, 0x69, 0x6f, 0x73, 0x65, 0x6e, 0x73, 0x6f, 0x72, 0x70,};


    int pin1st = inputPincode/1000;
    int pin2nd = (inputPincode - pin1st*1000)/100;
    int pin3rd = (inputPincode - pin1st*1000 - pin2nd*100)/10;
    int pin4th = inputPincode % 10;

    pinchar[3] = pin4th + 0x30;
    pinchar[2] = pin3rd + 0x30;
    pinchar[1] = pin2nd + 0x30;
    pinchar[0] = pin1st + 0x30;

    keychar[12] = pinchar[0];
    keychar[13] = pinchar[1];
    keychar[14] = pinchar[2];
    keychar[15] = pinchar[3];

    KeyExpansion(keychar, RoundKey); //전역변수가 pointer로 들어가 조정되어 나옴
    LRes = 1; //LRes = KEYGEN_SUCCESS;
    return LRes;
}

int SetFinalAccessKey( unsigned char* appUuid, unsigned char* authUuid, unsigned char* deviceUuid ){    
    unsigned char keychar[32] = {0,};
    CreateAcccessKeyAsString(appUuid,authUuid,deviceUuid,keychar);
    KeyExpansion(keychar, RoundKey); //전역변수가 pointer로 들어가 조정되어 나옴
    return 1; //return KEYGEN_SUCCESS;
}



unsigned char* ByteDataEncrypt(unsigned char DecryptData[], int length){

    int LLen = trunc(length/16); //16의 몪만 취득
    if((length%16)!=0){LLen++;}  //나머지 존재 여부에 따라 길이 추가조정
    LLen*=16;                    //암호화 길이로 변환
    unsigned char* LRes = (unsigned char*)malloc(LLen * sizeof(unsigned char));
    Encrypt(RoundKey,DecryptData,LRes);
    return LRes;
}

unsigned char* ByteDataDecrypt(unsigned char EncryptData[], int length){
    int LLen = length; //decrypt는 길이가 더 커질 이유가 없어 그대로 사용 
    unsigned char* LRes = (unsigned char*)malloc(LLen * sizeof(unsigned char));
    Decrypt(RoundKey,EncryptData,LRes);
    return LRes; 
}

int IsInAFinalAccessKey( unsigned char* unknownUuid){
}
