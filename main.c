#include <stdio.h>
#include <string.h>
#include "CGMSEncryption.h"
#include "CGMSEncryption.c"



int main(void)
{
    int pin;
    unsigned char input[32]={"teststring"};
    unsigned char output[32]={0,};
    unsigned char redecr[32]={0,};
    unsigned char uuidky[32]={0,};

    unsigned char* charBuffer;

    unsigned char uuid1[32]={"7777567890123456"};
    unsigned char uuid2[32]={"abcdefghijklmnop"};
    unsigned char uuid3[32]={"asdfasdfasdfasdf"};

    printf("Pin을 입력하세요 : ");
    scanf("%d",&pin);

    SetInitialAccessKey(pin);
    printf("PinStaticKey : ");
    printBytes(RoundKey,240);

    /*입력 확인*/
    printf("Input   : ");
    printBytes(input,16);

    /*암호화된 데이터 확인*/
    // Encrypt(RoundKey,input,output);
    charBuffer = ByteDataEncrypt(input,16);
    memcpy(output,charBuffer,16);
    printf("Output  : ");
    printBytes(output,16);

    /*복호화된 데이터 검증*/
    // Decrypt(RoundKey,output,redecr);
    charBuffer = ByteDataDecrypt(output,16);
    memcpy(redecr,charBuffer,16);
    printf("ReDecr  : ");
    printBytes(redecr,16);

    SetFinalAccessKey(uuid1,uuid2,uuid3);
    printf("UUIDStaticKey : ");
    printBytes(RoundKey,240);    

    return 0;
}