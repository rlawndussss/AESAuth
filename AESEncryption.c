#include <stdio.h>
#include <string.h>
#include <math.h>
#include "AESEncryption.h"
#include "functions.c"

 
/* S-Box를 이용하여 1Byte 단위로 치환하는 함수 */
void SubBytes( unsigned char (*state)[4] )
{
    /* 총 16번의 반복을 통하여 상태 배열의 각 Byte 값을 S-Box 표에서 알맞은 값으로 치환한다. */
    for (int i = 0; i<4; i++)
    {
        for (int j = 0; j < Nb; j++)
        { state[i][j] = Sbox[state[i][j]]; }
    }
}
 
/* In_Sbox를 이용하여 1Byte 단위로 치환하는 함수 */
void InvSubBytes( unsigned char (*state)[4] )
{
    /* 총 16번의 반복을 통하여 상태 배열의 각 Byte 값을 Inverse S-Box 표에서 알맞은 값으로 치환한다. */
    for (int i = 0; i<4; i++)
    {
        for (int j = 0; j<4; j++)
        { state[i][j] = In_Sbox[state[i][j]]; }
    }
}
 
/* 암호화시 Byte 치환이 이루어진 값을 Bit 단위로 뒤섞는 함수 */
void ShiftRows( unsigned char (*state)[4] )
{
    unsigned char temp = 0;
 
    /* 첫 번째 행을 기준으로 왼쪽으로 순환시킨다. */
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;
 
    /* 두 번째 행을 기준으로 왼쪽으로 순환시킨다. */
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
 
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;
 
    /* 셋 번째 행을 기준으로 왼쪽으로 순환시킨다. */
    temp = state[3][0];
    state[3][0] = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = temp;
}
 
/* 복호화시 Byte 치환이 이루어진 값을 Bit 단위로 뒤섞는 함수 */
void InvShiftRows( unsigned char (*state)[4] )
{
    unsigned char temp;
 
    /* 첫 번째 행을 기준으로 오른쪽으로 순환시킨다. */
    temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;
 
    /* 두 번째 행을 기준으로 오른쪽으로 순환시킨다. */
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
 
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;
 
    /* 셋 번째 행을 기준으로 오른쪽으로 순환시킨다. */
    temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}
 
/* 암호화시 Bit 단위로 뒤섞인 값을 통해서 4Bit 단위로 Bit 연산 함수 */
void MixColumns( unsigned char (*state)[4] )
{
    unsigned char Tmp, Tm, t;
 
    /* 총 4번의 For문을 수행하면서 상태 배열의 각 4열과 고정된 다항식 행렬을 곱한다. */
    for (int i = 0; i<4; i++)
    {
        t = state[0][i];
 
        /* 반복문을 수행하면서 상태 배열의 i(0~3)열과 고정된 다항식 행렬의 곱셈 연산을 수행하여 Tm에 저장한다. */
        /* 열 혼합이 완료된 Temp와 0x000000FF를 Bit 단위 AND 연산하여 얻어진 Byte 값을 다시 상태 배열의 알맞은 위치에 저장한다. */
        t = state[0][i];
        Tmp = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i];
        Tm = state[0][i] ^ state[1][i]; Tm = xtime(Tm); state[0][i] ^= Tm ^ Tmp;
        Tm = state[1][i] ^ state[2][i]; Tm = xtime(Tm); state[1][i] ^= Tm ^ Tmp;
        Tm = state[2][i] ^ state[3][i]; Tm = xtime(Tm); state[2][i] ^= Tm ^ Tmp;
        Tm = state[3][i] ^ t; Tm = xtime(Tm); state[3][i] ^= Tm ^ Tmp;
    }
}
 
/* 복호화시 Bit 단위로 뒤섞인 값을 통해서 4Bit 단위로 Bit 연산 함수 */
void InvMixColumns( unsigned char (*state)[4] )
{
    unsigned char a, b, c, d;
    for (int i = 0; i<4; i++)
    {
 
        a = state[0][i];
        b = state[1][i];
        c = state[2][i];
        d = state[3][i];
 
        state[0][i] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
        state[1][i] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
        state[2][i] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
        state[3][i] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
    }
}
 
/* 상태 배열 128 Bit와 라운드 키 128Bit 간의 Bit 단위 XOR 연산 수행 함수 */
void AddRoundKey(int round, unsigned char* RoundKey, unsigned char (*state)[4])
{
    for (int i = 0; i<4; i++)
    {
        /* 상태 배열와 Round Key를 XOR 연산을 통하여 Round Key 값을 추가한다. */
        for (int j = 0; j<4; j++)
        { state[j][i] ^= RoundKey[round * Nb * 4 + i * Nb + j]; }
    }
}
 
/* 각 라운드에서 사용하는 라운드키를 생성하기 위해 키 확장 과정 수행 함수 */
void KeyExpansion(unsigned char* key, unsigned char* RoundKey)
{
    int i, j;
    unsigned char temp[4], k;
 
    /* 첫 번째 Round Key에 Key 값을 저장한다. */
    for (i = 0; i<Nk; i++)
    {
        RoundKey[i * 4] = key[i * 4];
        RoundKey[i * 4 + 1] = key[i * 4 + 1];
        RoundKey[i * 4 + 2] = key[i * 4 + 2];
        RoundKey[i * 4 + 3] = key[i * 4 + 3];
    }
 
    /* 이전의 Round Key로부터 다른 모든 Round Key를 생성한다. */
    while (i < (Nb * (Nr + 1)))
    {
        for (j = 0; j<4; j++)
        {
            temp[j] = RoundKey[(i - 1) * 4 + j];
        }
        if (i % Nk == 0)
        {
            /* Word 단위로 순환이동 시키는 함수 (RotWord) */
            {
                k = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = k;
            } /* B0, B1, B2, B3 순서를 B1, B2, B3, B0 로 만든다. */
 
            /* 네개의 Byte를 S-Box를 통해서 치환 (SubWord) */
            {
                temp[0] = Sbox[temp[0]];
                temp[1] = Sbox[temp[1]];
                temp[2] = Sbox[temp[2]];
                temp[3] = Sbox[temp[3]];
            }
 
            temp[0] = temp[0] ^ Rcon[i / Nk];
        }
        else if (Nk > 6 && i % Nk == 4)
        {
            /* 네개의 Byte를 S-Box를 통해서 치환 (SubWord) */
            {
                temp[0] = Sbox[temp[0]];
                temp[1] = Sbox[temp[1]];
                temp[2] = Sbox[temp[2]];
                temp[3] = Sbox[temp[3]];
            }
        }
        RoundKey[i * 4 + 0] = RoundKey[(i - Nk) * 4 + 0] ^ temp[0];
        RoundKey[i * 4 + 1] = RoundKey[(i - Nk) * 4 + 1] ^ temp[1];
        RoundKey[i * 4 + 2] = RoundKey[(i - Nk) * 4 + 2] ^ temp[2];
        RoundKey[i * 4 + 3] = RoundKey[(i - Nk) * 4 + 3] ^ temp[3];
        i++;
    }
}
 
/* Cipher and Inverse Cipher Implementations 함수 */
int Implement_Cipher(unsigned char * RoundKey, unsigned char * in, unsigned char * out, bool mSwitch)
{
    unsigned char state[4][4] = { 0, };
    /* 입력받은 1차원 배열(128 Bit)의 평문을 2차원 상태 배열에 열 단위로 저장한다. */
    for (int i = 0; i<4; i++)
    {
        for (int j = 0; j<Nb; j++)
        {
            state[j][i] = in[i * 4 + j];
        }
    }
 
    /* Switch Cipher Implementations */
    switch (mSwitch)
    {
        /* Cipher Implementations */
    case (true):
    {
        AddRoundKey(0, RoundKey, state); // 첫 번째 라운드 키 추가
        for (int round = 1; round<Nr; round++) // 9번의 라운드를 돌면서 4단계 연산
        {
            SubBytes(state); // 바이트 치환
            ShiftRows(state); // 행 이동
            MixColumns(state); // 열 혼합
            AddRoundKey(round, RoundKey, state); // 확장된 키와 현재 블록을 XOR 연산
        }
 
        SubBytes(state); // 바이트 치환
        ShiftRows(state); // 열 이동
        AddRoundKey(Nr, RoundKey, state); // 확장된 키 중 마지막 키와 현재 블록을 XOR 연산
        break;
    }
    /* Inverse Cipher Implementations */
    case (false):
    {
        AddRoundKey(Nr, RoundKey, state);
        for (int round = Nr - 1; round>0; round--)
        {
            InvShiftRows(state); // 역 행 이동
            InvSubBytes(state); // 역 바이트 치환
            AddRoundKey(round, RoundKey, state);
            InvMixColumns(state); // 역 열 혼합
        }
 
        InvShiftRows(state); // 역 행 이동
        InvSubBytes(state); // 역 바이트 치환
        AddRoundKey(0, RoundKey, state); // 확장된 키 중 첫번째 키와 현재 블록을 XOR 연산
        break;
    }
    }
 
    /* 암호화가 완료된 2차원 상태 배열을 1차원 배열인 Out 배열에 저장한다. */
    for (int i = 0; i<4; i++)
    {
        for (int j = 0; j<Nb; j++)
        {
            out[i * 4 + j] = state[j][i];
        }
    }
    return 1;
}

void Encrypt(unsigned char * RoundKey, unsigned char * in, unsigned char * out, int len){

    int LLen=0;
    int LRewindCnt=0;
    int ibuf;
    
    // while ((in[LLen] != 0) && (in[LLen+1] != 0)){ LLen++; } //0이 연속적으로 나온다면 종료된 문자열. 이것도 크기 받아서 조정할 수 있지 않을까? 아니면 ciper에서 문제가 생기니 여기서 이렇게 거르는게 맞을까?
    // if(in[LLen] != 0){LLen++;}                              //(in[LLen+1] != 0) 조건으로 인해 줄어든 문자열 크기 보정.
    // if((LLen % 16) == 0){LRewindCnt = trunc(LLen/16); } else { LRewindCnt = trunc(LLen/16)+1; } 
    // unsigned char LOut[LRewindCnt*16]={0,};

    //07-17변경
    LRewindCnt = trunc(len/16);
    /*L16Buf를 16자리 block 분류를 위해 사용*/
    for(int i=0; i<LRewindCnt; i++){

        EncBlock Lin16Buf = {0,};
        EncBlock Lout16Buf = {0,};

        for(int j=0; j<16; j++){ Lin16Buf[j] = in[i*16 + j]; } //16자리씩 끊어서 구분    // std::cout << "● Input : " << Lin16Buf << std::endl;
        Implement_Cipher(RoundKey, Lin16Buf, Lout16Buf,true); //암호화                  // std::cout << "● Output : " << Lout16Buf << std::endl;
        for(int j=0; j<16; j++){ out[i*16 + j] = Lout16Buf[j]; } //16자리씩 끊어서 구분  // printBytes(out, LRewindCnt*16); /*debug code는 암호화 검증 시 사용 */
    }
}

void Decrypt(unsigned char * RoundKey, unsigned char * in, unsigned char * out, int len){

    int LLen=0;
    int LRewindCnt=0;
    int ibuf;
    
    // while ((in[LLen] != 0) && (in[LLen+1] != 0)){ LLen++; } //0이 연속적으로 나온다면 종료된 문자열. 이 부분이 문제가 된다. 길이를 받아서 수행하며, 길이 체크는 최종결과에서 수행하는게 맞다.
    // if(in[LLen] != 0){LLen++;}                              //(in[LLen+1] != 0) 조건으로 인해 줄어든 문자열 크기 보정.
    // if((LLen % 16) == 0){LRewindCnt = trunc(LLen/16); } else { LRewindCnt = trunc(LLen/16)+1; } 
    // unsigned char LOut[LRewindCnt*16]={0,};
    // 07-17변경
    LRewindCnt = trunc(len/16);
    /*L16Buf를 16자리 block 분류를 위해 사용*/
    for(int i=0; i<LRewindCnt; i++){

        EncBlock Lin16Buf = {0,};
        EncBlock Lout16Buf = {0,};

        for(int j=0; j<16; j++){ Lin16Buf[j] = in[i*16 + j]; } //16자리씩 끊어서 구분    
        //std::cout << "● Input : " << Lin16Buf << std::endl;
        Implement_Cipher(RoundKey, Lin16Buf, Lout16Buf,false); //복호화                           
        //std::cout << "● Output : " << Lout16Buf << std::endl;
        for(int j=0; j<16; j++){ out[i*16 + j] = Lout16Buf[j]; } //16자리씩 끊어서 구분  
        //printBytes(out, LRewindCnt*16); /*debug code는 암호화 검증 시 사용 */

        // printf("index : %d\r\n", i);
        // printBytes(Lin16Buf,16);
        // printBytes(Lout16Buf,16);
        
    }
}


void PINtoByte(int pin, unsigned char pinchar[]){
    int pin1st = pin/1000;
    int pin2nd = (pin - pin1st*1000)/100;
    int pin3rd = (pin - pin1st*1000 - pin2nd*100)/10;
    int pin4th = pin % 10;

    pinchar[3] = pin4th + 0x30;
    pinchar[2] = pin3rd + 0x30;
    pinchar[1] = pin2nd + 0x30;
    pinchar[0] = pin1st + 0x30;
}


void CreateAcccessKey16AsString(unsigned char* appUuid, unsigned char* authUuid, unsigned char* deviceUuid, unsigned char* out) {
    AES128Key LappUuid;
    AES128Key LauthUuid;
    AES128Key LdeviceUuid;
    AES128Key LXOR = {0,}; //단지 이거 하나 달라서 함수를 가르긴 했는데, 애초에 선언의 문제라 하나로 합치는것도 문제가 있긴 함
    

    /* 모든 uuid의 길이는 16자리여야 진행이나, uuid는 무조건 16자리가 들어온다고 가정하고 16자리로 강제 고정 */
    bytescpy(LappUuid,appUuid, BaseLen);
    bytescpy(LauthUuid,authUuid, BaseLen);
    bytescpy(LdeviceUuid,deviceUuid, BaseLen);
        
    //BYTE ROTATE
    for (int i = 0; i < 4; i++) {        
        RRotateByte(LappUuid,i*4,4);
        RRotateByte(LdeviceUuid,i*4,4);
        LRotateByte(LauthUuid,i*4,4);        
    }
    
    /* auth와 app 상위, auth와 device 하위 16byte를 XOR 연산. 이것도 어떻게 함수화 해서 깔끔하게 한줄로 끝낼 수 있지 않을까? 깔끔한 구조가 생각이 안남 */
    int MedValue = trunc(EncLen/2);
    for (int i = 0; i < (EncLen) ; i++) {
        if (i < MedValue) {
            LXOR[i] = LappUuid[i] ^ LauthUuid[i];
        } else {
            LXOR[i] = LdeviceUuid[i-MedValue] ^ LauthUuid[i-MedValue];
        }
    }

    bytescpy(out,LXOR,EncLen);
}


void CreateAcccessKey32AsString(unsigned char* appUuid, unsigned char* authUuid, unsigned char* deviceUuid, unsigned char* out) {
    AES128Key LappUuid;
    AES128Key LauthUuid;
    AES128Key LdeviceUuid;
    AES256Key LXOR = {0,};
    

    /* 모든 uuid의 길이는 16자리여야 진행이나, uuid는 무조건 16자리가 들어온다고 가정하고 16자리로 강제 고정 */
    bytescpy(LappUuid,appUuid, BaseLen);
    bytescpy(LauthUuid,authUuid, BaseLen);
    bytescpy(LdeviceUuid,deviceUuid, BaseLen);
        
    //BYTE ROTATE
    for (int i = 0; i < 4; i++) {        
        RRotateByte(LappUuid,i*4,4);
        RRotateByte(LdeviceUuid,i*4,4);
        LRotateByte(LauthUuid,i*4,4);        
    }
    
    /* auth와 app 상위, auth와 device 하위 16byte를 XOR 연산. 이것도 어떻게 함수화 해서 깔끔하게 한줄로 끝낼 수 있지 않을까? 깔끔한 구조가 생각이 안남 */
    int MedValue = trunc(EncLen/2);
    for (int i = 0; i < (EncLen) ; i++) {
        if (i < MedValue) {
            LXOR[i] = LappUuid[i] ^ LauthUuid[i];
        } else {
            LXOR[i] = LdeviceUuid[i-MedValue] ^ LauthUuid[i-MedValue];
        }
    }

    bytescpy(out,LXOR,EncLen);
}