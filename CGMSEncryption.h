#ifndef CGMSENCRYPTION_H
#define CGMSENCRYPTION_H

#define KEYGEN_SUCCESS 1
#define ENCRYPT_SUCCESS 1
#define DECRYPT_SUCCESS 1

#define KEYGEN_FAIL 0
#define ENCRYPT_FAIL 0
#define DECRYPT_FAIL 0

#define ENCRYPT_LENGTHUNMATCH 2
#define DECRYPT_LENGTHUNMATCH 2


#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include "AESEncryption.h"
#include "AESEncryption.c"

/*
    * 규칙은 기능-용도-분류로 진행

    * 변수의 경우 기능이 없으므로 용도-분류로 한정될 수 있음
    * Round Key는 인가용, 데이터 통신용을 각 각 Initial, Final으로 구분지어 RoundKey(용도)_Initial(분류) 형태로 작명
    * 함수의 경우 용도가 없을 수 있으므로, 기능-분류로 한정될 수 있음
    * 암호화는 인가용, 데이터 통신용을 각 각 Initial, Final으로 구분지어 Encrypt(용도)_Initial(분류) 형태로 작명

    * 함수 내에서 사용하는 경우는 Local의 의미를 담아 L첨자를 추가
    * 입력 변수는 Any의 의미를 담아 A첨자를 추가

    * 반환 변수는 모두 LRes를 선언 후 이를 통해 이루어진다. 
    
*/

unsigned char RoundKey_Initial[RoundLen];
unsigned char RoundKey_Temporary[RoundLen];
unsigned char RoundKey_Final[RoundLen];

/*
    * 4Digit를 통해 인가용 Static Key 및 Round Key를 생성하는 Set_AccessKey_Initial
    * 16Byte의 UUID 3종을 통해 데이터 통신용 Static Key 및 Round Key를 생성하는 Set_AccessKey_Final
*/
int Set_AccessKey_Initial( int A4Digit);
int Set_AccessKey_Temporar( unsigned char AappUuid[], unsigned char AauthUuid[], unsigned char AdeviceUuid[]);
int Set_AccessKey_Final( unsigned char AappUuid[], unsigned char AauthUuid[], unsigned char AdeviceUuid[]); //Guest도 어짜피 Final Key고, 이를 별도로 구분하지 못하니 중간단계가 아닌 그냥 change final Key가 들어가야 함
int Change_AccessKey_Final();

/* 분류에 따라, 자신의 위치에서 암호화/복호화를 수행. 구조상 Round Key를 제외하곤 Initial, Final이 동일하나, 사용자 호출을 위해 둘을 분리 */
int Encrypt_Initial(unsigned char ADecryptData[], int AInLen, unsigned char AOut[], int AOutLen); //AOutLen은 배열의 최대 크기, AInLen은 들어가는 문자열의 최대 길이로 정의
int Decrypt_Initial(unsigned char AEncryptData[], int AInLen, unsigned char AOut[], int AOutLen); //10글자 텍스트라도 선언은 16으로 하며, 나머지 6자리에는 PKES#7 Padding으로 채움

int Encrypt_Temporary(unsigned char ADecryptData[], int AInLen, unsigned char AOut[], int AOutLen);//때문에 선언은 varies[Multiply16(50)] 과 같은식으로 하여
int Decrypt_Temporary(unsigned char AEncryptData[], int AInLen, unsigned char AOut[], int AOutLen);//50자 텍스트를 쓰되 선언은 64로 생성되도록 하여야 함. 

int Encrypt_Final(unsigned char ADecryptData[], int AInLen, unsigned char AOut[], int AOutLen);//이는 입력배열의 크기를 malloc없이 동적으로 변경할 수 없기 때문
int Decrypt_Final(unsigned char AEncryptData[], int AInLen, unsigned char AOut[], int AOutLen);

/* 고정키를 통해 UUID를 역산하는 알고리즘이나, 현재 구현 가능성이 미지수인 관계로 빈 함수 형태로 작성 */
int ExtractUUIDs_Final( unsigned char unknownUuid[]);

#endif
