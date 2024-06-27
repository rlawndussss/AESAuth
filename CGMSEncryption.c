#include "CGMSEncryption.h"

//sdbiosensorcgms1의 16byte고정값에, 4자리 숫자 블록을 4byte단위 블록에 더하여 고정키를 생성
// 초기값 73 64 62 69 6f 73 65 6e 73 6f 72 63 67 6d 73 31 
// 7834 입력 시 예상되는 결과값 aa 9c 95 9d a6 ab 98 a2 aa a7 a5 97 9e a5 a6 65 
int Set_AccessKey_Initial( int A4Digit, unsigned char AOut[] ){
    int LRes = KEYGEN_FAIL;
    unsigned char pinchar[4]  = {0,};
    AES128Key keychar = {0x73, 0x64, 0x62, 0x69, 0x6f, 0x73, 0x65, 0x6e, 0x73, 0x6f, 0x72, 0x63, 0x67, 0x6D, 0x73, 0x31};     

    int pin1st = A4Digit/1000;
    int pin2nd = (A4Digit - pin1st*1000)/100;
    int pin3rd = (A4Digit - pin1st*1000 - pin2nd*100)/10;
    int pin4th = A4Digit % 10;

    pinchar[3] = pin4th + 0x30;
    pinchar[2] = pin3rd + 0x30;
    pinchar[1] = pin2nd + 0x30;
    pinchar[0] = pin1st + 0x30;

    for(int i = 0; i<4; i++){
        for (int j = 0; j<4;j++){
            keychar[i*4+j] = defaultkey[i*4+j] + pinchar[j];
            AOut[i*4+j] = keychar[i*4+j];
        }        
    }

    KeyExpansion(keychar, RoundKey_Initial); //전역변수가 pointer로 들어가 조정되어 나옴
    LRes =  KEYGEN_SUCCESS;                  //try catch를 못쓰니 일단 함수가 마지막까지 진행되면 Success를 반환하게 함. 
    return LRes;
}

int Set_AccessKey_Final( unsigned char AappUuid[], unsigned char AauthUuid[], unsigned char AdeviceUuid[], unsigned char AOut[] ){    
    AES256Key keychar = {0,};
    AES128Key LAppuuid;
    AES128Key LauthUuid;
    AES128Key LdeviceUuid;

    //strcpy는 길이를 제한하는 인자가 없어 printf에서 string출력할 때와 마찬가지로 길이의 끝을 못찾는 현상이 발생. 때문에 bytescpy라는 배열 값을 넘겨주는 함수를 추가
    bytescpy(LAppuuid,AappUuid, BaseLen);
    bytescpy(LauthUuid,AauthUuid, BaseLen);
    bytescpy(LdeviceUuid,AdeviceUuid, BaseLen);
    CreateAcccessKey32AsString(LAppuuid,LauthUuid,LdeviceUuid,keychar);

    bytescpy(AOut, keychar,EncLen);
    KeyExpansion(keychar, RoundKey_Final); //전역변수가 pointer로 들어가 조정되어 나옴

    return KEYGEN_SUCCESS;
}

int Set_AccessKey_Temporar( unsigned char AappUuid[], unsigned char AauthUuid[], unsigned char AdeviceUuid[], unsigned char AOut[] ){
    AES256Key keychar = {0,};
    AES128Key LAppuuid;
    AES128Key LauthUuid;
    AES128Key LdeviceUuid;

    //strcpy는 길이를 제한하는 인자가 없어 printf에서 string출력할 때와 마찬가지로 길이의 끝을 못찾는 현상이 발생. 때문에 bytescpy라는 배열 값을 넘겨주는 함수를 추가
    bytescpy(LAppuuid,AappUuid, BaseLen);
    bytescpy(LauthUuid,AauthUuid, BaseLen);
    bytescpy(LdeviceUuid,AdeviceUuid, BaseLen);
    CreateAcccessKey32AsString(LAppuuid,LauthUuid,LdeviceUuid,keychar);

    bytescpy(AOut, keychar,EncLen);
    KeyExpansion(keychar, RoundKey_Temporary); //전역변수가 pointer로 들어가 조정되어 나옴

    printCaptionedByte("Final Key ", AOut, EncLen);
    printCaptionedByte("Round Key span by Final Key ", AOut, RoundLen);

    return KEYGEN_SUCCESS;
}


//길이 재산정을 하지 않으며, 길이가 맞지 않으면 ENCRYPT_LENGTHUNMATCH를 반환
int Encrypt_Initial(unsigned char ADecryptData[], int AInLen, unsigned char AOut[], int AOutLen){
    
    int LRes;
    if((AOutLen %BaseLen)==0) {   
        for(int i=AInLen; i<AOutLen; i++){ ADecryptData[i] = AOutLen - AInLen; } 
        Encrypt(RoundKey_Initial,ADecryptData,AOut);
        LRes = ENCRYPT_SUCCESS;
    } else {
        LRes = ENCRYPT_LENGTHUNMATCH;
    }
    return LRes;
}

int Decrypt_Initial(unsigned char AEncryptData[], int AInLen, unsigned char AOut[], int AOutLen){

    int LRes;
    int LPaddingLen;
    bool LVerify;
    if((AOutLen %BaseLen)==0) {   
        Decrypt(RoundKey_Initial,AEncryptData,AOut);
        LPaddingLen = AOut[AInLen-1]; //복호화의 경우, In과 Out의 크기가 동일. 이는 out의 크기에 맞춰 암호화가 완료되어, 모든 byte array에 무언가의 값들이 존재하기 때문
        LVerify = true;
        if (LPaddingLen > 1){                 //마지막 데이터가 0x00,0x01인 경우, 일단 패딩이 아니라 원래데이터라고 판단.
            if (LPaddingLen < AInLen ){       //마지막 데이터가 전체 길이보다 작은 경우. 마지막 데이터가 길이보다 크다면 패딩이 아니므로 해당 경우의 수 추가
                for(int i = AInLen - LPaddingLen; i<AInLen; i++ ){ //검증을 위한 반복문. padding 규칙에 따라 구간을 확인할 때, padding과 불일치하는 데이터가 나온다면, 데이터로 간주
                    if (LPaddingLen != AOut[i]){ LVerify = false; } 
                }
            }

            if(LVerify == true){ //위 패딩을 전부 만족하였을 시 
                    for(int i = AInLen - LPaddingLen; i<AInLen; i++ ){ //검증이 완료된 이후에 출력된 데이터의 패딩을 제거. 미리 제거하면 아닐경우 데이터에 손상이 간다. 
                        AOut[i] = 0x00;
                }
            }
        }
        LRes = DECRYPT_SUCCESS;
    } else {
        LRes = DECRYPT_LENGTHUNMATCH;
    }
    return LRes;
}

int Encrypt_Final(unsigned char ADecryptData[], int AInLen, unsigned char AOut[], int AOutLen){
    
    int LRes;
    if((AOutLen %BaseLen)==0) {   
        for(int i=AInLen; i<AOutLen; i++){ ADecryptData[i] = AOutLen - AInLen; } 
        Encrypt(RoundKey_Final,ADecryptData,AOut);
        LRes = ENCRYPT_SUCCESS;
    } else {
        LRes = ENCRYPT_LENGTHUNMATCH;
    }
    return LRes;
}

int Decrypt_Final(unsigned char AEncryptData[], int AInLen, unsigned char AOut[], int AOutLen){

    int LRes;
    int LPaddingLen;
    bool LVerify;
    if((AOutLen %BaseLen)==0) {   
        Decrypt(RoundKey_Final,AEncryptData,AOut);
        LPaddingLen = AOut[AInLen-1]; //복호화의 경우, In과 Out의 크기가 동일. 이는 out의 크기에 맞춰 암호화가 완료되어, 모든 byte array에 무언가의 값들이 존재하기 때문
        LVerify = true;
        if (LPaddingLen > 1){                 //마지막 데이터가 0x00,0x01인 경우, 일단 패딩이 아니라 원래데이터라고 판단.
            if (LPaddingLen < AInLen ){       //마지막 데이터가 전체 길이보다 작은 경우. 마지막 데이터가 길이보다 크다면 패딩이 아니므로 해당 경우의 수 추가
                for(int i = AInLen - LPaddingLen; i<AInLen; i++ ){ //검증을 위한 반복문. padding 규칙에 따라 구간을 확인할 때, padding과 불일치하는 데이터가 나온다면, 데이터로 간주
                    if (LPaddingLen != AOut[i]){ LVerify = false; } 
                }
            }

            if(LVerify == true){ //위 패딩을 전부 만족하였을 시 
                    for(int i = AInLen - LPaddingLen; i<AInLen; i++ ){ //검증이 완료된 이후에 출력된 데이터의 패딩을 제거. 미리 제거하면 아닐경우 데이터에 손상이 간다. 
                        AOut[i] = 0x00;
                }
            }
        }
        LRes = ENCRYPT_SUCCESS;
    } else {
        LRes = ENCRYPT_LENGTHUNMATCH;
    }
    return LRes;
}

int Encrypt_Temporary(unsigned char ADecryptData[], int AInLen, unsigned char AOut[], int AOutLen){
    
    int LRes;
    if((AOutLen %BaseLen)==0) {   
        for(int i=AInLen; i<AOutLen; i++){ ADecryptData[i] = AOutLen - AInLen; } 
        Encrypt(RoundKey_Temporary,ADecryptData,AOut);
        LRes = ENCRYPT_SUCCESS;
    } else {
        LRes = ENCRYPT_LENGTHUNMATCH;
    }
    return LRes;
}

int Decrypt_Temporary(unsigned char AEncryptData[], int AInLen, unsigned char AOut[], int AOutLen){

    int LRes;
    int LPaddingLen;
    bool LVerify;
    if((AOutLen %BaseLen)==0) {   
        Decrypt(RoundKey_Temporary,AEncryptData,AOut);
        LPaddingLen = AEncryptData[AInLen-1]; //복호화의 경우, In과 Out의 크기가 동일. 이는 out의 크기에 맞춰 암호화가 완료되어, 모든 byte array에 무언가의 값들이 존재하기 때문
        LVerify = true;
        if (LPaddingLen > 1){                 //마지막 데이터가 0x00,0x01인 경우, 일단 패딩이 아니라 원래데이터라고 판단.
            if (LPaddingLen < AInLen ){       //마지막 데이터가 전체 길이보다 작은 경우. 마지막 데이터가 길이보다 크다면 패딩이 아니므로 해당 경우의 수 추가
                for(int i = AInLen - LPaddingLen; i<AInLen; i++ ){ //검증을 위한 반복문. padding 규칙에 따라 구간을 확인할 때, padding과 불일치하는 데이터가 나온다면, 데이터로 간주
                    if (LPaddingLen != AOut[i]){ LVerify = false; } 
                }
            }

            if(LVerify == true){ //위 패딩을 전부 만족하였을 시 
                    for(int i = AInLen - LPaddingLen; i<AInLen; i++ ){ //검증이 완료된 이후에 출력된 데이터의 패딩을 제거. 미리 제거하면 아닐경우 데이터에 손상이 간다. 
                        AOut[i] = 0x00;
                }
            }
        }
        LRes = ENCRYPT_SUCCESS;
    } else {
        LRes = ENCRYPT_LENGTHUNMATCH;
    }
    return LRes;
}

int Change_AccessKey_Final(){
    for(int i=0; i<RoundLen; i++){ 
        RoundKey_Final[i] = RoundKey_Temporary[i];
    }
    bytesclear(RoundKey_Temporary, RoundLen);
    return 1;
}

int IsInAFinalAccessKey( unsigned char* unknownUuid){
}
