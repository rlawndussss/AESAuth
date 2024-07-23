#include "CGMSEncryption.h"

//sdbiosensorcgms1의 16byte고정값에, 4자리 숫자 블록을 4byte단위 블록에 더하여 고정키를 생성
// 초기값 73 64 62 69 6f 73 65 6e 73 6f 72 63 67 6d 73 31 
// 7834 입력 시 예상되는 결과값 aa 9c 95 9d a6 ab 98 a2 aa a7 a5 97 9e a5 a6 65 
int Set_AccessKey_Initial( int A4Digit ){
    int LRes = KEYGEN_FAIL;
    unsigned char pinchar[4]  = {0,};
    AES256Key keychar = {0x73, 0x64, 0x62, 0x69, 0x6f, 0x73, 0x65, 0x6e, 0x73, 0x6f, 0x72, 0x63, 0x67, 0x6D, 0x73, 0x31,
                         0x74, 0x92, 0xA1, 0x14, 0x5D, 0x66, 0x37, 0x3E, 0x49, 0x5B, 0x45, 0x4F, 0xB3, 0x52, 0x93, 0x41};     

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
        }        
    }
    KeyExpansion(keychar, RoundKey_Initial);    //전역변수가 pointer로 들어가 조정되어 나옴
    for(int i = 0; i < BaseLen; i++){            //AOS, IOS로 변환시에 자동 초기화가 안먹히는듯함. 16~32에서 쓰레기값이 들어가, RoundKey가 가변적이 되는것을 확인함
        AccessKey_Initial[i] = keychar[i];      //앞 16자리는 고정키 입력
        AccessKey_Initial[i+BaseLen] = 0x00;    //뒤 16자리는 0으로 초기화
    }                                           //실제 데이터는 16Byte이나, 어짜피 AES-256을 사용하기에 총32Byte를 초기화. 이 부분에 들어가는 0x00들이 문제가 된다면 뒤쪽을 특정 상수로 초기화
    //이 시점에서 Final Key는 초기화 되어야 하는가? 
    //Initial Access Key가 생성이 되었다면 다음 Final Key를 생성하기 위한 단계이니 미리 초기화를 시켜두는것이 맞을까?
    //Key 생성을 중단하고 이전 통신으로 되돌아가는 경우는 없는것인가?
    //위 경우에 대해서 경우의수가 확정이 된다면 진행해야 할 듯 함. 
    LRes =  KEYGEN_SUCCESS;                     //try catch를 못쓰니 일단 함수가 마지막까지 진행되면 Success를 반환하게 함. 
    return LRes;
}

int Get_AccessKey_Initial(AES256Key AOutAccessKey){ //AccessKey_Initial에서 직접 가져오는것과 같으나, C++ 변환시 계층화 시킬것을 감안한다면 이 함수는 필요함 
    for(int i = 0; i< EncLen; i++){                 //그러나 Access Key를 초기화한 적이 없기때믄에 최초 1회 생성후에는 항상 존재하게 됨. 
        AOutAccessKey[i] = AccessKey_Initial[i];    //Final Key를 생성하면 이를 초기화하게끔 하거나 해야 함
    }
    return KEYGEN_SUCCESS;
}

bool IsExist_AccessKey_Initial(){   // 0x73 + 0x30~0x3A 사이의 값이 되므로 Access Key는 사용중이라면 값이 존재한다는것을 보장받은채로 진행. 이는 16byte전체가 해당된다
    bool LRes = true;               // 보장받는 16자리 내에서는 0이 되는값이 존재한다면 Key가 손상 또는 존재하지 않는것으로 판단. 
    for(int i = 0; i< BaseLen; i++){
        if(AccessKey_Initial[i] == 0){
            LRes = false;
        }
    }
    return LRes;
}

int Init_AccessKey_Initial(){
    for(int i = 0; i<EncLen; i++){ AccessKey_Initial[i] = 0x00; }
    for(int i = 0; i<RoundLen; i++){ RoundKey_Initial[i] = 0x00; }
    return KEYGEN_SUCCESS;
}


int Set_AccessKey_Final(AES128Key AappUuid, AES128Key AauthUuid, AES128Key AdeviceUuid){    
    AES256Key keychar = {0,};
    AES128Key LAppuuid;
    AES128Key LauthUuid;
    AES128Key LdeviceUuid;

    //strcpy는 길이를 제한하는 인자가 없어 printf에서 string출력할 때와 마찬가지로 길이의 끝을 못찾는 현상이 발생. 때문에 bytescpy라는 배열 값을 넘겨주는 함수를 추가
    bytescpy(LAppuuid,AappUuid, BaseLen);
    bytescpy(LauthUuid,AauthUuid, BaseLen);
    bytescpy(LdeviceUuid,AdeviceUuid, BaseLen);
    CreateAcccessKey32AsString(LAppuuid,LauthUuid,LdeviceUuid,keychar);
    KeyExpansion(keychar, RoundKey_Final); //전역변수가 pointer로 들어가 조정되어 나옴
    for(int i = 0; i < EncLen; i++){ AccessKey_Final[i] = keychar[i]; }
    //Initial의 경우와는 반대로 
    return KEYGEN_SUCCESS;
}

int Get_AccessKey_Final(AES256Key AOutAccessKey){   //그러고보니 배열이라도 지정된 타입이면 고정된 크기를 반환하는건데 Get/Set에 맞게 AES256Key를 반환하게 하는것은 어떨까? 
    for(int i = 0; i< EncLen; i++){                 
        AOutAccessKey[i] = AccessKey_Final[i];   
    }
    return KEYGEN_SUCCESS;
}

int Init_AccessKey_Final(){
    for(int i = 0; i<EncLen; i++){ AccessKey_Final[i] = 0x00; }
    for(int i = 0; i<RoundLen; i++){ RoundKey_Final[i] = 0x00; }
    return KEYGEN_SUCCESS;
}

bool IsExist_AccessKey_Final(){
    bool LRes = false;              //여기서는 반대로 0이 아닌값이 존재한다면 값이 존재하는것으로 판단. 0이 안된다는것이 보장이 되지 않으니 이 부분에서는 좀 더 빈약할 수 밖에 없음               
    for(int i = 0; i< EncLen; i++){ //애초에 전역으로 선언했기에 AccessKey_Final == nullptr같은것은 항상 true를 반환한다. 
        if(AccessKey_Final[i] != 0){
            LRes = true;
        }
    }
    return LRes;
}


int Set_AccessKey_Temporary(AES128Key AappUuid, AES128Key AauthUuid, AES128Key AdeviceUuid){
    AES256Key keychar = {0,};
    AES128Key LAppuuid;
    AES128Key LauthUuid;
    AES128Key LdeviceUuid;

    //strcpy는 길이를 제한하는 인자가 없어 printf에서 string출력할 때와 마찬가지로 길이의 끝을 못찾는 현상이 발생. 때문에 bytescpy라는 배열 값을 넘겨주는 함수를 추가
    bytescpy(LAppuuid,AappUuid, BaseLen);
    bytescpy(LauthUuid,AauthUuid, BaseLen);
    bytescpy(LdeviceUuid,AdeviceUuid, BaseLen);
    CreateAcccessKey32AsString(LAppuuid,LauthUuid,LdeviceUuid,keychar);
    KeyExpansion(keychar, RoundKey_Temporary); //전역변수가 pointer로 들어가 조정되어 나옴
    for(int i = 0; i < EncLen; i++){         
        AccessKey_Temporary[i] = keychar[i];     
    }    
    return KEYGEN_SUCCESS;
}

int Get_AccessKey_Temporary(AES256Key AOutAccessKey){
    for(int i = 0; i< EncLen; i++){                 
        AOutAccessKey[i] = AccessKey_Temporary[i];   
    }
    return KEYGEN_SUCCESS;
}

int Init_AccessKey_Temporary(){
    for(int i = 0; i<EncLen; i++){ AccessKey_Temporary[i] = 0x00; }
    for(int i = 0; i<RoundLen; i++){ RoundKey_Temporary[i] = 0x00; }
    return KEYGEN_SUCCESS;
}


//길이 재산정을 하지 않으며, 길이가 맞지 않으면 ENCRYPT_LENGTHUNMATCH를 반환
int Encrypt_Initial(unsigned char ADecryptData[], int AInLen, unsigned char AOut[], int AOutLen){    
    int LRes;
    int LInLen = AInLen + 1;
    unsigned char LDecryptData[AOutLen];

    if(IsExist_AccessKey_Initial()){
        if((AOutLen %BaseLen)==0) {               
            LDecryptData[0] = AOutLen - LInLen;
            for(int i=0; i<AInLen; i++){LDecryptData[i+1] = ADecryptData[i];}
            for(int i=LInLen; i<AOutLen; i++){ LDecryptData[i] = AOutLen - LInLen; } 
            Encrypt(RoundKey_Initial,LDecryptData,AOut, AOutLen);
            LRes = ENCRYPT_SUCCESS;
        } else {
            LRes = ENCRYPT_LENGTHUNMATCH;
        }
    } else {
        LRes = ENCRYPT_FAIL;
    }
    return LRes;
}

int Decrypt_Initial(unsigned char AEncryptData[], int AInLen, unsigned char AOut[], int *AOutLen){

    int LRes;
    int LPaddingLen;
    bool LVerify;
    unsigned char LOut[AInLen];
    if(IsExist_AccessKey_Initial()){
        if((AInLen %BaseLen)==0) {   
            Decrypt(RoundKey_Initial,AEncryptData,LOut, AInLen);
            LPaddingLen = LOut[0];              //최초값은 Padding 길이를 담고 있음. 
            *AOutLen = AInLen-LPaddingLen-1;    //때문에 padding값 이외에 1을 더 차감. 16byte일 경우에도 차감하는데, 이는 이런 경우는 원래 데이터 길이는 15이기 때문
            LVerify = true;
            if (LPaddingLen > 0){                 //마지막 데이터가 0x00인 경우, 일단 패딩이 아니라 원래데이터라고 판단.
                if (LPaddingLen < AInLen ){       //마지막 데이터가 전체 길이보다 작은 경우. 마지막 데이터가 길이보다 크다면 패딩이 아니므로 해당 경우의 수 추가
                    for(int i = AInLen - LPaddingLen; i<AInLen; i++ ){ //검증을 위한 반복문. padding 규칙에 따라 구간을 확인할 때, padding과 불일치하는 데이터가 나온다면, 데이터로 간주
                        if (LPaddingLen != LOut[i]){ LVerify = false; } 
                    }
                    if(LVerify == true){ //위 패딩을 전부 만족하였을 시 
                            for(int i = AInLen - LPaddingLen; i<AInLen; i++ ){ //검증이 완료된 이후에 출력된 데이터의 패딩을 제거. 미리 제거하면 아닐경우 데이터에 손상이 간다. 
                                LOut[i] = 0x00;
                        }
                        // *AOutLen = AInLen - LPaddingLen;//길이 재조정
                    }
                }
            } 
            // else
            // if (LPaddingLen == 0){
            //     *AOutLen = strlen(AOut);
            // }
            bytesclear(AOut,AInLen);
            for(int i = 0; i < AInLen-1; i++){
                AOut[i] = LOut[i+1];
            }

            LRes = DECRYPT_SUCCESS;
        } else {
            LRes = DECRYPT_LENGTHUNMATCH;
        }
    } else {
        LRes = DECRYPT_FAIL;
    }
    return LRes;
}

int Encrypt_Final(unsigned char ADecryptData[], int AInLen, unsigned char AOut[], int AOutLen){
    int LRes;
    int LInLen = AInLen + 1;
    unsigned char LDecryptData[AOutLen];

    if(IsExist_AccessKey_Initial()){
        if((AOutLen %BaseLen)==0) {               
            LDecryptData[0] = AOutLen - LInLen;
            for(int i=0; i<AInLen; i++){LDecryptData[i+1] = ADecryptData[i];}
            for(int i=LInLen; i<AOutLen; i++){ LDecryptData[i] = AOutLen - LInLen; } 
            Encrypt(RoundKey_Final,LDecryptData,AOut, AOutLen);
            LRes = ENCRYPT_SUCCESS;
        } else {
            LRes = ENCRYPT_LENGTHUNMATCH;
        }
    } else {
        LRes = ENCRYPT_FAIL;
    }
    return LRes;
}


int Decrypt_Final(unsigned char AEncryptData[], int AInLen, unsigned char AOut[], int *AOutLen){

    int LRes;
    int LPaddingLen;
    bool LVerify;
    unsigned char LOut[AInLen];
    if(IsExist_AccessKey_Initial()){
        if((AInLen %BaseLen)==0) {   
            Decrypt(RoundKey_Final,AEncryptData,LOut, AInLen);
            LPaddingLen = LOut[0];              //최초값은 Padding 길이를 담고 있음. 
            *AOutLen = AInLen-LPaddingLen-1;    //때문에 padding값 이외에 1을 더 차감. 16byte일 경우에도 차감하는데, 이는 이런 경우는 원래 데이터 길이는 15이기 때문
            LVerify = true;
            if (LPaddingLen > 0){                 //마지막 데이터가 0x00인 경우, 일단 패딩이 아니라 원래데이터라고 판단.
                if (LPaddingLen < AInLen ){       //마지막 데이터가 전체 길이보다 작은 경우. 마지막 데이터가 길이보다 크다면 패딩이 아니므로 해당 경우의 수 추가
                    for(int i = AInLen - LPaddingLen; i<AInLen; i++ ){ //검증을 위한 반복문. padding 규칙에 따라 구간을 확인할 때, padding과 불일치하는 데이터가 나온다면, 데이터로 간주
                        if (LPaddingLen != LOut[i]){ LVerify = false; } 
                    }
                    if(LVerify == true){ //위 패딩을 전부 만족하였을 시 
                            for(int i = AInLen - LPaddingLen; i<AInLen; i++ ){ //검증이 완료된 이후에 출력된 데이터의 패딩을 제거. 미리 제거하면 아닐경우 데이터에 손상이 간다. 
                                LOut[i] = 0x00;
                        }
                        // *AOutLen = AInLen - LPaddingLen;//길이 재조정
                    }
                }
            } 
            // else
            // if (LPaddingLen == 0){
            //     *AOutLen = strlen(AOut);
            // }
            bytesclear(AOut,AInLen);
            for(int i = 0; i < AInLen-1; i++){
                AOut[i] = LOut[i+1];
            }

            LRes = DECRYPT_SUCCESS;
        } else {
            LRes = DECRYPT_LENGTHUNMATCH;
        }
    } else {
        LRes = DECRYPT_FAIL;
    }
    return LRes;
}

int Encrypt_Temporary(unsigned char ADecryptData[], int AInLen, unsigned char AOut[], int AOutLen){
    int LRes;
    int LInLen = AInLen + 1;
    unsigned char LDecryptData[AOutLen];

    if(IsExist_AccessKey_Initial()){
        if((AOutLen %BaseLen)==0) {               
            LDecryptData[0] = AOutLen - LInLen;
            for(int i=0; i<AInLen; i++){LDecryptData[i+1] = ADecryptData[i];}
            for(int i=LInLen; i<AOutLen; i++){ LDecryptData[i] = AOutLen - LInLen; } 
            Encrypt(RoundKey_Temporary,LDecryptData,AOut, AOutLen);
            LRes = ENCRYPT_SUCCESS;
        } else {
            LRes = ENCRYPT_LENGTHUNMATCH;
        }
    } else {
        LRes = ENCRYPT_FAIL;
    }
    return LRes;
}


int Decrypt_Temporary(unsigned char AEncryptData[], int AInLen, unsigned char AOut[], int *AOutLen){ //Temporary로는 실제로 통신을 하는 구간이 없으나 만약을 대비해 만든것으로 알고 있음

    int LRes;
    int LPaddingLen;
    bool LVerify;
    unsigned char LOut[AInLen];
    if(IsExist_AccessKey_Initial()){
        if((AInLen %BaseLen)==0) {   
            Decrypt(RoundKey_Temporary,AEncryptData,LOut, AInLen);
            LPaddingLen = LOut[0];              //최초값은 Padding 길이를 담고 있음. 
            *AOutLen = AInLen-LPaddingLen-1;    //때문에 padding값 이외에 1을 더 차감. 16byte일 경우에도 차감하는데, 이는 이런 경우는 원래 데이터 길이는 15이기 때문
            LVerify = true;
            if (LPaddingLen > 0){                 //마지막 데이터가 0x00인 경우, 일단 패딩이 아니라 원래데이터라고 판단.
                if (LPaddingLen < AInLen ){       //마지막 데이터가 전체 길이보다 작은 경우. 마지막 데이터가 길이보다 크다면 패딩이 아니므로 해당 경우의 수 추가
                    for(int i = AInLen - LPaddingLen; i<AInLen; i++ ){ //검증을 위한 반복문. padding 규칙에 따라 구간을 확인할 때, padding과 불일치하는 데이터가 나온다면, 데이터로 간주
                        if (LPaddingLen != LOut[i]){ LVerify = false; } 
                    }
                    if(LVerify == true){ //위 패딩을 전부 만족하였을 시 
                            for(int i = AInLen - LPaddingLen; i<AInLen; i++ ){ //검증이 완료된 이후에 출력된 데이터의 패딩을 제거. 미리 제거하면 아닐경우 데이터에 손상이 간다. 
                                LOut[i] = 0x00;
                        }
                        // *AOutLen = AInLen - LPaddingLen;//길이 재조정
                    }
                }
            } 
            // else
            // if (LPaddingLen == 0){
            //     *AOutLen = strlen(AOut);
            // }
            bytesclear(AOut,AInLen);
            for(int i = 0; i < AInLen-1; i++){
                AOut[i] = LOut[i+1];
            }

            LRes = DECRYPT_SUCCESS;
        } else {
            LRes = DECRYPT_LENGTHUNMATCH;
        }
    } else {
        LRes = DECRYPT_FAIL;
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
