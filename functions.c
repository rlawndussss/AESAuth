#include <stdio.h>

void bytescpy(unsigned char* bytes, const unsigned char* sources, size_t length){
    for (int i = 0; i<length; i++){
        bytes[i] = sources[i];
    }

}

void bytesclear(unsigned char* bytes, size_t length){
    for (int i = 0; i<length; i++){
        bytes[i] = 0;
    }

}

void printBytes(const unsigned char* bytes, size_t length) {
    printf("\r\nArray(Length : %d) -  ",length);
    for (size_t i = 0; i < length; i++) {
        printf("%02x, ", bytes[i]);        
    }
    printf("\n");
}

void printCaptionedByte(const unsigned char* caption, const unsigned char* bytes, size_t length) {
    // unsigned char* nullChar = memchr(bytes, '\0', length);
    // size_t actualLength = nullChar ? (size_t)(nullChar - bytes) : length;
    // if (length > actualLength) { length = actualLength; }
    printf("\r\n%s (Length : %d) -  ",caption, length);
    for (size_t i = 0; i < length; ++i) {
        printf("%02x, ", bytes[i]);
    }
    printf("\n");
}


void RRotateByte(unsigned char* bytes, int start, size_t length){
    unsigned char Lbyte[length];
    Lbyte[0] = bytes[start + length - 1];
    for(int i = 0; i<length-1; i++){ //마지막은 실행하고 싶지 않음. 
        Lbyte[i+1] = bytes[start+i];
    }

    for(int i = 0; i<length; i++){
        bytes[start+i] = Lbyte[i];
    }
}

void LRotateByte(unsigned char* bytes, int start, size_t length){
    unsigned char Lbyte[length];
    Lbyte[length-1] = bytes[start];
    for(int i = 0; i<length-1; i++){ //마지막은 실행하고 싶지 않음. 
        Lbyte[i] = bytes[start+i+1];
    }

    for(int i = 0; i<length; i++){
        bytes[start+i] = Lbyte[i];
    }
}

int Multiply16(int ALen){
    int LRes = ALen/BaseLen;
    if ((ALen%BaseLen) > 0){
        LRes++;
    }
    LRes = LRes*BaseLen;
    return LRes;
}