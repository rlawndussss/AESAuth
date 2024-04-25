#include <stdio.h>

void printBytes(const unsigned char* bytes, size_t length) {
    printf("입력된 Byte Array 출력 ");
    for (size_t i = 0; i < length; ++i) {
        printf("%02x ", bytes[i]);
    }
    printf("\n");
}