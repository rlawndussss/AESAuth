#ifndef CGMSENCRYPTION_H
#define CGMSENCRYPTION_H

#define KEYGEN_SUCCESS = 1
#define KEYGEN_FAIL = 0

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include "AESEncryption.h"
#include "AESEncryption.c"

unsigned char RoundKey[240];


int SetInitialAccessKey( int inputPincode );
int SetFinalAccessKey( unsigned char appUuid[], unsigned char authUuid[], unsigned char deviceUuid[] );

unsigned char* ByteDataEncrypt(unsigned char DecryptData[], int length);
unsigned char* ByteDataDecrypt(unsigned char EncryptData[], int length);

int IsInAFinalAccessKey( unsigned char unknownUuid[]);


#endif
