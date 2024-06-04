/*
© 2024 Nokia
Licensed under the BSD 3-Clause Clear License
SPDX-License-Identifier: BSD-3-Clause-Clear
*/

#define lowercaseuuid true

static bool EnableVerbosePrintf = false;

#define TRACE_ENCLAVE(fmt, ...) \
    printf("Enclave: ***%s(%d): " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)

void myprintf(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    if (EnableVerbosePrintf){
      printf(format, ap);
    }
    va_end(ap);
}

void printHex(uint8_t* buffer, int size, const char* name)
{
    printf("Server: %s: 0x", name);
    for (uint32_t i = 0; i < size; i++)
    {
        printf("%02x", buffer[i]);
    }
    printf("\n");
}

void printString(uint8_t* buffer, int size, const char* name)
{
    printf("Server: %s: ", name);
    for (uint32_t i = 0; i < size; i++)
    {
        printf("%c", buffer[i]);
    }
    printf("\n");
}
