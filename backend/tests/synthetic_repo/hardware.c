#include "hardware.h"
#include <stdlib.h>
#include <stdio.h>

void init_hardware(void) {
    // Resource misuse (memory leak)
    char *buffer = (char *)malloc(1024);
    if (!buffer) return;
    
    // Dangerous API (gets)
    gets(buffer);
    
    // Forgot to free(buffer) -> leak
}

void process_data(void) {
    // Invalid state handling - using resource without initialization check
    FILE *fp = fopen("config.txt", "r");
    // Missing NULL check on fp
    char c = fgetc(fp);
    fclose(fp);
}

void safe_function(int *data, int len) {
    // Safe code
    if (data == NULL || len <= 0) return;
    for (int i = 0; i < len; i++) {
        data[i] = 0;
    }
}
