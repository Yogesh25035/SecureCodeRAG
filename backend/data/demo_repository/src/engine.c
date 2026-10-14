/* 
 * Educational automotive engine module.
 * WARNING: This code is intentionally vulnerable for testing purposes only. 
 * Do NOT use in production.
 */
#include "../include/engine.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void calculate_speed(int index) {
    int buffer[10] = {0};
    
    // 2. Array boundary issue: 'index' is not validated before array access.
    buffer[index] = 50; 
    
    printf("Speed calculated: %d\n", buffer[index]);
}

void log_engine_status(const char* status) {
    char log_buffer[50];
    
    // 3. Unsafe string operation: strcpy without length check.
    strcpy(log_buffer, status); 
    
    printf("Engine Status: %s\n", log_buffer);
}
