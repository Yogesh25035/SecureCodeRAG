import os

base_dir = "backend/tests/synthetic_repo"
os.makedirs(base_dir, exist_ok=True)

files = {
    "utils.h": """
#ifndef UTILS_H
#define UTILS_H

void copy_name(char *dest, const char *src);
void unsafe_concat(char *str1, const char *str2);
int get_length(const char *str);

#endif
""",
    "utils.c": """
#include "utils.h"
#include <string.h>
#include <stdio.h>

void copy_name(char *dest, const char *src) {
    // Unsafe string operation (strcpy)
    strcpy(dest, src);
}

void unsafe_concat(char *str1, const char *str2) {
    // Buffer overflow potential (strcat)
    strcat(str1, str2);
}

int get_length(const char *str) {
    // NULL pointer dereference (if str is NULL)
    int len = 0;
    while (str[len] != '\\0') {
        len++;
    }
    return len;
}
""",
    "sensor.h": """
#ifndef SENSOR_H
#define SENSOR_H

void read_sensor_data(void);
int calculate_speed(int distance, int time);

#endif
""",
    "sensor.c": """
#include "sensor.h"

int sensor_history[10];

void read_sensor_data(void) {
    // Uninitialized variable
    int raw_value;
    int processed = raw_value * 2;
    
    // Array boundary violation (out of bounds)
    for (int i = 0; i <= 10; i++) {
        sensor_history[i] = processed;
    }
}

int calculate_speed(int distance, int time) {
    // Integer overflow / division by zero potential if not checked
    return distance / time;
}
""",
    "hardware.h": """
#ifndef HARDWARE_H
#define HARDWARE_H

void init_hardware(void);
void process_data(void);
void safe_function(int *data, int len);

#endif
""",
    "hardware.c": """
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
""",
    "main.c": """
#include "utils.h"
#include "sensor.h"
#include "hardware.h"
#include <stdio.h>

int main() {
    // Multiple vulnerabilities
    char buffer[10];
    
    // Cross-file dependency vulnerability
    copy_name(buffer, "This is a very long string that will overflow the buffer");
    
    read_sensor_data();
    init_hardware();
    
    return 0;
}
"""
}

for name, content in files.items():
    with open(os.path.join(base_dir, name), "w", encoding="utf-8") as f:
        f.write(content.strip() + "\n")

print(f"Created synthetic repo at {base_dir}")
