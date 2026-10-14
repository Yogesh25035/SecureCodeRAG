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
    while (str[len] != '\0') {
        len++;
    }
    return len;
}
