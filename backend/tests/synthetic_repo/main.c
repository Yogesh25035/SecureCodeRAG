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
