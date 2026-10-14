/* 
 * Educational automotive sensor module.
 * WARNING: This code is intentionally vulnerable for testing purposes only.
 */
#include "../include/sensor.h"
#include <stdlib.h>
#include <stdio.h>

Sensor* get_sensor(int id) {
    if (id < 0) return NULL;
    Sensor* s = (Sensor*)malloc(sizeof(Sensor));
    if (s) s->value = id * 10;
    return s;
}

int read_sensor_value(int id) {
    Sensor* sensor = get_sensor(id);
    
    // 1. Null pointer dereference: 'sensor' might be NULL if id < 0.
    int value = sensor->value; 
    
    // 4. Resource leak: malloc'd sensor is never freed.
    return value;
}
