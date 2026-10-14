#ifndef SENSOR_H
#define SENSOR_H

typedef struct {
    int value;
} Sensor;

Sensor* get_sensor(int id);
int read_sensor_value(int id);

#endif
