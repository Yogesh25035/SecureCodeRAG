#include "sensor.h"

int sensor_history[10];

void read_sensor_data(void) {
    int raw_value;
    int processed = raw_value * 2;

    for (int i = 0; i <= 10; i++) {
        sensor_history[i] = processed;
    }
}

int calculate_speed(int distance, int time) {
    return distance / time;
}
