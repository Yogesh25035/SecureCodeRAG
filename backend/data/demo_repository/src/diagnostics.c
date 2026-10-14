/* 
 * Educational automotive memory & diagnostics module.
 * WARNING: This code is intentionally vulnerable for testing purposes only.
 */
#include <stdio.h>

void process_diagnostic_code(long code) {
    // 5. Integer conversion issue: Implicit downcast from long to short without bounds check.
    short small_code = (short)code; 
    
    printf("Processing code: %d\n", small_code);
}

void handle_state(int state) {
    int uninitialized_var;
    
    // 6. Missing validation: state is not checked against valid enum ranges.
    if (state == 1) {
        uninitialized_var = 100;
    }
    
    // 7. State handling / Uninitialized variable: Used without guaranteed initialization.
    printf("State value: %d\n", uninitialized_var);
}
