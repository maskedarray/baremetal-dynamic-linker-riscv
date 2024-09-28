#include "dummyheader.h"



int global_var = 7;
int global_var2 = 7;
int c;
extern char _sbss;  /* Start of .bss section */
int complexFunction1() {
    int a;
    int b;
    int sum;
    // b = &_sbss;
    b = 250;
    a = 750;
    
    // Introducing a calculation that simulates a more complex operation
    sum = b + a + global_var + global_var2;
    
    // Adding a check to modify the sum based on certain conditions
    if (sum > 1000) {
        sum -= 100; // Deducting a value if the sum exceeds a threshold
    } else if (sum < 500) {
        sum += 50; // Adding a value if the sum is below a threshold
    }
    
    // Assigning the calculated value to global variable 'c'
    c = sum;
    return sum;
}

int complexFunction2() {
    // Performing a more intricate calculation involving the global variable and 'c'
    int temp = c;
    c = (temp * temp) + (global_var * 5);
    
    // Adding a modular operation to change 'c' based on its value
    if (c % 2 == 0) {
        c /= 2; // Halve 'c' if it's even
    } else {
        c = c * 3 + 1; // Modify 'c' differently if it's odd
    }
    return c;
}

int complexFunction3() {
    // Adjusting 'c' based on the global variable and introducing an intermediate step
    c = global_var * 10;
    
    // Calling another function to modify 'c' further
    complexFunction1();
    
    // Performing additional operations on 'c'
    c += global_var * 2; // Incrementing 'c' based on another multiple of the global variable
    c = (c > 1000) ? c / 2 : c * 2; // Conditional operation based on 'c' value
    return c;
}

int complexFunction4() {
    // Introducing a recursive element to increase complexity
    if (c < 10000) {
        c += global_var*200;    //c += 1400 
        complexFunction4(); // Recursive call to deepen the function's complexity
    }
    return c;
}
void complexFunction6();
void complexFunction5() {
    // Finalizing the operations with another layer of complexity
    int original_c = c;
    
    // Creating a more intricate relation between 'c' and the global variable
    c = (original_c % global_var == 0) ? original_c * 3 : original_c - global_var;
    
    // Performing a range check and adjusting 'c' accordingly
    if (c > 2000) {
        c -= 500; // Reduce 'c' if it exceeds a certain limit
    }
    complexFunction6();
}
