

int global_var = 7;
int c;

void function1() {
    int a;
    int b;
    b = 250;
    a = 750;
    c = b + a + global_var;
}

void function2() {
    c = c*c;
}

void function3() {
    c = global_var * 10;
}

