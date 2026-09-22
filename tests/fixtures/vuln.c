#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

void win(void) {
    system("/bin/sh");
}

int add(int a, int b) { return a + b; }
int sub(int a, int b) { return a - b; }

void vulnerable(void) {
    char buf[64];
    printf("gimme: ");
    fflush(stdout);
    read(0, buf, 512);   // classic stack overflow
    printf("got: %s\n", buf);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    vulnerable();
    add(1, 2);
    sub(3, 4);
    return 0;
}
