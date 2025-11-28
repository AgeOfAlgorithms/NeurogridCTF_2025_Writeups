#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    // Try to open the flag file directly (SUID will handle permissions)
    FILE *file = fopen("/root/flag.txt", "r");
    if (file != NULL) {
        char buffer[256];
        if (fgets(buffer, sizeof(buffer), file) != NULL) {
            printf("Flag: %s", buffer);
        } else {
            printf("Error: Could not read flag content\n");
        }
        fclose(file);
    } else {
        printf("Error: Could not open /root/flag.txt\n");
    }
    
    return 0;
}

