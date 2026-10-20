#include <stdlib.h>
#include <stdio.h>

int main(void) {
    int result = system("yara64.exe APT_Blackenergy.yar sample.exe");

    if (result == -1) {
        perror("Failed to execute YARA");
        return 1;
    }
    return 0;
}
