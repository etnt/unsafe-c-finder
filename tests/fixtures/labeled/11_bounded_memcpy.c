#include <string.h>

void copy_name(void)
{
    char destination[16];
    const char source[] = "safe";
    memcpy(destination, source, sizeof(source));
}
