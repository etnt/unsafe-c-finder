#include <stdio.h>
#include <stdlib.h>

void print_owned(char *value)
{
    free(value);
    printf("%s\n", value);
}
