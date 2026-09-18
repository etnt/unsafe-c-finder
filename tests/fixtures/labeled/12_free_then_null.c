#include <stdlib.h>

void release(char **value)
{
    free(*value);
    *value = NULL;
}
