#include <stdlib.h>

void release_twice(void *value)
{
    free(value);
    free(value);
}
