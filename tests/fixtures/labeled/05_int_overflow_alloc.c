#include <stddef.h>
#include <stdlib.h>

int *allocate_values(size_t count)
{
    return malloc(count * sizeof(int));
}
