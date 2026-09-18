#include <stdint.h>
#include <stdlib.h>

int *allocate_values(size_t count)
{
    if (count > SIZE_MAX / sizeof(int)) {
        return NULL;
    }
    return malloc(count * sizeof(int));
}
