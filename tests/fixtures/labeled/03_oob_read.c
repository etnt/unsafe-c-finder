#include <stddef.h>

int element_at(const int *values, size_t count, size_t index)
{
    (void)count;
    return values[index];
}
