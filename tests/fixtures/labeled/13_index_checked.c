#include <stddef.h>

int element_at(const int *values, size_t count, size_t index, int *output)
{
    if (index >= count) {
        return -1;
    }
    *output = values[index];
    return 0;
}
