#include <stdlib.h>

void process_many(size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        int *value = malloc(sizeof(*value));
        if (value) {
            *value = (int)i;
        }
    }
}
