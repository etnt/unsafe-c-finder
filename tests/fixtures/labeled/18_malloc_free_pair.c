#include <stdlib.h>

int calculate(void)
{
    int *value = malloc(sizeof(*value));
    if (value == NULL) {
        return -1;
    }
    *value = 42;
    int result = *value;
    free(value);
    return result;
}
