#include <stdlib.h>

struct item {
    int value;
};

int make_item(void)
{
    struct item *item = malloc(sizeof(*item));
    if (item == NULL) {
        return -1;
    }
    item->value = 42;
    free(item);
    return 0;
}
