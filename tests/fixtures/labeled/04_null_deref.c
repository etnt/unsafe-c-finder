#include <stdlib.h>

struct item {
    int value;
};

int make_item(void)
{
    struct item *item = malloc(sizeof(*item));
    item->value = 42;
    return item->value;
}
