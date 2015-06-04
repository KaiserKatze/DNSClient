#include "data.h"

#include <stdlib.h>
#include <string.h>

#define MAGIC   31

struct String *
createString(int len)
{
    struct String *res;

    if (len <= 0)
        return (struct String *) 0;
    res = (struct String *) malloc(sizeof (struct String) +len);
    res->hash = 0;
    res->len = len;
    bzero(res->str, len);

    return res;
}

void
releaseString(struct String * str)
{
    free(str);
}

unsigned int
hashCode(struct String * str)
{
    int i;

    if (!str)
        return 0;
    if (!str->hash)
        for (i = 0; i < str->len; i++)
            str->hash = MAGIC * str->hash + str->str[i];

    return str->hash;
}


