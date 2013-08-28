#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <sqlite3.h>
#include <time.h>

#include "su.h"

policy_t database_check(struct su_context *ctx) {
    return ALLOW;
}
