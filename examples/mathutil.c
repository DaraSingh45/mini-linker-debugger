#include "mathutil.h"

static int call_count;

int add(int a, int b)
{
    call_count++;
    return a + b;
}

int multiply(int a, int b)
{
    int result = 0;
    int i;
    for (i = 0; i < b; i++) {
        result = add(result, a);
    }
    return result;
}

int factorial(int n)
{
    if (n <= 1) {
        return 1;
    }
    return n * factorial(n - 1);
}

int get_call_count(void)
{
    return call_count;
}
