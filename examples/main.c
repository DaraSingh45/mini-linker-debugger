#include "mathutil.h"
#include "syscalls.h"

int global_counter = 100;          /* .data   */
int uninitialized_counter;         /* .bss    */
const char banner[] = "== mini-linker demo ==\n";          /* .rodata */
const char *greeting = "Hello from a program linked by mylink!\n";

typedef int (*binop)(int, int);
binop operations[] = { add, multiply };     /* .data with R_X86_64_64 relocations */

int main(void)
{
    int a = 6;
    int b = 7;
    int sum;
    int product;
    int fact;

    write_str(banner);
    write_str(greeting);

    sum = operations[0](a, b);
    product = operations[1](a, b);
    fact = factorial(5);

    global_counter += product;
    uninitialized_counter = sum;

    write_label_int("sum = ", sum);
    write_label_int("product = ", product);
    write_label_int("factorial(5) = ", fact);
    write_label_int("global_counter = ", global_counter);
    write_label_int("add() calls = ", get_call_count());

    if (sum == 13 && product == 42 && fact == 120 &&
        global_counter == 142 && uninitialized_counter == 13)
        return 0;
    return 1;
}
