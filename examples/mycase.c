   #include "syscalls.h"

   int sum_to(int n)
   {
       int total = 0;
       int i;
       for (i = 1; i <= n; i++) {
           total += i;
       }
       return total;
   }

   int main(void)
   {
       int n = 10;
       int result = sum_to(n);
       write_label_int("sum = ", result);
       return 0;
   }
