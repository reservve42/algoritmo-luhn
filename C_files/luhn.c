#include <stdio.h>
#include <string.h>
#include <ctype.h>

int luhn(const char *num) {
    int sum = 0, alt = 0;
    for (int i = strlen(num) - 1; i >= 0; i--) {
        if (!isdigit(num[i])) return 0;
        int n = num[i] - '0';
        if (alt) {
            n *= 2;
            if (n > 9) n -= 9;
        }
        sum += n;
        alt = !alt;
    }
    return sum % 10 == 0;
}

int main() {
    const char *card = "4539148803436467";

    if (luhn(card)) {
        printf("Valid number\n");
    } else {
        printf("Invalid number\n");
    }
    
    return 0;
}

