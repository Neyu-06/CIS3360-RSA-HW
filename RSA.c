/*
Assignment:
Optional Homework - RSA Encryption/Decryption Algorithm Implementation
Author: <Quyen Le>
Language: C, C++, or Rust (only)
To Compile:
gcc -O2 -std=c99 -o RSA RSA.c -lm
g++ -O2 -std=c++17 -o RSA RSA.cpp -lm
rustc -O RSA.rs -o RSA
To Execute (on Eustis):
./RSA <keypair_file> <input_file>
where:
<keypair_file> is the path to the file containing P, Q, and E values
<input_file> is the path to the plaintext message file
Notes:
- This is an OPTIONAL homework assignment
- Implements RSA encryption and decryption in a single run
- Validates prime numbers P and Q
- Validates that E is relatively prime to phi(N)
- Calculates private key D using Extended Euclidean Algorithm
- Processes only alphanumeric characters
- Encrypts the plaintext and then decrypts it to verify
- Tested on Eustis
Class: CIS3360 - Security in Computing - Fall 2025
Instructor: Dr. Jie Lin
Due Date: Friday, November 07, 2025 at 11:59 PM ET
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_MESSAGE_SIZE 10000

long long isPrime(long long num);
long long gcd(long long a, long long b);
long long extendedEA(long long a, long long b, long long *x, long long *y);
long long modExpo(long long base, long long exp, long long mod);

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Key: %s <keypair_file> <message_file>\n", argv[0]);
        return 1;
    }

    long long P, Q, E;
    FILE *keypair_file = fopen(argv[1], "r");
    fscanf(keypair_file, "P: %lld\nQ: %lld\nE: %lld", &P, &Q, &E);
    fclose(keypair_file);
    
    // Step 1: Prime Number Validation
    printf("P:\n");
    if (!isPrime(P)) {
        printf("Error: %lld is not a prime number\n", P);
        return 1;
    }
    printf("%lld is a prime number\n\n", P);
    
    printf("Q:\n");
    if (!isPrime(Q)) {
        printf("Error: %lld is not a prime number\n", Q);
        return 1;
    }
    printf("%lld is a prime number\n\n", Q);
    
    // Step 2: Calculate N (RSA Modulus)
    long long N = P * Q;
    printf("N:\n%lld\n\n", N);
    
    // Step 3: Calculate Euler’s Totient Function φ(N )
    long long totient = (P - 1) * (Q - 1);
    printf("Totient of N:\n%lld\n\n", totient);
    
    // Step 4: Validate E (Public Exponent)
    printf("E:\n");
    if (gcd(E, totient) != 1) {
        printf("Error: %lld is not relatively prime to φ(N) = %lld\n", E, totient);
        return 1;
    }
    printf("%lld is relatively prime to %lld\n\n", E, totient);
    
    // Step 5: Calculate D (Private Exponent)
    long long x, y;
    extendedEA(E, totient, &x, &y);
    long long D = (x % totient + totient) % totient;
    printf("D:\n%lld\n\n", D);
    
    printf("Public key pair:\n(%lld, %lld)\n\n", E, N);
    printf("Private key pair:\n(%lld, %lld)\n\n", D, N);
    
    FILE *message_file = fopen(argv[2], "r");
    
    char *message = malloc(MAX_MESSAGE_SIZE);

    int len = 0;
    int letter = 0;

    while ((letter = fgetc(message_file)) != EOF) {
        message[len++] = (char)letter;
    }

    message[len] = '\0';

    fclose(message_file);

    char *plaintext = malloc(len + 1);
    int j = 0;
    
    for (int i = 0; i < len; i++) {
        if (isalnum(message[i])) {
            plaintext[j++] = message[i];
        }
    }
    plaintext[j] = '\0';

    free(message);
    
    printf("Plaintext:\n%s\n\n", plaintext);
    
    // Encrypt message
    int length = strlen(plaintext);
    long long *ciphertext = malloc(length * sizeof(long long));
    
    printf("Encrypted message:\n");
    for (int i = 0; i < length; i++) {
        long long m = (long long)plaintext[i];
        ciphertext[i] = modExpo(m, E, N);
        printf("%lld ", ciphertext[i]);
    }
    printf("\n\n");
    
    // Decrypt message
    printf("Decrypted message:\n");
    for (int i = 0; i < length; i++) {
        long long m = modExpo(ciphertext[i], D, N);
        char decrypted = (char)m;
        printf("%c ", decrypted);
    }
    printf("\n");
    
    free(plaintext);
    free(ciphertext);
    
    return 0;
}

// Function to verify primality
long long isPrime(long long num) {
    if (num <= 1) { 
        return 0;
    }

    for (long long i = 2 ; i*i <= num; i++) {
        if (num % i == 0) {
            return 0;
        }
    }
    return 1;
}

// Function to calculate GCD using Euclidean algorithm
long long gcd(long long a, long long b) {
    if (a == 0) {
        return b;
    }
    return gcd(b % a, a);
}

// Extended Euclidean Algorithm to find modular multiplicative inverse
long long extendedEA(long long a, long long b, long long *x, long long *y) {
    if (b == 0) {
        *x = 1;
        *y = 0;
        return a;
    }
    
    long long x1, y1;
    long long gcd = extendedEA(b, a % b, &x1, &y1);
    
    *x = y1;
    *y = x1 - (a / b) * y1;
    
    return gcd;
}

// Function to perform efficient modular exponentiation
long long modExpo(long long base, long long exp, long long mod) {
    long long result = 1;

    while (exp > 0) {
        if (exp % 2 == 1) {
            result = (result * base) % mod;
        }
        base = (base * base) % mod;
        exp = exp / 2;
    }
    
    return result;
}