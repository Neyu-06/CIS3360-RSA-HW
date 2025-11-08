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
#include <math.h>

int isPrime(long long n);
long long gcd(long long a, long long b);
long long extended_gcd(long long a, long long b, long long *x, long long *y);
long long mod_inverse(long long e, long long phi_n);
long long mod_exp(long long base, long long exp, long long mod);
char* preprocess_message(const char *input);


int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Key: %s <keypair_file> <message_file>\n", argv[0]);
        return 1;
    }

    long long P, Q, E;
    fscanf(keypair_file, "P: %lld\nQ: %lld\nE: %lld", &P, &Q, &E);
    fclose(keypair_file);
    
    // Validate P
    printf("P:\n");
    if (!isPrime(P)) {
        printf("Error: %lld is not a prime number\n", P);
        return 1;
    }
    printf("%lld is a prime number\n\n", P);
    
    // Validate Q
    printf("Q:\n");
    if (!isPrime(Q)) {
        printf("Error: %lld is not a prime number\n", Q);
        return 1;
    }
    printf("%lld is a prime number\n\n", Q);
    
    // Calculate N
    long long N = P * Q;
    printf("N:\n%lld\n\n", N);
    
    // Calculate phi(N)
    long long phi_n = (P - 1) * (Q - 1);
    printf("Totient of N:\n%lld\n\n", phi_n);
    
    // Validate E
    printf("E:\n");
    if (gcd(E, phi_n) != 1) {
        printf("Error: %lld is not relatively prime to φ(N) = %lld\n", E, phi_n);
        return 1;
    }
    printf("%lld is relatively prime to %lld\n\n", E, phi_n);
    
    // Calculate D
    long long D = mod_inverse(E, phi_n);
    if (D == -1) {
        fprintf(stderr, "Error: Cannot calculate modular inverse\n");
        return 1;
    }
    printf("D:\n%lld\n\n", D);
    
    // Print key pairs
    printf("Public key pair:\n(%lld, %lld)\n\n", E, N);
    printf("Private key pair:\n(%lld, %lld)\n\n", D, N);
    
    // Read message file
    FILE *message_file = fopen(argv[2], "r");
    if (!message_file) {
        fprintf(stderr, "Error: Cannot open message file %s\n", argv[2]);
        return 1;
    }
    
    // Read entire file content
    fseek(message_file, 0, SEEK_END);
    long file_size = ftell(message_file);
    fseek(message_file, 0, SEEK_SET);
    
    char *message = (char*)malloc(file_size + 1);
    fread(message, 1, file_size, message_file);
    message[file_size] = '\0';
    fclose(message_file);
    
    // Preprocess message
    char *plaintext = preprocess_message(message);
    free(message);
    
    printf("Plaintext:\n%s\n\n", plaintext);
    
    // Encrypt message
    int msg_len = strlen(plaintext);
    long long *ciphertext = (long long*)malloc(msg_len * sizeof(long long));
    
    printf("Encrypted message:\n");
    for (int i = 0; i < msg_len; i++) {
        long long m = (long long)plaintext[i];
        ciphertext[i] = mod_exp(m, E, N);
        if (i > 0) printf(" ");
        printf("%lld", ciphertext[i]);
    }
    printf("\n\n");
    
    // Decrypt message
    printf("Decrypted message:\n");
    for (int i = 0; i < msg_len; i++) {
        long long m = mod_exp(ciphertext[i], D, N);
        char decrypted_char = (char)m;
        if (i > 0) printf(" ");
        printf("%c", decrypted_char);
    }
    printf("\n");
    
    // Cleanup
    free(plaintext);
    free(ciphertext);
    
    return 0;
}

// Function to check if a number is prime
int isPrime(long long n) {
    if (n <= 1) return 0;
    if (n <= 3) return 1;
    if (n % 2 == 0 || n % 3 == 0) return 0;
    
    long long sqrt_n = (long long)sqrt((double)n);
    for (long long i = 5; i <= sqrt_n; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0) return 0;
    }
    return 1;
}

// Function to calculate GCD using Euclidean algorithm
long long gcd(long long a, long long b) {
    while (b != 0) {
        long long temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

// Extended Euclidean Algorithm to find modular multiplicative inverse
long long extended_gcd(long long a, long long b, long long *x, long long *y) {
    if (b == 0) {
        *x = 1;
        *y = 0;
        return a;
    }
    
    long long x1, y1;
    long long gcd_val = extended_gcd(b, a % b, &x1, &y1);
    
    *x = y1;
    *y = x1 - (a / b) * y1;
    
    return gcd_val;
}

// Function to calculate modular multiplicative inverse
long long mod_inverse(long long e, long long phi_n) {
    long long x, y;
    long long gcd_val = extended_gcd(e, phi_n, &x, &y);
    
    if (gcd_val != 1) {
        return -1; // Inverse doesn't exist
    }
    
    // Make sure x is positive
    long long result = (x % phi_n + phi_n) % phi_n;
    return result;
}

// Efficient modular exponentiation
long long mod_exp(long long base, long long exp, long long mod) {
    long long result = 1;
    base = base % mod;
    
    while (exp > 0) {
        if (exp % 2 == 1) {
            result = (result * base) % mod;
        }
        exp = exp >> 1;
        base = (base * base) % mod;
    }
    
    return result;
}

// Function to preprocess message (keep only alphanumeric)
char* preprocess_message(const char *input) {
    int len = strlen(input);
    char *output = (char*)malloc(len + 1);
    int j = 0;
    
    for (int i = 0; i < len; i++) {
        if (isalnum(input[i])) {
            output[j++] = input[i];
        }
    }
    output[j] = '\0';
    
    return output;
}