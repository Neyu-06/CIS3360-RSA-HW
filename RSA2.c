#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

// Function prototypes
int is_prime(long long n);
long long gcd(long long a, long long b);
long long extended_gcd(long long a, long long b, long long *x, long long *y);
long long mod_inverse(long long e, long long phi);
long long mod_exp(long long base, long long exp, long long mod);
char* preprocess_message(const char* message);

// Check if a number is prime
int is_prime(long long n) {
    if (n <= 1) return 0;
    if (n <= 3) return 1;
    if (n % 2 == 0 || n % 3 == 0) return 0;
    
    for (long long i = 5; i * i <= n; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0)
            return 0;
    }
    return 1;
}

// Calculate GCD using Euclidean algorithm
long long gcd(long long a, long long b) {
    while (b != 0) {
        long long temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

// Extended Euclidean Algorithm
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

// Calculate modular multiplicative inverse
long long mod_inverse(long long e, long long phi) {
    long long x, y;
    long long gcd_val = extended_gcd(e, phi, &x, &y);
    
    if (gcd_val != 1) {
        return -1; // Inverse doesn't exist
    }
    
    // Make sure result is positive
    long long result = (x % phi + phi) % phi;
    return result;
}

// Modular exponentiation (efficient method to prevent overflow)
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

// Preprocess message: keep only alphanumeric characters
char* preprocess_message(const char* message) {
    int len = strlen(message);
    char* processed = (char*)malloc(len + 1);
    int j = 0;
    
    for (int i = 0; i < len; i++) {
        if (isalnum(message[i])) {
            processed[j++] = message[i];
        }
    }
    processed[j] = '\0';
    
    return processed;
}

int main(int argc, char *argv[]) {
    // Check command line arguments
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <keypair_file> <plaintext_file>\n", argv[0]);
        return 1;
    }
    
    // Read keypair file
    FILE *keypair_file = fopen(argv[1], "r");
    if (!keypair_file) {
        fprintf(stderr, "Error: Cannot open keypair file %s\n", argv[1]);
        return 1;
    }
    
    long long P, Q, E;
    char label[10];
    
    fscanf(keypair_file, "%s %lld", label, &P);
    fscanf(keypair_file, "%s %lld", label, &Q);
    fscanf(keypair_file, "%s %lld", label, &E);
    fclose(keypair_file);
    
    // Validate P
    printf("P:\n");
    if (!is_prime(P)) {
        printf("Error: %lld is not a prime number\n", P);
        return 1;
    }
    printf("%lld is a prime number\n\n", P);
    
    // Validate Q
    printf("Q:\n");
    if (!is_prime(Q)) {
        printf("Error: %lld is not a prime number\n", Q);
        return 1;
    }
    printf("%lld is a prime number\n\n", Q);
    
    // Calculate N
    long long N = P * Q;
    printf("N:\n%lld\n\n", N);
    
    // Calculate Totient of N
    long long phi_n = (P - 1) * (Q - 1);
    printf("Totient of N:\n%lld\n\n", phi_n);
    
    // Validate E
    printf("E:\n");
    if (gcd(E, phi_n) != 1) {
        printf("Error: %lld is not relatively prime to phi(N) = %lld\n", E, phi_n);
        return 1;
    }
    printf("%lld is relatively prime to %lld\n\n", E, phi_n);
    
    // Calculate D
    long long D = mod_inverse(E, phi_n);
    printf("D:\n%lld\n\n", D);
    
    // Display key pairs
    printf("Public key pair:\n(%lld, %lld)\n\n", E, N);
    printf("Private key pair:\n(%lld, %lld)\n\n", D, N);
    
    // Read plaintext file
    FILE *plaintext_file = fopen(argv[2], "r");
    if (!plaintext_file) {
        fprintf(stderr, "Error: Cannot open plaintext file %s\n", argv[2]);
        return 1;
    }
    
    // Read entire file content
    fseek(plaintext_file, 0, SEEK_END);
    long file_size = ftell(plaintext_file);
    fseek(plaintext_file, 0, SEEK_SET);
    
    char *message = (char*)malloc(file_size + 1);
    fread(message, 1, file_size, plaintext_file);
    message[file_size] = '\0';
    fclose(plaintext_file);
    
    // Preprocess message
    char *plaintext = preprocess_message(message);
    free(message);
    
    printf("Plaintext:\n%s\n\n", plaintext);
    
    // Encrypt message
    int plaintext_len = strlen(plaintext);
    long long *ciphertext = (long long*)malloc(plaintext_len * sizeof(long long));
    
    printf("Encrypted message:\n");
    for (int i = 0; i < plaintext_len; i++) {
        long long m = (long long)plaintext[i];
        ciphertext[i] = mod_exp(m, E, N);
        if (i > 0) printf(" ");
        printf("%lld", ciphertext[i]);
    }
    printf("\n\n");
    
    // Decrypt message
    printf("Decrypted message:\n");
    for (int i = 0; i < plaintext_len; i++) {
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