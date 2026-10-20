#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#define SHA256_BLOCK_SIZE 32 // 256 bits = 32 bytes

int main(int argc, char *argv[]) {
    // 1. Validate that the user provided exactly one argument
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <number_of_hashes>\n", argv[0]);
        fprintf(stderr, "Example: %s 100\n", argv[0]);
        return 1;
    }

    // 2. Convert the argument string to an integer
    int n = atoi(argv[1]);

    // 3. Ensure N is a valid positive number
    if (n <= 0) {
        fprintf(stderr, "Error: The number of hashes must be a positive integer greater than 0.\n");
        return 1;
    }

    char filename[32];
	snprintf(filename, sizeof(filename), "hashes-%d.bin", n);

    // Seed the random number generator using the current system time
    srand((unsigned int)time(NULL));

    // Allocate memory for N random 32-byte blocks (N * 32 bytes)
    uint8_t (*hash_array)[SHA256_BLOCK_SIZE] = malloc(n * SHA256_BLOCK_SIZE);
    if (hash_array == NULL) {
        perror("Failed to allocate memory");
        return 1;
    }

    printf("Generating %d randomized 256-bit byte blocks...\n", n);

    // Populate the array with random byte streams
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < SHA256_BLOCK_SIZE; j++) {
            hash_array[i][j] = (uint8_t)(rand() % 256);
        }
    }

    // Open the output file in binary-write mode
    FILE *file = fopen(filename, "wb");
    if (file == NULL) {
        perror("Error opening file");
        free(hash_array);
        return 1;
    }

    // Write the entire sequential memory array into the file at once
    size_t written = fwrite(hash_array, SHA256_BLOCK_SIZE, n, file);
    fclose(file);

    if ((int)written == n) {
        printf("Successfully wrote %d pseudo-hashes (%zu bytes) to '%s'.\n", n, n * SHA256_BLOCK_SIZE, filename);
    } else {
        printf("Error: Only wrote %zu elements out of %d requested.\n", written, n);
    }

    free(hash_array);
    return 0;
}

