#ifndef _RSA_H
#define _RSA_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

#define RSA_SIEVE_LIMIT 255


/*
 * Sieve of Eratosthenes Algorithm
 * https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes
 *
 * arg0: A limit
 * arg1: The size of the generated primes list. Empty argument used as ret val
 *
 * ret:  The prime numbers that are less or equal to the limit
 */
size_t * sieve_of_eratosthenes(int, int *);


/*
 * Greatest Common Denominator
 * https://en.wikipedia.org/wiki/Greatest_common_divisor
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: the GCD
 *
 * Based on Euclid's algorithm
 */
int gcd(int , int);


/*
 * Chooses 'e' where 1 < e < fi(n) AND gcd(e, fi(n)) == 1
 *
 * arg0: fi(n)
 *
 * ret: 'e'
 */
size_t choose_e(size_t);


/*
 * Calculates the modular inverse
 * https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: modular inverse
 *
 * Based on Extended Euclidean algorithm
 *
 * da = 1 (mod b) => d = a^-1(mod b)
 * a in {2,3,...,b-1}
 */
size_t mod_inverse(size_t, size_t);


/*
 * Generates an RSA key pair and saves
 * each key in a different file
 */
void rsa_keygen(void);


/*
 * Encrypts an input file and dumps the ciphertext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void rsa_encrypt(char *, char *, char *);


/*
 * Decrypts an input file and dumps the plaintext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void rsa_decrypt(char *, char *, char *);


/*
 * This function is responsible to calculate the result = (base^exp) mod modulo
 * Furthermore, this function is used during the process of encryption and decryption
 * https://en.wikipedia.org/wiki/Modular_exponentiation
 *
 * arg0: base
 * arg1: exponent
 * arg2: modulo
 * ret: Return the result of the above formula
 *
 * Based on Right-to-left binary method
*/
size_t modular_power(size_t , size_t , size_t);


#endif /* _RSA_H */