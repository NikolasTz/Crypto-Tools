#include "rsa.h"
#include "utils.h"

/*
 * Sieve of Eratosthenes Algorithm
 * https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes
 *
 * arg0: A limit
 * arg1: The size of the generated primes list. Empty argument used as ret val
 *
 * ret:  The prime numbers that are less or equal to the limit
 */
size_t* sieve_of_eratosthenes(int limit, int *primes_sz){
	
	size_t *primes;
	size_t *candidate_primes = (size_t*)malloc(sizeof(size_t)*(limit-1));

	// 1-true corresponding to prime number
	// 0-false corresponding to not a prime number
	
	// Initialized all candidate primes as primes
	for(int k=0;k<limit-1;k++){ *(candidate_primes+k) = 1; }

	// If i not exceeding √limit then repeat 
	for(int i=2;i*i<=(int)limit;i++){

		// If *(candidate_primes+i-2) is not changed, then it is a prime 
		if( *(candidate_primes+i-2) == 1){

			// Update all multiples of *(candidate_primes+i-2) greater than or equal to the square of it
			// Numbers which are multiple of *(candidate_primes+i-2) and are less than *(candidate_primes+i-2)^2 are already been marked
			for(int j=i*i;j<=limit;j=j+i){
				*(candidate_primes+j-2) = 0; // Check as marked that is not prime
			}
		}
	}

	// Calculate the size of generated primes list in case of the variable primes_sz is not null
	if(primes_sz != NULL){
		for(int i=2;i<=limit;i++){
			if(*(candidate_primes+i-2) == 1){ *primes_sz = *primes_sz+1; }
		}
	}

	// Retrun the generated list of primes
	int pos=0;
	primes = (size_t*)malloc(sizeof(size_t)*(*primes_sz));
	for(int i=2;i<=limit;i++){
		if( *(candidate_primes+i-2) == 1){
			*(primes+pos) = i; 
			pos++; 
		}
	}

	return primes;
}


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
int gcd(int a, int b){
	if(a == 0){ return b; }
	return gcd(b%a,a);
}


/*
 * Chooses 'e' where 1 < e < fi(n) AND gcd(e, fi(n)) == 1
 *
 * arg0: fi(n)
 *
 * ret: 'e'
 */
size_t choose_e(size_t fi_n){

	size_t e;

	// Generate the primes until the value of fi_n
	int prime_sz = 0;
	size_t* primes = sieve_of_eratosthenes(fi_n,&prime_sz);

	// Find the e
	for(int i=0;i<prime_sz;i++){
		e = *(primes+i);
		if((e < fi_n) && (gcd(e,fi_n)==1)){ break;}
	}

	free(primes);
	return e;
}


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
size_t mod_inverse(size_t a, size_t b) {

	size_t t = 0;
	size_t r = b;
	size_t new_t = 1;
	size_t new_r = a;
	size_t quotient;
	size_t tmp;

	while(new_r != 0){

		quotient = r / new_r;

		tmp = new_t;
		new_t = t-(quotient*new_t);
		t = tmp;
		
		tmp = new_r;
		new_r = r-(quotient*new_r);
		r = tmp;
	}

	if((int)t < 0){ t = t+b; }

	return t;
}


/*
 * Generates an RSA key pair and saves
 * each key in a different file
 */
void rsa_keygen(void){

	// Generate the primes until the value of RSA_SIEVE_LIMIT
	int prime_sz = 0;
	size_t* primes = sieve_of_eratosthenes(RSA_SIEVE_LIMIT,&prime_sz);

	// Initialize the variables
	size_t p = 0;
	size_t q = 0;
	size_t n = 0;
	size_t fi_n = 0;
	size_t e = 0;
	size_t d = 0;


	// Pick two distinct prime numbers
	// Use current time as seed for random generator 
    srand(time(0)); 

    do{
    	p = (rand() % (prime_sz));
    	q = (rand() % (prime_sz));
    }while(p==q);	

    p = *(primes+p);
    q = *(primes+q);


    // Clean up the primes
    free(primes);

    // Compute n
    n = p*q;

	// Calculate the fi(n)(using Euler’s totient function)
	fi_n = (p-1)*(q-1);

	// Compute the e
	e = choose_e(fi_n);

	// Compute the d
	d = mod_inverse(e,fi_n);

	// Write the public key
	FILE *fp = fopen("public.key","w");
	if( fp == NULL) { fprintf(stderr,"%s","File does not exist!!!\n"); abort(); }
	fwrite(&n,sizeof(size_t),1,fp);
	fwrite(&d,sizeof(size_t),1,fp);

	// Write the private key
	fp = fopen("private.key","w");
	if( fp == NULL) { fprintf(stderr,"%s","File does not exist!!!\n"); abort(); }
	fwrite(&n,sizeof(size_t),1,fp);
	fwrite(&e,sizeof(size_t),1,fp);

	fclose(fp);
}


/*
 * Encrypts an input file and dumps the ciphertext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void rsa_encrypt(char *input_file, char *output_file, char *key_file) {

	node* input_node;
	unsigned char* plaintext;
	int count=0;

	// Read the plaintext from input_file
	input_node = read_file(input_file);

	plaintext = input_node->plaintext;
	count = input_node->length;

	// Read the key from key_file
	node* key_node;
	size_t n;
	size_t e;

	key_node = read_file(key_file);

	// Take the n
	memcpy(&n,key_node->plaintext,sizeof(size_t));

	// Take the e
	memcpy(&e,key_node->plaintext+sizeof(size_t),sizeof(size_t));

	// Encryption
	// Start the process of encryption
	size_t* ciphertext = (size_t*)malloc(sizeof(size_t)*count);

	for(int i=0;i<count;i++){
		// Using this equation calculates the ciphertext_char = (plaintext_char^e) mod n
		*(ciphertext+i) = modular_power(*(plaintext+i),e,n);
	}


	// Write the ciphertext to output_file
	FILE *fp = fopen(output_file,"w");
	if( fp == NULL) { fprintf(stderr,"%s","File does not exist!!!\n"); abort(); }
	for(int i=0;i<count;i++){
		fwrite(ciphertext+i,sizeof(size_t),1,fp);
	}

	// Clean up
	free(input_node);
	free(key_node);
	free(ciphertext);
	free(plaintext);
	fclose(fp);
}


/*
 * Decrypts an input file and dumps the plaintext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void rsa_decrypt(char *input_file, char *output_file, char *key_file) {

	node* input_node;
	size_t* ciphertext;
	int count = 0;

	// Read the ciphertext from input_file
	input_node = read_file(input_file);

	ciphertext = (size_t*)input_node->plaintext;
	count = (input_node->length)/sizeof(size_t);

	// Read the key from key_file
	node* key_node;
	size_t n;
	size_t d;

	key_node = read_file(key_file);

	// Take the n
	memcpy(&n,key_node->plaintext,sizeof(size_t));

	// Take the d
	memcpy(&d,key_node->plaintext+sizeof(size_t),sizeof(size_t));

	// Decryption
	// Start the process of decryption
	unsigned char* plaintext = (unsigned char*)malloc(sizeof(unsigned char)*count);

	for(int i=0;i<count;i++){
		// Using this equation calculates the plaintext_char = (ciphertext_char^d) mod n
		*(plaintext+i) = (int)modular_power(*(ciphertext+i),d,n);
	}

	// Write the plaintext to output_file
	FILE *fp = fopen(output_file,"w");
	if( fp == NULL) { fprintf(stderr,"%s","File does not exist!!!\n"); abort(); }
	for(int i=0;i<count;i++){
		fwrite(plaintext+i,sizeof(unsigned char),1,fp);
	}

	// Clean up
	free(input_node);
	free(key_node);
	free(ciphertext);
	free(plaintext);
	fclose(fp);
}


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
size_t modular_power(size_t base, size_t exp, size_t modulo){

	// Initialize result 
	size_t result = 1;

	// Update base if it is bigger than or equal to modulo 
	base = base % modulo;  
  	
  	// In case base is divisible by modulo
    if (base == 0) return 0;

	while (exp > 0) {

		// If e is odd, multiply base with result 
		if (exp % 2 == 1){ result = (result * base) % modulo; }

		// Right shift exp
		exp >>= 1;

		// Update the base
		base = (base * base) % modulo;
	}

	return result;
}