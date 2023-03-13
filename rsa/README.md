
## Description

This tool can be used for asymmetric encryption and decryption using the RSA algorithm.Moreover,this tool can be used to generate RSA key-pair


#### Implementation

```
					  	            rsa_keygen 
			
This function generates an RSA key pair and saves each key(public and private) in a different file.

The function follows the procedure below :
 		1. Pick two distinct prime numbers p,q using the sieve_of_eratosthenes function
 		2. Compute the n=p*q
 		3. Calculate the fi(n)=(1-p)*(1-q) using Euler’s totient function
 		4. Choose a prime ​'e' where ​(e % fi(n) != 0) AND (gcd(e, fi(n)) == 1) using choose_e function
 		5. Choose ​'d' ​where 'd' is the ​modular inverse of (e,fi(n))​ using mod_inverse function
 		6. Finally write the public(n,d) and private(n,e) key in different files
```


```
						            rsa_encrypt 
	
This function encrypts an input file using key_file and dumps the ciphertext into an output file.

The function follows the procedure below :
 		1. Read the plaintext and key
 		2. For each character in the plaintext "calculates" the cipher character using the below formula
 		3. ciphertext_char = (plaintext_char^e) mod n where the pair (n,e) consist the key_file
 		4. The above modular exponentiation computed using the function modular_power function
 		5. Finally, writes the cipher text to output file.

```


```
					 	            rsa_decrypt 
	
This function decrypts an input file using key_file and dumps the plaintext into an output file.

The function follows the procedure below :
 		1. Read the ciphertext and key 
		2. For each character in the ciphertext "calculates" the plaintext character using the below formula
 		3. plaintext_char = (ciphertext_char^d) mod n where the pair (n,d) consist the key_file
		4. The above modular exponentiation computed using the function modular_power function
 		5. Finally, writes the plain text to output file.
```


## Tool specifications

```
Options:
    -i path Path to input file
    -o path Path to output file
    -k path Path to key file
    -g Perform RSA key-pair generation)
    -d Decrypt input and store results to output
    -e Encrypt input and store results to output
    -h This help message
```


## Compilation

#### Requirements: Any Linux distribution

#### Compilation: 
  1. make [all]  - to build 
  2. make clean - to remove
   


## References

1. RSA algorithm : https://en.wikipedia.org/wiki/RSA_(cryptosystem)
2. Sieve of Eratosthenes Algorithm : https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes
3. GCD : https://en.wikipedia.org/wiki/Greatest_common_divisor
4. Modular Inverse : https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
5. Modular exponentiation : https://en.wikipedia.org/wiki/Modular_exponentiation
