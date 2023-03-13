
## Description

This tool can be used for symmetric encryption using the AES cryptographic algorithm in ECB mode. Moreover can be used for signing and verifying using CMAC
Finally can be used for deriving a symmetric key from a password using SHA1.For the implementation of tool was used the EVP and CMAC APIs, found in the OpenSSL toolkit.

***************************************************************
* AES stands for Advanced Encryption Standard
* ECB stands for Electronic Code Book
* CMAC stands for Cipher-based Message Authentication Code
* SHA1 stands for Secure Hashing Algorithm 1
***************************************************************


#### Implementation


```
					                keygen 
			
This function is responsible to generate the key using the password.
For this function was used the function EVP_BytesToKey with the appropriate arguments and iteration equal to one.
This function was preferred over PKCS5_PBKDF2_HMAC_SHA1 ,because it is the default function which used by OpenSSL if not used the argument -iter.
Also, because we do not have the argument iteration available,the function EVP_BytesToKey was preferred.

```



```
				                    encrypt 
	
This function is responsible for encryption the data

For the encryption was used the functions in the following order:
1. EVP_CIPHER_CTX_new : Create and initialize the context
2. EVP_EncryptInit_ex : Sets up the cipher context for encryption with cipher type where the cipher type based on bit_mode
3. EVP_EncryptUpdate : Provide the plaintext to be encrypted, and obtain the cipher text
4. EVP_EncryptFinal_ex : Finalize the encryption that is encrypts any data that remains in a partial block,using standard block padding(aka PKCS padding)
5. EVP_CIPHER_CTX_free : Clears all information from the cipher context and free up any allocated memory associate with it
@return : Return the length of cipher text


```



```
					                decrypt 	
This function is responsible for decryption of the data

For the decryption was used the functions in the following order:
1. EVP_CIPHER_CTX_new : Create and initialize the context
2. EVP_DecryptInit_ex : Sets up the cipher context for decryption with cipher type where the cipher type based on bit_mode
3. EVP_DecryptUpdate : Provide the cipher text to be decrypted, and obtain the plaintext
4. EVP_DecryptFinal_ex : Finalize the decryption that is decrypts any data that remains in a partial block,using standard block padding(aka PKCS padding)
5. EVP_CIPHER_CTX_free : Clears all information from the cipher context and free up any allocated memory associate with it
@return : Return the length of plaintext

```



```
					            gen_cmac

This function is responsible for generating the CMAC

For the generation of CMAC was used the functions from CMAC API in the following order:
1. CMAC_CTX_new : Create and initialize the CMAC context
2. CMAC_Init : Sets up the CMAC context to use the given key and cipher type where the cipher type based on bit_mode
2. CMAC_Update : Processes the data of plaintext to generate the CMAC
3. CMAC_Final : Finalize the operation,that is set the length of CMAC and writes the result to cmac variable
4. CMAC_CTX_free : Clears all information from the CMAC context and free up any allocated memory associate with it

```



```
				   	            verify_cmac 
	
This function is responsible for verification a CMAC
Compare two CMACs and return the result

```

## Tool specifications

```
Options:
    -i path Path to input file
    -p psswd Password for key generation
    -b bits Bit mode (128 or 256 only)
    -o path Path to output file
    -d Decrypt input and store results to output
    -e Encrypt input and store results to output
    -s Encrypt+sign input and store results to output
    -v Decrypt+verify input and store results to output
    -h This help message
```
## Compilation

#### Requirements: Any Linux distribution

#### Compilation: 
  1. make [all]  - to build 
  2. make clean - to remove
