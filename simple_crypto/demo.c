#include "simple_crypto.h"

int main( int argc, char ** argv )
{
	
	char *encryptedText = NULL,*decryptedText = NULL,*keyphrase = NULL,*randomSecretKey = NULL;
	int key;
	
	char *plaintext = (char*)malloc(sizeof(char)*4095); // MAX SIZE INPUT_BUFFER
	char *plaintext1 = (char*)malloc(sizeof(char)*4095); // MAX SIZE INPUT_BUFFER

	// One-time pad	
	printf("[OTP] input: ");
	scanf("%s",plaintext);

	while ( (getchar()) != '\n');

	// Just used to have equivalents pritned formats.Either the input comes from terminal or file using redirect.
	if( !isatty(STDIN_FILENO) ){ // if STDIN_FILENO not referring to a terminal
		printf("%s\n",plaintext);
	}

	randomSecretKey = one_time_pad_generateRandomSecretKey(plaintext);
	
	// Encryption
	encryptedText = one_time_pad_encrypting(plaintext,randomSecretKey);

	// Decryption
	decryptedText = one_time_pad_decrypting(encryptedText,randomSecretKey,strlen(plaintext));
	printf("[OTP] decrypted: %s\n",decryptedText);


	// Caesar's cipher
	printf("[Caesars] input: ");
	scanf("%s",plaintext);

	while ((getchar()) != '\n'); 

	// Just used to have equivalents pritned formats.Either the input comes from terminal or file using redirect.
	if( !isatty(STDIN_FILENO) ){ // if STDIN_FILENO not referring to a terminal
		printf("%s\n",plaintext);
	}

	printf("[Caesars] key: ");
	scanf("%d",&key);

	while ((getchar()) != '\n'); 

	// Just used to have equivalents pritned formats.Either the input comes from terminal or file using redirect.
	if( !isatty(STDIN_FILENO) ){ // if STDIN_FILENO not referring to a terminal
		printf("%d\n",key);
	}

	// Encryption
	encryptedText = caesar_encrypting(plaintext,key);
	printf("[Caesars] encrypted: %s\n",encryptedText);

	// Decryption
	decryptedText = caesar_decrypting(encryptedText,key);
	printf("[Caesars] decrypted: %s\n",decryptedText);


	// Vigenere's cipher
	printf("[Vigenere] input: ");
	scanf("%s",plaintext);

	while ((getchar()) != '\n'); 

	// Just used to have equivalents pritned formats.Either the input comes from terminal or file using redirect.
	if( !isatty(STDIN_FILENO) ){ // if STDIN_FILENO not referring to a terminal
		printf("%s\n",plaintext);
	}

	printf("[Vigenere] key: ");
	scanf("%s",plaintext1);

	if( !isatty(STDIN_FILENO) ){ // if STDIN_FILENO not referring to a terminal
		printf("%s\n",plaintext1);
	} 

	keyphrase = vigenere_generate_key_phrase(strlen(plaintext),plaintext1);

	// Encryption
	encryptedText = vigenere_encrypting(plaintext,keyphrase);
	printf("[Vigenere] encrypted: %s\n",encryptedText);

	// Decryption
	decryptedText = vigenere_decrypting(encryptedText,keyphrase);
	printf("[Vigenere] decrypted: %s\n",decryptedText);


	free(plaintext);
	free(plaintext1);
	free(encryptedText);
	free(decryptedText);
	free(keyphrase);
	free(randomSecretKey);
}