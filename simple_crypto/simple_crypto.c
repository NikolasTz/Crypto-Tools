#include "simple_crypto.h"

const char alphaNumeric[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};


// One-time pad

char* one_time_pad_generateRandomSecretKey(char *userInput){

	int userInputLength = strlen(userInput);
	
	FILE *fp = fopen("/dev/urandom","r");
	char *randomSecretKey = (char*)malloc(sizeof(char)*userInputLength);
	int c;

	if( fp != NULL) { 
		for (int i = 0; i < userInputLength; ++i){
			c = fgetc(fp);
			*(randomSecretKey+i) = c;
		}
	}
	else{ fprintf(stderr,"%s","File does not exist!!!\n"); }


	fclose(fp);
	return randomSecretKey;
}

char* one_time_pad_encrypting(char *userInput,char *randomSecretKey){

	int stringLength = strlen(userInput);
	char *encryptedText = (char*)malloc(sizeof(char)*(stringLength+1));
	char *printableEncryptText = (char*)malloc(sizeof(char)*(stringLength+1));

	for (int i = 0; i < stringLength; ++i){

		//XOR-ing
		*(encryptedText+i) = (*(userInput+i)) ^ (*(randomSecretKey+i));
		if( isprint( *(encryptedText+i) ) == 0 ) { *(printableEncryptText+i) = '#'; }
		else{ *(printableEncryptText+i) = *(encryptedText+i); }
		
	}
	
	*(encryptedText+stringLength) = '\0';
	*(printableEncryptText+stringLength) = '\0';

	printf("[OTP] encrypted: %s\n",printableEncryptText);
	return encryptedText;
}

char* one_time_pad_decrypting(char *encryptedText,char *randomSecretKey,int userInputLength){

	int stringLength = userInputLength;
	char *decryptedText = (char*)malloc(sizeof(char)*(stringLength+1));

	for (int i = 0; i < stringLength; ++i){
		//XOR-ing
		*(decryptedText+i) = (*(encryptedText+i)) ^ (*(randomSecretKey+i));
	}

	*(decryptedText+stringLength) = '\0';
	return decryptedText;
}


// Caesar's cipher

char* caesar_encrypting(char *userInput,int key){

	int stringLength = strlen(userInput);
	char *encryptedText = (char*)malloc(sizeof(char)*(stringLength+1));
	int position,modulo;

	for (int i = 0; i < stringLength; ++i){

		// Find the position on array alphaNumeric
		if( *(userInput+i) <= 57 ){ position = *(userInput+i) - 48; }
		else if( *(userInput+i) <= 90 ){ position = 10 + *(userInput+i) - 65; }
		else{ position = 36 + *(userInput+i) - 97; }

		modulo = key % 62;

		if( position + modulo <= 61 ){ *(encryptedText+i) = alphaNumeric[position+modulo]; }
		else{ 
			position = position - 62;
			*(encryptedText+i) = alphaNumeric[position+modulo]; 
		}

	}

	*(encryptedText+stringLength) = '\0';
	return encryptedText;
}

char* caesar_decrypting(char *encryptedText,int key){

	int stringLength = strlen(encryptedText);
	char *decryptedText = (char*)malloc(sizeof(char)*(stringLength+1));
	int position,modulo;

	for (int i = 0; i < stringLength; ++i){

		// Find the position on array alphaNumeric
		if( *(encryptedText+i) <= 57 ){ position = *(encryptedText+i) - 48; }
		else if( *(encryptedText+i) <= 90 ){ position = 10 + *(encryptedText+i) - 65; }
		else{ position = 36 + *(encryptedText+i) - 97; }
		
		modulo = key % 62;

		if( position - modulo >= 0 ){ *(decryptedText+i) = alphaNumeric[position-modulo]; }
		else{
			position = position + 62;
			*(decryptedText+i) = alphaNumeric[position-modulo]; 
		}
	}

	*(decryptedText+stringLength) = '\0';
	return decryptedText;
}


// Vigenere's cipher

char* vigenere_generate_key_phrase(int userInputLength,char* key){

	int lengthKey = strlen(key);
	int char_pos=0;

	char *keyphrase = (char*)malloc(sizeof(char)*(userInputLength+1));
	strncpy( keyphrase , key , lengthKey);

	int diffChar = userInputLength - lengthKey;
	
	for (int i = 0; i < diffChar; ++i){

		*(keyphrase+lengthKey+i) = *(key+char_pos);
		char_pos++;
		if( char_pos == lengthKey ){ char_pos = 0; }
	}


	*(keyphrase+userInputLength) = '\0';
	return keyphrase;
}

char* vigenere_encrypting(char *userInput,char* keyphrase){

	int stringLength = strlen(userInput);
	char *encryptedText = (char*)malloc(sizeof(char)*(stringLength+1));

	for (int i = 0; i < stringLength; ++i){ *(encryptedText+i) = (( *(userInput+i) + *(keyphrase+i) ) % 26) + 65; }

	*(encryptedText+stringLength) = '\0';
	return encryptedText;
}

char* vigenere_decrypting(char *encryptedText,char* keyphrase){

	int stringLength = strlen(encryptedText);
	char *decryptedText = (char*)malloc(sizeof(char)*(stringLength+1));

	for (int i = 0; i < stringLength; ++i){ *(decryptedText+i) = ( (*(encryptedText+i) - *(keyphrase+i) + 26 ) % 26) + 65; }

	*(decryptedText+stringLength) = '\0';
	return decryptedText;
}