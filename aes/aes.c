#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/cmac.h>

#define BLOCK_SIZE 16
#define ITERATION 1


/* function prototypes */
void print_hex(unsigned char *, size_t);
void print_string(unsigned char *, size_t); 
void usage(void);
void check_args(char *, char *, unsigned char *, int, int);
void keygen(unsigned char *, unsigned char *, unsigned char *, int);
int encrypt(unsigned char *, int, unsigned char *, unsigned char *, unsigned char *, int );
int decrypt(unsigned char *, int, unsigned char *, unsigned char *, unsigned char *, int);
void gen_cmac(unsigned char *, size_t, unsigned char *, unsigned char *, int);
int verify_cmac(unsigned char *, unsigned char *);


/* TODO Declare your function prototypes here... */
typedef struct{
	unsigned char *plaintext;
	int length;
}node;

node* read_file(char*);
void write_file(char*,unsigned char*,int);


/*
 * Prints the hex value of the input
 * 16 values per line
 */
void print_hex(unsigned char *data, size_t len){
	
	size_t i;
	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("\n");
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}


/*
 * Prints the input as string
 */
void print_string(unsigned char *data, size_t len){

	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++)
			printf("%c", data[i]);
		printf("\n");
	}
}


/*
 * Prints the usage message
 * Describe the usage of the new arguments you introduce
 */
void usage(void){

	printf(
	    "\n"
	    "Usage:\n"
	    "    assign_1 -i in_file -o out_file -p passwd -b bits" 
	        " [-d | -e | -s | -v]\n"
	    "    assign_1 -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    " -i    path    Path to input file\n"
	    " -o    path    Path to output file\n"
	    " -p    psswd   Password for key generation\n"
	    " -b    bits    Bit mode (128 or 256 only)\n"
	    " -d            Decrypt input and store results to output\n"
	    " -e            Encrypt input and store results to output\n"
	    " -s            Encrypt+sign input and store results to output\n"
	    " -v            Decrypt+verify input and store results to output\n"
	    " -h            This help message\n"
	);
	exit(EXIT_FAILURE);
}


/*
 * Checks the validity of the arguments
 * Check the new arguments you introduce
 */
void check_args(char *input_file, char *output_file, unsigned char *password, int bit_mode, int op_mode){

	if (!input_file) {
		printf("Error: No input file!\n");
		usage();
	}

	if (!output_file) {
		printf("Error: No output file!\n");
		usage();
	}

	if (!password) {
		printf("Error: No user key!\n");
		usage();
	}

	if ((bit_mode != 128) && (bit_mode != 256)) {
		printf("Error: Bit Mode <%d> is invalid!\n", bit_mode);
		usage();
	}

	if (op_mode == -1) {
		printf("Error: No mode\n");
		usage();
	}
}


/*
 * Generates a key using a password
 */
void keygen(unsigned char *password, unsigned char *key, unsigned char *iv,int bit_mode){

	const EVP_CIPHER *cipher;
    const EVP_MD *dgst = NULL;
	
	// Specify the type of cipher based on bit_mode    
    if( bit_mode == 128 ){  cipher = EVP_aes_128_ecb(); }
	else{ cipher = EVP_aes_256_ecb(); }

    if(!cipher) { fprintf(stderr, "No such cipher\n"); abort(); }

    // Specify the message digest function
    dgst = EVP_sha1();
    if(!dgst) { fprintf(stderr, "No such digest\n"); abort(); }

    // Generate the key
    if(!EVP_BytesToKey(cipher, dgst,NULL,password,strlen((const char*)password),ITERATION,key,iv)){

        fprintf(stderr, "EVP_BytesToKey failed\n");
        abort();
    }
}


/*
 * Encrypts the data
 */
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,unsigned char *iv, unsigned char *ciphertext, int bit_mode){

	/* TODO Task B */

	EVP_CIPHER_CTX* ctx; 
	const EVP_CIPHER* type;
	int length;
	int ciphertext_len;

	// Create and initialize the context
	if(!(ctx = EVP_CIPHER_CTX_new())){
		ERR_print_errors_fp(stderr);
	    abort();
	}

	// Specify the type of cipher based on bit_mode 
	if( bit_mode == 128 ){  type = EVP_aes_128_ecb(); }
	else{ type = EVP_aes_256_ecb(); }
	
	// Initialize the encryption operation
	if ( EVP_EncryptInit_ex(ctx,type,NULL,key,NULL) != 1){ 
		ERR_print_errors_fp(stderr);
	    abort(); 
	}

	// Provide the plaintext to be encrypted, and obtain the cipher text
	if( EVP_EncryptUpdate(ctx,ciphertext,&length,plaintext,plaintext_len) != 1){
		ERR_print_errors_fp(stderr);
	    abort();
	}

	ciphertext_len = length;

	// Finalize the encryption
	if( EVP_EncryptFinal_ex(ctx,ciphertext+length,&length) != 1){
		ERR_print_errors_fp(stderr);
	    abort();
	}

	// Add the length to get the correct length(because of padding)
	ciphertext_len += length;

	/* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    // Return the length of cipher text
    return ciphertext_len;
}


/*
 * Decrypts the data and returns the plaintext size
 */
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,unsigned char *iv, unsigned char *plaintext, int bit_mode){
	
	int plaintext_len;
	plaintext_len = 0;

	/*TODO Task C */
	EVP_CIPHER_CTX* ctx; 
	const EVP_CIPHER* type;
	
	int length;

	// Create and initialize the context
	if(!(ctx = EVP_CIPHER_CTX_new())){
		ERR_print_errors_fp(stderr);
	    abort();
	}

	// Specify the type of cipher based on bit_mode 
	if( bit_mode == 128 ){  type = EVP_aes_128_ecb(); }
	else{ type = EVP_aes_256_ecb(); }

	// Initialize the decryption operation
	if ( EVP_DecryptInit_ex(ctx,type,NULL,key,NULL) != 1){ 
		ERR_print_errors_fp(stderr);
	    abort(); 
	}

	// Provide the cipher text to be decrypted, and obtain the plaintext
	if( EVP_DecryptUpdate(ctx,plaintext,&length,ciphertext,ciphertext_len) != 1){
		ERR_print_errors_fp(stderr);
	    abort();
	}

	plaintext_len = length;

	// Finalize the decryption
	if( EVP_DecryptFinal_ex(ctx,plaintext+length,&length) != 1){
		ERR_print_errors_fp(stderr);
	    abort();
	}

	// Add the length to get the correct length(because of padding)
	plaintext_len += length;

	/* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    // Return the length of plaintext
	return plaintext_len;
}


/*
 * Generates a CMAC
 */
void gen_cmac(unsigned char *data, size_t data_len, unsigned char *key, unsigned char *cmac, int bit_mode){

	/* TODO Task D */

  	CMAC_CTX *ctx = CMAC_CTX_new();
	const EVP_CIPHER* type;
	size_t cmac_len;

	// Specify the type of cipher based on bit_mode 
	if(bit_mode == 128){ type =  EVP_aes_128_ecb(); }
  	else{ type =  EVP_aes_256_ecb(); }

  	// Initialize the CMAC context
  	if( CMAC_Init(ctx,key,bit_mode/8,type,NULL) == 0){
  		printf("CMAC_Init\n");
	    abort(); 
  	}
 	
 	// Processes the data_len bytes from data to generate the CMAC
 	if( CMAC_Update(ctx,data,data_len) == 0){
 		printf("CMAC_Update\n");
	    abort();
 	}

 	// Finalize the operation,that is set the cmac_len=16 bytes and writes the 16 bytes to cmac
  	if( CMAC_Final(ctx,cmac,&cmac_len) == 0){
  		printf("CMAC_Final\n");
	    abort();
  	}

  	/* Clean up */
  	CMAC_CTX_free(ctx);
}


/*
 * Verifies a CMAC
 */
int verify_cmac(unsigned char *cmac1, unsigned char *cmac2){
	
	int verify;
	verify = 0;

	/* TODO Task E */

	// Compare the cmac1 and camc2 and return the result
	verify = strncmp((const char*)cmac1,(const char*)cmac2,BLOCK_SIZE);
	return verify;
}


/* TODO Develop your functions here... */

/* Read from input file */
node* read_file(char* input_file){

	int c;
	int count=0;
	unsigned char* plaintext=(unsigned char*)malloc(sizeof(char)*1);
	node* mynode = (node*)malloc(sizeof(node));

	FILE *fp = fopen(input_file,"r");

	if( fp != NULL) { 
		do {
		    c = fgetc(fp);
		    if( feof(fp) ) { break; }
	      	*(plaintext+count) = c;
	      	count++;
	      	plaintext = realloc(plaintext, count+1);
	   	}while(1);
	}
	else{ fprintf(stderr,"%s","File does not exist!!!\n"); abort(); }

	fclose(fp);
	mynode->plaintext = plaintext;
	mynode->length = count;
	return mynode;
}

/* Write to the output file */
void write_file(char* output_file,unsigned char* plaintext,int length){

	FILE *fp = fopen(output_file,"w");
	for(int i=0;i<length;i++){
		fputc(*(plaintext+i), fp);
	}

	fclose(fp);
}



/*
 * Encrypts the input file and stores the ciphertext to the output file
 *
 * Decrypts the input file and stores the plaintext to the output file
 *
 * Encrypts and signs the input file and stores the ciphertext concatenated with 
 * the CMAC to the output file
 *
 * Decrypts and verifies the input file and stores the plaintext to the output
 * file
 */
int main(int argc, char **argv){

	int opt;					/* used for command line arguments */
	int bit_mode;				/* defines the key-size 128 or 256 */
	int op_mode;				/* operation mode */
	char *input_file;			/* path to the input file */
	char *output_file;			/* path to the output file */
	unsigned char *password;	/* the user defined password */

	/* Init arguments */
	input_file = NULL;
	output_file = NULL;
	password = NULL;
	bit_mode = -1;
	op_mode = -1;


	/*
	 * Get arguments
	 */
	while ((opt = getopt(argc, argv, "b:i:m:o:p:desvh:")) != -1) {
		switch (opt) {
		case 'b':
			bit_mode = atoi(optarg);
			break;
		case 'i':
			input_file = strdup(optarg);
			break;
		case 'o':
			output_file = strdup(optarg);
			break;
		case 'p':
			password = (unsigned char *)strdup(optarg);
			break;
		case 'd':
			/* if op_mode == 1 the tool decrypts */
			op_mode = 1;
			break;
		case 'e':
			/* if op_mode == 0 the tool encrypts */
			op_mode = 0;
			break;
		case 's':
			/* if op_mode == 2 the tool signs */
			op_mode = 2;
			break;
		case 'v':
			/* if op_mode == 3 the tool verifies */
			op_mode = 3;
			break;
		case 'h':
		default:
			usage();
		}
	}


	/* check arguments */
	check_args(input_file, output_file, password, bit_mode, op_mode);


	/* TODO Develop the logic of your tool here... */

	/* Keygen from password */
	unsigned char* key = (unsigned char*)malloc(sizeof(char)*EVP_MAX_KEY_LENGTH);
	unsigned char* iv = NULL;
	keygen(password,key,iv,bit_mode);


	/* Operate on the data according to the mode */

	/* encrypt */
	if(op_mode == 0){

		node* mynode;
		unsigned char* plaintext;
		int count=0;

		// Read the plaintext from input_file
		mynode = read_file(input_file);

		plaintext = mynode->plaintext;
		count = mynode->length;

		// Encryption
		unsigned char* ciphertext = (unsigned char*)malloc(sizeof(char)*count + sizeof(char)*BLOCK_SIZE);
		int length = encrypt(plaintext,count,key,NULL,ciphertext,bit_mode);

		// Write the ciphertext to output_file
		write_file(output_file,ciphertext,length);

		// Clean up
		free(plaintext);
		free(ciphertext);
		free(mynode);
	}

	/* decrypt */
	if(op_mode == 1){

		node* mynode;
		unsigned char* ciphertext;
		int count=0;

		// Read the cipher text from input_file
		mynode = read_file(input_file); 

		ciphertext = mynode->plaintext;
		count = mynode->length;

		// Decryption
		unsigned char* plaintext = (unsigned char*)malloc(sizeof(char)*count + sizeof(char)*BLOCK_SIZE);
		int length = decrypt(ciphertext,count,key,NULL,plaintext,bit_mode);
		
		// Write the plaintext to output_file
		write_file(output_file,plaintext,length);

		// Clean up
		free(ciphertext);
		free(plaintext);
		free(mynode);
	}

	/* sign */
	if(op_mode == 2){

		node* mynode;
		unsigned char* data;
		int count=0;

		// Read the plaintext from input_file
		mynode = read_file(input_file);

		data = mynode->plaintext;
		count = mynode->length;

		unsigned char* cmac = (unsigned char*)malloc(sizeof(char)*BLOCK_SIZE);
		gen_cmac(data,count,key,cmac,bit_mode);

		// Encryption
		unsigned char* ciphertext = (unsigned char*)malloc(sizeof(char)*count + sizeof(char)*BLOCK_SIZE);
		int length = encrypt(data,count,key,NULL,ciphertext,bit_mode);

		// Write the cipher text and the cmac to output file
		FILE *fp = fopen(output_file,"w");
		for(int i=0;i<length+BLOCK_SIZE;i++){
			if(i<length){ fputc(*(ciphertext+i), fp); }
			else{ fputc(*(cmac+i-length), fp); }
		}

		// Clean up
		free(data);
		free(cmac);
		free(ciphertext);
		free(mynode);
		fclose(fp);	
	}

	/* verify */
	if(op_mode == 3){

		node* mynode;
		unsigned char* data;
		int count=0;

		// Read the file char by char from input_file
		mynode = read_file(input_file);

		data = mynode->plaintext;
		count = mynode->length;

		// Partitioning
		unsigned char* cmac1 = (unsigned char*)malloc(sizeof(char)*BLOCK_SIZE);
		unsigned char* ciphertext = (unsigned char*)malloc(sizeof(char)*(count - BLOCK_SIZE));

		// Copy cipher text from data
		memcpy(ciphertext,data,count - BLOCK_SIZE);

		// Copy cmac from data
		for(int i=0;i<BLOCK_SIZE;i++){ *(cmac1+i) = *(data+count-BLOCK_SIZE+i); }

		// Decryption
		unsigned char* plaintext = (unsigned char*)malloc(sizeof(char)*(count-BLOCK_SIZE) + sizeof(char)*BLOCK_SIZE);
		int length_plaintext = decrypt(ciphertext,count-BLOCK_SIZE,key,NULL,plaintext,bit_mode);

		// Generate cmac for plaintext which derived from decrypt
		unsigned char* cmac2 = (unsigned char*)malloc(sizeof(char)*BLOCK_SIZE);
		gen_cmac(plaintext,length_plaintext,key,cmac2,bit_mode);

		int verify = verify_cmac(cmac1,cmac2);
		if(verify == 0){ 
			printf("TRUE\n");
			// Write the cmac to output file
			write_file(output_file,plaintext,length_plaintext);
		}
		else{ printf("FALSE\n"); }

		// Clean up
		free(cmac1);
		free(cmac2); 
		free(data);
		free(mynode);
		free(ciphertext);
		free(plaintext);	
	}	

	/* Clean up */
	free(input_file);
	free(output_file);
	free(password);
	free(key);
	free(iv);

	/* END */
	return 0;
}
