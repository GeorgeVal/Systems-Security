#define _GNU_SOURCE
#define  MD5_DIGEST_LENGTH 16

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>
#include <time.h>
#include <stdbool.h>
#include <errno.h>
#include <gmp.h>



int acceptable_bit_length(int lamda){
    int i;
    //number of times lamda can be divided by 2 gives its bit digits
    for(i=0;lamda>0;i++)    
    {        
    lamda=lamda/2;    
    }
    //i-1 beacause any number that has i-1 bits is smaller than lamda
    return i-1;    
}

void generate_keys(mpz_t p ,mpz_t q){
	FILE *(*original_fopen)(const char*, const char*);
	FILE *original_fopen_ret;

	original_fopen = dlsym(RTLD_NEXT, "fopen");
	//original_fopen_ret = (*original_fopen)(path, mode);
    //initializing a randomizor and seeding it to generate different values upon different executions of this function
    gmp_randstate_t state;
    gmp_randinit_mt (state);
    gmp_randseed_ui(state, time(NULL)+mpz_get_ui(p));
    int bit_length;
    mpz_t n,lamda,p_1,q_1,e,gcd,mod,rand_prime,d;
    mpz_inits(n,lamda,p_1,q_1,e,gcd,mod,rand_prime,d,NULL);


    
    
    //calculate n=p*q
    mpz_mul(n,p,q);
    mpz_sub_ui (p_1, p, 1); 
    mpz_sub_ui (q_1, q, 1);

    //calculate lamda=(p-1)*(q-1)
    mpz_mul(lamda,p_1,q_1);
    
    
    bit_length = acceptable_bit_length(mpz_get_ui(lamda));
    
    //generating random e value 
    while (true){

     mpz_urandomb(rand_prime, state, bit_length);
     if (mpz_probab_prime_p(rand_prime, 50))
          gmp_randclear(state);
          break;
     }

    mpz_set(e,rand_prime);
    mpz_gcd(gcd, e, lamda);
    mpz_mod(mod,e,lamda);
  

    //if e checks rsa requirements then break else go through prime numbers less than lamda until a proper e is found (checks RSA's requirements)
    while((mpz_cmp_ui(gcd, 1) != 0) || (mpz_cmp_ui(mod, 0) == 0)){
        mpz_nextprime(e,rand_prime);
        mpz_set(rand_prime, e);
        
        mpz_gcd(gcd, e, lamda);
        mpz_mod(mod,e,lamda);
        
        if(mpz_cmp(e,lamda)>0){
            printf("Couldnt find proper e value :(\n");
            break;
        }
    }

    //calculate modular inverse of (e, lambda) = d
    mpz_invert (d, e, lamda);

    //-----Helpful prints-----
    gmp_printf("N value %Zd \n",n);
    gmp_printf("D value %Zd \n",d);
    gmp_printf("E value %Zd \n",e);
    gmp_printf("Lamda: %Zd \n",lamda);
    //printf("Acceptable bit length %d \n",bit_length);

    //now that we have what we need, lets write the public and private key to seperate files
    FILE *fptr;
    //storing public key to file
    if ((fptr = original_fopen("public.key","w")) == NULL){
       printf("Error! opening file");

       return;
    }
    fprintf(fptr,"%ld|%ld|",mpz_get_ui(n) ,mpz_get_ui(d));
    //storing private key to file
    if ((fptr = original_fopen("private.key","w")) == NULL){
        printf("Error! opening file");

        return;
    }
    fprintf(fptr,"%ld|%ld|",mpz_get_ui(n) ,mpz_get_ui(e));
    fclose(fptr);
    
    mpz_clears(n,lamda,p_1,q_1,e,gcd,mod,rand_prime,d,NULL);
    return;
}

//encrypting plain text to ciphertext
void encrypt(char *plain_path, char *cipher_path, char *key_path){

	FILE *(*original_fopen)(const char*, const char*);
	FILE *original_fopen_ret;

	original_fopen = dlsym(RTLD_NEXT, "fopen");
    
    FILE* fptr;
    char read_ch;

    if ((fptr = original_fopen(plain_path,"r")) == NULL){
       printf("Error! opening file");
       exit(1);
   }
   fseek(fptr, 0, SEEK_END);
  
    // calculating the size of the file
    long int flength = ftell(fptr);

    char plaintext[flength]; 
    int i=0;

    fseek(fptr, 0, SEEK_SET);
    while( (read_ch = fgetc(fptr)) != EOF && i<flength ) {
        plaintext[i] = read_ch;
        i++;
        }
        fclose(fptr);
        long long int plainint[flength];

        //convert chars to integers
    for(int i=0; i<flength; i++){
        plainint[i] = (long long int)plaintext[i];
        }

   
    mpz_t n_en,d_en,c,m;
    mpz_inits(n_en,d_en,c,m,NULL);
    size_t plainint_length = (sizeof(plainint)/sizeof(long long int));
    
    if ((fptr = original_fopen("public.key","r")) == NULL){
       printf("Error! opening file");

       return ;
    }
    fseek(fptr, 0, SEEK_END);
  
    // calculating the size of the file
    flength = ftell(fptr);
    char p_key[flength];

    fseek(fptr, 0, SEEK_SET);
    fgets(p_key,flength,fptr);
    char *token;
    int n,d;
    long long int c_int;

    //reading n,d from public.key using the delimiter |
    token = strtok(p_key, "|");
    n = atoi(token);
    token = strtok(NULL, "|");
    d = atoi(token);
	//printf("%d | %d\n",n,d);

    mpz_set_ui(n_en,n);
    mpz_set_ui(d_en,d);

    fclose(fptr);
    //open file to write the ciphertext
    long long int current_char;
    if ((fptr = original_fopen("file_logging.log","w+")) == NULL){
                printf("Error! opening file");

                return ;
            }
    //encrypting message char by char (ascii by ascii) and storing it to file
    for(int i=0; i<plainint_length; i++){
        mpz_set_ui(m,plainint[i]);
        mpz_powm(c,m,d_en,n_en);
       // gmp_printf("C: %Zd\n",c);
        current_char=mpz_get_ui(c);
        

        //storing every encrypted element as 8 bytes long long int   
        fwrite(&current_char, 8, 1, fptr);
            
        
    }
    fclose(fptr);
    mpz_clears(n_en,d_en,c,m,NULL);
    return ;
}


//decrypting ciphertext from input file and writing the decrypted message to output file
void decrypt(char *cipher_path, char *plain_path, char *key_path){

	FILE *(*original_fopen)(const char*, const char*);
	FILE *original_fopen_ret;

	original_fopen = dlsym(RTLD_NEXT, "fopen");
    FILE* fptr;
    long long int read_int;
    size_t flength;
    mpz_t n_ci,e_ci,c,decrypt;
    mpz_inits(n_ci,e_ci,c,decrypt,NULL);

    if ((fptr = original_fopen("private.key","r")) == NULL){
       printf("Error! opening file");

       return ;
    }
    fseek(fptr, 0, SEEK_END);
  
    // calculating the size of the file
    flength = ftell(fptr);
    char p_key[flength];

    fseek(fptr, 0, SEEK_SET);
    fgets(p_key,flength,fptr);
    char *token;
    int n,e;
  
    //reading n,e from private.key using the delimiter |
    token = strtok(p_key, "|");
    n = atoi(token);
    token = strtok(NULL, "|");
    e = atoi(token);

    mpz_set_ui(n_ci,n);
    mpz_set_ui(e_ci,e);

    fclose(fptr);

    if ((fptr = original_fopen(cipher_path,"r")) == NULL){
       printf("Error! opening file");
       exit(1);
    }
    fseek(fptr, 0, SEEK_END);
  
    // calculating the size of the file
    flength = ftell(fptr);
    //printf("Cipher file length is: %ld \n",flength);

    long long int plainint[flength/8];
    fseek(fptr, 0, SEEK_SET);

    //reading the ciphertext.txt and decrypting it (8 bytes at a time)
    for(int i=0; i<flength/sizeof(long long int); i++){
        fread(&read_int, 8, 1, fptr);
        mpz_set_ui(c,read_int);
        mpz_powm(decrypt,c,e_ci,n_ci);
        plainint[i]=mpz_get_ui(decrypt);

    }

    fclose(fptr);

    char dec_plain[flength/8]; //char outcome of decryption (initial message)
    //printf("Initial message:\n");

    //converting long long ints to chars
    for(int i=0; i<flength/8; i++){
        dec_plain[i]=plainint[i];
        //printf("%c",dec_plain[i]);
    }
    //printf("\n");

    if ((fptr = original_fopen(plain_path,"w")) == NULL){
       printf("Error! opening file");
       exit(1);
    }

    //writing decrypted text to output file
    for(int i=0; i<flength/sizeof(long long int); i++){
        fwrite(&dec_plain[i], 1, 1, fptr);
    }

    fclose(fptr);
    mpz_clears(n_ci,e_ci,c,decrypt,NULL);
    return;
}

//checks if file already exists
bool check_existence(const char *path){
	//change_flag();
	struct stat buffer;
    int exist = stat(path,&buffer);
    if(exist == 0)
        return true;
    else  
        return false;
	
}

//entry structure containing everything needed for log file
struct entry {

	int uid; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	time_t t; /* file access time/date */

	const char *file_path; /* filename (string) */
	unsigned char fingerprint[MD5_DIGEST_LENGTH]; /* file fingerprint */

	/* add here other fields if necessary */
	/* ... */
	/* ... */

};

struct entry log_entry;



void find_fingerprint(FILE* fp, unsigned char* fingerprint){
	MD5_CTX c; 
	int bytes;
	MD5_Init(&c); //this is clean
	// calculating the size of the file
	fseek(fp, 0, SEEK_END);
	//printf("Fseek failure\n");
    long int flength = ftell(fp);
	//printf("ftell success\n");
	fseek(fp, 0, SEEK_SET);
    unsigned char log_data[flength]; 

	int i=0;
	while ((bytes = fread (log_data, 1, flength, fp)) != 0)
        MD5_Update (&c, log_data, bytes);
    MD5_Final (fingerprint,&c);
	
	return ;

}

FILE *
fopen(const char *path, const char *mode) 
{	
	if(access("public.key",F_OK)!=0 || access("private.key",F_OK)!=0){
		        mpz_t p,q,sub; 
                mpz_inits(p,q,sub,NULL);
                gmp_randstate_t state;
                gmp_randinit_mt (state);
                
                //generating random prime 12-bit number for p
                gmp_randseed_ui(state, time(NULL));
                while (true){

                    mpz_urandomb(p, state, 12);
                    if (mpz_probab_prime_p(p, 50)==2)
                        break;
                }
                gmp_randseed_ui(state, time(NULL));
                //generating q
                mpz_mul_ui(q,p,4);
                mpz_sub(sub,p,q);
                //if p and q are close multiply p
                if(mpz_cmp_ui(sub,500)<0){
                    mpz_mul_ui(q,p,8);
                }
                
                //iterate prime numbers larger than q until a definite prime is found
                while (true){

                    mpz_nextprime(q,q);
                    if ((mpz_probab_prime_p(q, 50)==2)){
                        break;}
                    
                }
                gmp_randclear(state);
                gmp_printf("P: %Zd, Q: %Zd\n",p,q);
                
                //generating keys
                generate_keys(p,q);
                mpz_clears(p,q,sub,NULL);
	}
	bool exists = check_existence(path);
	if((strcmp(mode,"r")==0) && (exists==false)){
		return NULL;
	}

	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	//check if file already exists to distinguish creation from opening 
	
	if(exists && ((strcmp(mode,"w")==0 )|| (strcmp(mode,"w+")==0))){
		log_entry.access_type=3;
	}
	else if (exists) {
		log_entry.access_type=1;
	}
	else{
		log_entry.access_type=0;
	}


	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);


	/* add your code here */
	
	
	FILE *logfile;
	char str_log[500];

	


	log_entry.uid = getuid();
	log_entry.file_path=path;
	log_entry.t = time(NULL);
	struct tm timestamp = *localtime(&log_entry.t);

		
	//mode = r and file can be read
	if((strcmp(mode,"r"))==(access(path, R_OK))){
		log_entry.action_denied=0;
	}
	else if((access(path, W_OK)==0)){
		log_entry.action_denied=0;
	}
	else{
		log_entry.action_denied=1;
	}


	
	FILE* fp_read;
	fp_read = original_fopen(path,"r");
	find_fingerprint(fp_read,log_entry.fingerprint);
	
 

	// printf("UID: %d , PATH:  %s, DATE: %02d/%02d/%02d, TIME: %02d:%02d:%02d, ACCESS_TYPE: %d, ACTION_DENIED: %d, "
	// , log_entry.uid, log_entry.file_path, timestamp.tm_mday, timestamp.tm_mon+1, timestamp.tm_year+1900, timestamp.tm_hour, timestamp.tm_min, timestamp.tm_sec,
	// log_entry.access_type, log_entry.action_denied);
	// printf("FINGERPRINT: ");
	// for(int i = 0; i < MD5_DIGEST_LENGTH; i++) printf("%02x", log_entry.fingerprint[i]);
	// printf("\n");

	logfile=original_fopen("file_logging.log","a+");

	sprintf(str_log, "%d %s %d/%d/%d %d:%d:%d %d %d "
	, log_entry.uid, log_entry.file_path, timestamp.tm_mday, timestamp.tm_mon+1, timestamp.tm_year+1900, timestamp.tm_hour, timestamp.tm_min, timestamp.tm_sec,
	log_entry.access_type, log_entry.action_denied);
	//special printf for fingerprint
	fprintf(logfile, "%s", str_log); 
	for(int i = 0; i < MD5_DIGEST_LENGTH; i++) fprintf(logfile, "%02x", log_entry.fingerprint[i]);
	fprintf(logfile, "\n");

	
	encrypt("file_logging.log","file_logging.log","public.key");
	
	
	/* ... */
	/* ... */
	/* ... */
	/* ... */

	
	
	return original_fopen_ret;
		
}


size_t 
fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{

	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);



	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	if(access(log_entry.file_path, W_OK)==0){
		original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);
		log_entry.action_denied=0;
	}
	else {
		original_fwrite_ret = NULL;
		log_entry.action_denied=1;
	}
	decrypt("file_logging.log","file_logging.log","private.key");

	/* add your code here */
	FILE *(*original_fopen)(const char*, const char*);
	FILE *logfile;
	char str_log[500];
	FILE* fp_read;


	fseek(stream, 0, SEEK_END);
    long int flength = ftell(stream);
	//printf("length of file: %ld\n",flength);
	fseek(stream, 0, SEEK_SET);

	if(flength==0){
		log_entry.access_type=3;
	}
	else{
		log_entry.access_type=2;
	}

	log_entry.uid = getuid();
	log_entry.t = time(NULL);
	struct tm timestamp = *localtime(&log_entry.t);

	original_fopen = dlsym(RTLD_NEXT, "fopen");

	
	fp_read = original_fopen(log_entry.file_path,"r");
	find_fingerprint(fp_read,log_entry.fingerprint);

	// printf("UID: %d , PATH:  %s, DATE: %02d/%02d/%02d, TIME: %02d:%02d:%02d, ACCESS_TYPE: %d, ACTION_DENIED: %d,"
	// , log_entry.uid, log_entry.file_path, timestamp.tm_mday, timestamp.tm_mon+1, timestamp.tm_year+1900, timestamp.tm_hour, timestamp.tm_min, timestamp.tm_sec,
	// log_entry.access_type, log_entry.action_denied);
	// printf(" FINGERPRINT: ");
	// for(int i = 0; i < MD5_DIGEST_LENGTH; i++) printf("%02x", log_entry.fingerprint[i]);
	// printf("\n");

	logfile=original_fopen("file_logging.log","a+");
	
	sprintf(str_log, "%d %s %d/%d/%d %d:%d:%d %d %d "
	, log_entry.uid, log_entry.file_path, timestamp.tm_mday, timestamp.tm_mon+1, timestamp.tm_year+1900, timestamp.tm_hour, timestamp.tm_min, timestamp.tm_sec,
	log_entry.access_type, log_entry.action_denied);
	//printf for fingerprint
	fprintf(logfile, "%s", str_log); 

	for(int i = 0; i < MD5_DIGEST_LENGTH; i++) fprintf(logfile, "%02x", log_entry.fingerprint[i]);
	fprintf(logfile, "\n");	


	

	

	
	/* ... */
	/* ... */
	/* ... */
	/* ... */


	return original_fwrite_ret;
}


