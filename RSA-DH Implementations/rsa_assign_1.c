#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include <stdbool.h>
#include<unistd.h> 
#include <time.h>


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
    //gmp_printf("N value %Zd \n",n);
    //gmp_printf("D value %Zd \n",d);
    //gmp_printf("E value %Zd \n",e);
    //gmp_printf("Lamda: %Zd \n",lamda);
    //printf("Acceptable bit length %d \n",bit_length);

    //now that we have what we need, lets write the public and private key to seperate files
    FILE *fptr;
    //storing public key to file
    if ((fptr = fopen("public.key","w")) == NULL){
       printf("Error! opening file");

       return;
    }
    fprintf(fptr,"%ld|%ld|",mpz_get_ui(n) ,mpz_get_ui(d));
    //storing private key to file
    if ((fptr = fopen("private.key","w")) == NULL){
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
    
    FILE* fptr;
    char read_ch;

    if ((fptr = fopen(plain_path,"r")) == NULL){
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
    
    if ((fptr = fopen("public.key","r")) == NULL){
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

    mpz_set_ui(n_en,n);
    mpz_set_ui(d_en,d);

    fclose(fptr);
    //open file to write the ciphertext
    long long int current_char;
    if ((fptr = fopen("ciphertext.txt","w")) == NULL){
                printf("Error! opening file");

                return ;
            }
    //encrypting message char by char (ascii by ascii) and storing it to file
    for(int i=0; i<plainint_length; i++){
        mpz_set_ui(m,plainint[i]);
        mpz_powm(c,m,d_en,n_en);
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
    FILE* fptr;
    long long int read_int;
    size_t flength;
    mpz_t n_ci,e_ci,c,decrypt;
    mpz_inits(n_ci,e_ci,c,decrypt,NULL);

    if ((fptr = fopen("private.key","r")) == NULL){
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

    if ((fptr = fopen(cipher_path,"r")) == NULL){
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

    if ((fptr = fopen(plain_path,"w")) == NULL){
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


    
int main(int argc,char* argv[]) {
   
   int opt;
   char *input_path, *output_path, *key_path;
   mpz_t p,q,sub;

   while((opt = getopt(argc, argv, ":hgi:o:k:ed")) != -1) 
    {   
        switch(opt) 
        {   
            case 'h': 
                printf("Options: \t\t\t -o path Path to output file \n\t\t\t\t -p number Prime number \n\t\t\t\t -g number Primitive Root for previous prime number \n\t\t\t\t -a number Private key A \n\t\t\t\t -b number Private key B \n\t\t\t\t -h This help message \n");
                exit(1);
                break;
            case 'g':
               // mpz_t p,q,sub; 
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
                    if ((mpz_probab_prime_p(q, 50)==2));
                        break;
                    
                }
                gmp_randclear(state);
                //gmp_printf("P: %Zd, Q: %Zd\n",p,q);
                
                //generating keys
                generate_keys(p,q);
                mpz_clears(p,q,sub,NULL);
                break;
            case 'i': 
                input_path = malloc(strlen(optarg) + 1);
                strcpy(input_path, optarg);
                break;
            case 'o': 
                output_path = malloc(strlen(optarg) + 1);
                strcpy(output_path, optarg);
                break;
            case 'k': 
                key_path = malloc(strlen(optarg) + 1);
                strcpy(key_path, optarg);
                break;
            case 'e':
                if(input_path==NULL || output_path==NULL || key_path==NULL){
                    printf("Required inputs missing (check i,o,k) \n");
                    exit(1);
                } 
                encrypt(input_path,output_path,key_path);
                break;
            case 'd':
                if(input_path==NULL || output_path==NULL || key_path==NULL){
                    printf("Required inputs missing (check i,o,k) \n");
                    exit(1);
                } 
                decrypt(input_path,output_path,key_path);
                break;
            case ':': 
                printf("option needs a value: \"%c\"\n", optopt); 
                exit(1);
                break; 
            case '?': 
                printf("unknown option: \"%c\"\n", optopt);
                break; 
        } 
    }

    
    exit(0);
}