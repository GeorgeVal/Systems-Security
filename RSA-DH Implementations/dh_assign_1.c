#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<math.h>
#include<unistd.h> 


long long int keygen(long long int a, long long int b, long long int c){
    
    return (((long long int)pow(a,b))%c);
}

int main(int argc,char* argv[]){
    
    long long int P,G,A,B,opt;
    int optcounter =0;
    char *path;
    //for every option given assign its argument's value to the proper variable  
    while((opt = getopt(argc, argv, ":ho:p:g:a:b:")) != -1) 
    {   
        optcounter++;
        switch(opt) 
        {   
            case 'h': 
                printf("Options: \t\t\t -o path Path to output file \n\t\t\t\t -p number Prime number \n\t\t\t\t -g number Primitive Root for previous prime number \n\t\t\t\t -a number Private key A \n\t\t\t\t -b number Private key B \n\t\t\t\t -h This help message \n");
                exit(1);
                break;
            case 'o': 
                path = malloc(strlen(optarg) + 1);
                strcpy(path, optarg);
                break;
            case 'p': 
                 P = atoi(optarg);
                break;
            case 'g': 
                 G = atoi(optarg);
                break; 
            case 'a': 
                A = atoi(optarg); 
                break;
            case 'b': 
                 B = atoi(optarg); 
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
    //If less arguments are entered then print help message and exit 
    if (optcounter<5){
        fprintf (stderr, "Wrong number of inputs or option without argument! \n");
        printf("Options: \t\t\t -o path Path to output file \n\t\t\t\t -p number Prime number \n\t\t\t\t -g number Primitive Root for previous prime number \n\t\t\t\t -a number Private key A \n\t\t\t\t -b number Private key B \n\t\t\t\t -h This help message \n");
        exit(1);
    }
    
    FILE *fptr;
    
    //Alice's public key
    long long int alice_pub = keygen(G, A, P); 
     
    //Bob's public key
    long long int bob_pub = keygen(G, B, P); 
 
    // key exchange
    long long int alice_sec = keygen(bob_pub, A, P); // Secret key for Alice
    long long int bob_sec = keygen(alice_pub, B, P); // Secret key for Bob

    if ((fptr = fopen(path,"w")) == NULL){
       printf("Error! opening file");
       exit(1);
   }
   fprintf(fptr,"<%lld> <%lld> <%lld>",alice_pub ,bob_pub, alice_sec);
   //if you want to confirm common secret
   //printf("alice_sec: %lld, bob_sec: %lld \n",alice_sec,bob_sec);
   fclose(fptr);
   free(path);
   exit(0);
    
}