#define  MD5_DIGEST_LENGTH 16
#define MAX_USERS 40

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <gmp.h>


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

 typedef struct entry {

	int uid; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	char date[11]; /* file access date */
	char time[9]; /* file access time */

	char file[100]; /* filename (string) */
	unsigned char fingerprint[2*MD5_DIGEST_LENGTH+1]; /* file fingerprint */

	/* add here other fields if necessary */
	/* ... */
	/* ... */

}entry_;

 typedef struct user {
	int uid;
	int malicious_attempts; //malicious attempts on different files
}user;

 entry_* read_log_entry(FILE *log){

	entry_* entry = malloc(sizeof(entry_));

	int ret = fscanf(log, "%d %s %s %s %d %d %s\n", 
		   		     &entry->uid, entry->file, entry->date,
					 entry->time, &entry->access_type, &entry->action_denied,
					 entry->fingerprint);

	if(ret == EOF){
		free(entry);
		return NULL;
	}


	return entry;
}

void
usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}

//iterates entry log file and for every entry searches if the entry uid is unique, if it is it adds it to the users list (all_users)
//if it isn't it continues the iteration. The concept is that by iterating the entries and comparing each entry with the next entries we 
//can find the last entry of a user. Using this tactic prevents from adding duplicate users.
user* find_all_users(int *number_of_distinct_users){
	FILE* log_1 = fopen("file_logging.log", "r");
	FILE* log_2 = fopen("file_logging.log", "r");

	entry_* entry_1;
	entry_* entry_2;

	user* all_users = malloc(MAX_USERS*sizeof(user));
	*number_of_distinct_users = 0;

	while((entry_1 = read_log_entry(log_1)) != NULL){ //for current entry uid , find if it is distinct
		
		fseek(log_2, ftell(log_1), SEEK_SET); // start log_2 where log_1 stopped

		while((entry_2 = read_log_entry(log_2)) != NULL){
			//user not distinct

			if(entry_1->uid == entry_2->uid) break;

		}
		//user is distinct
		if(entry_2 == NULL){ 
			all_users[*number_of_distinct_users].uid = entry_1->uid;
			all_users[*number_of_distinct_users].malicious_attempts = 0;
			(*number_of_distinct_users)++;
		}
		
	}
	fclose(log_1);
	fclose(log_2);
	return all_users;
}

//find specific user from users table
int find_user(user* all_users, int user_num, uid_t uid){
	for(int i=0; i<user_num; i++){
		if(all_users[i].uid == uid) return i;
	}
	return -1; //impossible
}

void print_malicious_users(user* all_users, int user_num){
	int counter=0;
	printf("Malicious Users (7 access attempts on different files each attempt) :\n");
	printf("--------------------------------\n");
	for(int i=0; i<user_num; i++){
		if(all_users[i].malicious_attempts > 7){
			printf("User: %d\n", all_users[i].uid);
			counter++;
		}
	}
	if(counter==0){
		printf("No malicious users found\n");
	}
	printf("--------------------------------\n");
}

void print_file_modifications(user* all_users, int user_num, int* user_file_modifications){
	printf("\n FILE MODIFICATIONS PER USER\n");
	printf("-------------------------------------------\n");
	for(int i=0; i<user_num; i++){
		printf("User: %d  Modifications: %d\n", all_users[i].uid, user_file_modifications[i]);
	}
	printf("-----------------------------------------------\n");
}

//Uses 2 entries and 2 logs to iterate to log_file. It searches for action_denied =1 entries from different users. In order not to count
//malicious attempts on same file as different malicious attempts, we iterate the log_file until there is no other entry with the same uid,action_denied and file
//then we count it as a malicious attempt.
void 
list_unauthorized_accesses(user* distinct_users, int number_of_distinct_users)
{

	FILE* log_1 = fopen("file_logging.log", "r");
	FILE* log_2 = fopen("file_logging.log", "r");

	entry_* entry_1;
	entry_* entry_2;

	int user_index;


	while((entry_1 = read_log_entry(log_1)) != NULL){ 

		//skip entry if action_denied == 0
		if(!entry_1->action_denied) continue;

		user_index = find_user(distinct_users, number_of_distinct_users, entry_1->uid);

		//start log_2 file pointer where log_1 was
		fseek(log_2, ftell(log_1), SEEK_SET); 

		//iterate entries until you find an entry with same file,user and action_denied =1 (there is a similar entry)
		while((entry_2 = read_log_entry(log_2)) != NULL){
			
			//checks for malicious attempt 
			if((!strcmp(entry_1->file, entry_2->file)) && (entry_2->action_denied) && (entry_1->uid == entry_2->uid)) {
				break;
			}

		}
		
		//it means that the entry is unique ,so we can count it
		if(entry_2 == NULL){ 
			distinct_users[user_index].malicious_attempts++;
		}
	}
	fclose(log_1);
	fclose(log_2);

	print_malicious_users(distinct_users, number_of_distinct_users);

	return ;
}


//For each user,it finds how many times a speciic file was modified by comparing the entries' fingerprints
void
list_file_modifications(user* all_users, int user_num, char *file_to_scan)
{

	FILE* log = fopen("file_logging.log", "r");

	entry_* entry;

	//contains all modifications per user
	int user_file_modifications[user_num];
	for(int i=0; i<user_num; i++) user_file_modifications[i] = 0; 

	
	//this used to see the fingerprint we scanned before every iteration
	char* last_file_fingerprint = NULL;
	int last_access_type = -1;


	user tmp_user;

	//iterates users
	for(int i = 0; i<user_num; i++){ 

		tmp_user = all_users[i];
		
		//iterates entries
		while((entry = read_log_entry(log)) != NULL){  

			if(!strcmp(entry->file, file_to_scan)){ 

				//if this is the first fingerprint we get, we save it and continue to next iteration
				if(last_file_fingerprint == NULL || last_access_type==-1) { 
					last_file_fingerprint = entry->fingerprint;
					last_access_type = entry->access_type;
					continue;
				}
				//if we found an entry with different fingerprint than before (same user,file, write or delete access type)
				//then we found a file modification
				if(entry->uid == tmp_user.uid && (strcmp(entry->fingerprint, last_file_fingerprint) != 0) ){ 
					if((last_access_type == 2 || last_access_type == 3)){
						user_file_modifications[i]++;
					}
				}
				last_file_fingerprint = entry->fingerprint;
				last_access_type = entry->access_type;

			}
		}
		fseek(log,0,SEEK_SET); //reset file pointer
		last_file_fingerprint = NULL; //reset last-fingerprint
		last_access_type = -1; //reset access type
	}
	print_file_modifications(all_users, user_num, user_file_modifications);

	fclose(log);

	return ;
}


int 
main(int argc, char *argv[])
{

	int ch;
	FILE *log;
	//decrypt("file_logging.log","file_logging.log","private.key");

	if (argc < 2)
		usage();

	log = fopen("./file_logging.log", "r");
	if (log == NULL) {
		printf("Error opening log file \n");
		return 1;
	}

	int user_num;
	user* all_users = find_all_users(&user_num);

	while ((ch = getopt(argc, argv, "hi:m")) != -1) {
		switch (ch) {		
		case 'i':
			//list_file_modifications(log, optarg);
			list_file_modifications(all_users, user_num, optarg);
			break;
		case 'm':
			//list_unauthorized_accesses(log);
			list_unauthorized_accesses(all_users, user_num);
			break;
		default:
			usage();
		}

	}


	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */


	fclose(log);
	argc -= optind;
	argv += optind;	
	
	return 0;
}
