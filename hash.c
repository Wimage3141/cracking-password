#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>

#include "hash_functions.h"

#define KEEP 16 // only the first 16 bytes of a hash are kept

struct cracked_hash {
	char hash[2*KEEP+1];
	char *password, *alg;
};

struct thread_args {
	char **passwords;
	int start;
	int end;
	struct cracked_hash *cracked_hashes;
	int n_hashed;
	pthread_mutex_t *mutex;
};

typedef unsigned char * (*hashing)(unsigned char *, unsigned int);

int n_algs = 4;
hashing fn[4] = {calculate_md5, calculate_sha1, calculate_sha256, calculate_sha512};
char *algs[4] = {"MD5", "SHA1", "SHA256", "SHA512"};

int compare_hashes(char *a, char *b) {
	for(int i=0; i < 2*KEEP; i++)
		if(a[i] != b[i])
			return 0;
	return 1;
}

void *worker_thread(void *arg) {
    struct thread_args *args = (struct thread_args *)arg;
    char hex_hash[2 * KEEP + 1];

    for (int p = args->start; p < args->end; p++) {
        char *password = args->passwords[p];
        for (int i = 0; i < n_algs; i++) {
            unsigned char *hash = fn[i]((unsigned char *)password, strlen(password));
            for (int j = 0; j < KEEP; j++)
                sprintf(&hex_hash[2 * j], "%02x", hash[j]);
            hex_hash[2 * KEEP] = '\0';

            for (int j = 0; j < args->n_hashed; j++) {
                pthread_mutex_lock(args->mutex);
                if (args->cracked_hashes[j].password == NULL &&
                    compare_hashes(hex_hash, args->cracked_hashes[j].hash)) {
                    args->cracked_hashes[j].password = strdup(password);
                    args->cracked_hashes[j].alg = algs[i];
                    pthread_mutex_unlock(args->mutex);
                    break;
                }
                pthread_mutex_unlock(args->mutex);
            }

            free(hash);
        }
    }

    return NULL;
}


// Function name: crack_hashed_passwords
// Description:   Computes different hashes for each password in the password list,
//                then compare them to the hashed passwords to decide whether if
//                any of them matches this password. When multiple passwords match
//                the same hash, only the first one in the list is printed.
void crack_hashed_passwords(char *password_list, char *hashed_list, char *output) {
	FILE *fp;
	char password[256];  // passwords have at most 255 characters
	char hex_hash[2*KEEP+1]; // hashed passwords have at most 'keep' characters

	// load hashed passwords
	int n_hashed = 0;
	struct cracked_hash *cracked_hashes;
	fp = fopen(hashed_list, "r");
	assert(fp != NULL);
	while(fscanf(fp, "%s", hex_hash) == 1)
		n_hashed++;
	rewind(fp);
	cracked_hashes = (struct cracked_hash *) malloc(n_hashed*sizeof(struct cracked_hash));
	assert(cracked_hashes != NULL);
	for(int i=0; i < n_hashed; i++) {
		fscanf(fp, "%s", cracked_hashes[i].hash);
		cracked_hashes[i].password = NULL;
		cracked_hashes[i].alg = NULL;
	}
	fclose(fp);

	// Load all passwords into memory
	char **passwords = NULL;
	int n_passwords = 0;
	int capacity = 1000; // start with room for 1000 passwords
	passwords = (char **)malloc(capacity * sizeof(char *));
	assert(passwords != NULL);

	fp = fopen(password_list, "r");
	assert(fp != NULL);
	while (fscanf(fp, "%s", password) == 1) {
		if (n_passwords >= capacity) {
			capacity *= 2;
			passwords = (char **)realloc(passwords, capacity * sizeof(char *));
			assert(passwords != NULL);
		}
		passwords[n_passwords] = strdup(password);
		n_passwords++;
	}
	fclose(fp);

	// Set up pthreads
	int n_threads = 4;
	pthread_t threads[n_threads];
	struct thread_args thread_data[n_threads];
	pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

	int chunk_size = n_passwords / n_threads;
	for (int i = 0; i < n_threads; i++) {
		thread_data[i].passwords = passwords;
		thread_data[i].start = i * chunk_size;
		thread_data[i].end = (i == n_threads - 1) ? n_passwords : (i + 1) * chunk_size;
		thread_data[i].cracked_hashes = cracked_hashes;
		thread_data[i].n_hashed = n_hashed;
		thread_data[i].mutex = &mutex;

		pthread_create(&threads[i], NULL, worker_thread, &thread_data[i]);
	}

	for (int i = 0; i < n_threads; i++) {
		pthread_join(threads[i], NULL);
	}

	// load common passwords, hash them, and compare them to hashed passwords
	// fp = fopen(password_list, "r");
	// assert(fp != NULL);
	// while(fscanf(fp, "%s", password) == 1) {
	// 	for(int i=0; i < n_algs; i++) {
	// 		unsigned char *hash = fn[i]((unsigned char *)password, strlen(password));
	// 		for(int j=0; j < KEEP; j++)
	// 			sprintf(&hex_hash[2*j], "%02x", hash[j]);
	// 		hex_hash[2*KEEP] = '\0';
	// 		for(int j=0; j < n_hashed; j++) {
	// 			if(cracked_hashes[j].password !=  NULL)
	// 				continue;
	// 			if(compare_hashes(hex_hash, cracked_hashes[j].hash)) {
	// 				cracked_hashes[j].password = strdup(password);
	// 				cracked_hashes[j].alg = algs[i];
	// 				break;
	// 			}
	// 		}
	// 		free(hash);
	// 	}
	// }
	// fclose(fp);



	// print results
// 	fp = fopen(output, "w");
// 	assert(fp != NULL);
// 	for(int i=0; i < n_hashed; i++) {
// 		if(cracked_hashes[i].password ==  NULL)
// 			fprintf(fp, "not found\n");
// 		else
// 			fprintf(fp, "%s:%s\n", cracked_hashes[i].password, cracked_hashes[i].alg);
// 	}
// 	fclose(fp);

// 	// release stuff
// 	for(int i=0; i < n_hashed; i++)
// 		free(cracked_hashes[i].password);
// 	free(cracked_hashes);
// }

	// print results
	fp = fopen(output, "w");
	assert(fp != NULL);
	for (int i = 0; i < n_hashed; i++) {
		if (cracked_hashes[i].password == NULL)
			fprintf(fp, "not found\n");
		else
			fprintf(fp, "%s:%s\n", cracked_hashes[i].password, cracked_hashes[i].alg);
	}
	fclose(fp);

	// release stuff
	for (int i = 0; i < n_hashed; i++)
		free(cracked_hashes[i].password);
	free(cracked_hashes);

	for (int i = 0; i < n_passwords; i++)
		free(passwords[i]);
	free(passwords);

	pthread_mutex_destroy(&mutex);
}