/**
 * @file BKEM.h
 * @brief General construction of the Boneh-Gentry-Waters 
 * broadcast key encapsulation scheme 
 *
 * BKEM is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * BKEM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with BKEM.  If not, see <http://www.gnu.org/licenses/>.
 * 
 * Oliver Guenther
 * mail@oliverguenther.de
 *
 * 
 * BKEM.h
*/

#ifndef H_BKEM
#define H_BKEM

#include <string.h>
#include <pbc/pbc.h>

/**
  @typedef Global broadcast system parameters
 */
 
#define MAX_m  16            // Max channels
#define MAX_n  64            // Max subscribers
#define MAX_N MAX_m * MAX_n + 1
#define MAX_SET MAX_n         // Here, Sets are  Users in Channel Sj

 
typedef struct bkem_global_params_s {
	pairing_t pairing;
	int N;
	
}* bkem_global_params_t;

/**
 * @typedef Public Key
 * Contains generator g, 2B-2 elements g[i] and A elements v[i]
 */
typedef struct pubkey_s {
    element_t g; // generator
    element_t gg; // generator
    element_t *g_i; // 1 element
    element_t *gg_i; // 3 elements
    element_t *v_i; // A elements
    element_t *X_i; // A elements
    element_t *gh_i; // A elements
    
}* pubkey_t;

/***
*
*
*/	
typedef struct
{
    int useri,channelj;  // User user_i  subscribe to chanel channel_j
} ID;


/**
 * @typedef broadcast system instance
 */
typedef struct bkem_system_s {
	pubkey_t PK;
	/** Private key of user s */
	element_t d[MAX_m][MAX_n][3];
	element_t hash_store[MAX_m][MAX_n];
	element_t all_hash_sum;
	element_t channel_hash_sum[MAX_m];
	element_t check;
	element_t C_1_x[MAX_m];
	element_t M_x[MAX_m];
	element_t C_22_x[MAX_m];
	element_t C_2_x[MAX_m];
	element_t SK[2];
	element_t C_0;
	element_t C_1;
	element_t C_2;
	element_t C_31;
	element_t C_32;
	element_t C_33;
	element_t t[4];
	
}* bkem_system_t;
/**
* Variable for Secret key 
*/

typedef struct bkem_secret_key_s {
	/** Private key of user s */
	element_t d[MAX_m][MAX_n][3];
}* bkem_secret_key_t;


/**
 * @typedef Keypair (HDR, K) [A+1, 1] elements
 */

typedef struct header_s {
    element_t C_0;
    element_t C_1_x[MAX_m];
    element_t C_2_x[MAX_m];
    element_t theta_x[MAX_m];
    element_t Gamma_x[MAX_m];
    
}* header_t;


typedef struct kpair_s {
    element_t *HR;
}* kpair_t;
typedef struct keypair_s {
    element_t *HDR;
    element_t K;
}* keypair_t;



/**
 * @brief Free a keypair_t
 */
void free_pubkey(pubkey_t pk, bkem_global_params_t gbs);


/**
 * @brief Free a bkem_system_t
 */
void free_bkem_system(bkem_system_t sys, bkem_global_params_t gbs);


/**
 * @brief Free a global_broadcast_params_t
 */
void free_global_params(bkem_global_params_t gbs);



/**
 * Setup global broadcast system parameters
 * @param[out] gps bkem_global_params_t pointer
 * @param[in] params Pairing Type paramters as string
 * @param[in] n number of users in the system
 */
void setup_global_system(bkem_global_params_t *gps, const char *params, int n);

/**
 * Setup broadcast key encapsulation system
 * @param[out] sys bkem_system_t pointer
 * @param[in] gps bkem_global_params_t pointer
 */
void setup(bkem_system_t *sys, bkem_global_params_t gps);

/**
 * Output encryption Keypair
 * @param[out] keypair pointer to encryption pair output
 * @param[in] S receiver array [indices of participating users]
 * @param[in] num_recip Number of elements in S
 * @param[in] sys Broadcast encryption parameters
 */
void get_encryption_key(keypair_t *key, int *S, int num_recip, bkem_system_t sys, bkem_global_params_t gps);
void grouptoken(keypair_t *key, int *S, int num_recip, bkem_system_t sys, bkem_global_params_t gps);
void get_enc_key(header_t Header, bkem_system_t sys, bkem_global_params_t gps);
/**
 * Output decryption Key
 * @param[out] K decryption key pointer
 * @param[in] gps global system parameters
 * @param[in] S receivers [indices of participating users]
 * @param[in] num_recip Number of elements in S
 * @param[in] i index of user
 * @param[in] d_i private key of user i
 * @param[in] HDR header
 * @param[in] PK public key
 */
void get_decryption_key(bkem_global_params_t gbs, bkem_system_t sys, pubkey_t PK);


#endif
