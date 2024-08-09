 
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <gmp.h>
#include "bkem.h"
#include <time.h>
clock_t t,t1,t0,t2,t4;
void setup_global_system(bkem_global_params_t *gps, const char *pstr, int N) {
    
    bkem_global_params_t params;
    params = pbc_malloc(sizeof(struct bkem_global_params_s));

    params->N = N;
    
    pairing_init_set_str(params->pairing, pstr);

    *gps = params;
}

void setup(bkem_system_t *sys, bkem_global_params_t gps) 
{
    t0 = clock();
     
    bkem_system_t gbs;
    bkem_secret_key_t sk;
    gbs = pbc_malloc(sizeof(struct bkem_system_s));
    gbs->PK = pbc_malloc(sizeof(struct pubkey_s));

    // ---------------------------------Choose random generator g --------------------------------------------
    element_init_G1(gbs->PK->g, gps->pairing);
    element_random(gbs->PK->g);

    //----------------------------------Choose another generator ghat=gg--------------------------------------
    element_init_G2(gbs->PK->gg, gps->pairing);
    element_random(gbs->PK->gg);

    // ---------------------------------random alpha in Zn ---------------------------------------------------
    element_t alpha;
    element_init_Zr(alpha, gps->pairing);
    element_random(alpha);

    // ---------------------------------random beta in Zn-----------------------------------------------------
    element_t beta1;
    element_init_Zr(beta1, gps->pairing);
    element_random(beta1);

    // ---------------------------------random xhat in Zn ----------------------------------------------------
    element_t xhat;
    element_init_Zr(xhat, gps->pairing);
    element_random(xhat);

    // ---------------------------------random yhat in Zn ----------------------------------------------------
    element_t yhat;
    element_init_Zr(yhat, gps->pairing);
    element_random(yhat);

    /*
    element_printf("alpha = %B\n", alpha);
    element_printf("beta1 = %B\n", beta1);
    element_printf("xhat = %B\n", xhat);
    element_printf("yhat = %B\n\n", yhat);
    */	

   // -------------------------------Compute the component of MPK ---------------------------------------------
    gbs->PK->g_i = pbc_malloc( 6 * sizeof(element_t));
    int size_of_MPK=7 * sizeof(element_t);
    //element_printf("size_of_MPK = %d in bytes\n\n", size_of_MPK);
    
   // element_printf("Compute the component of MPK\n");
	
     //-----------------------------Set the first element to g--------------------------------------------------
    element_init_G1(gbs->PK->g_i[0], gps->pairing);
    element_set(gbs->PK->g_i[0],gbs->PK->g);
    //element_printf("g = %B\n\n", gbs->PK->g_i[0]);
    
    //-------------------------------Set the first element to ghat---------------------------------------------
    element_init_G2(gbs->PK->g_i[1], gps->pairing);
    element_set(gbs->PK->g_i[1],gbs->PK->gg);
    //element_printf("ghat = %B\n\n", gbs->PK->g_i[1]);
   
    //-------------------------------Set the first element to Omega= e(g, ghat)^(alpha.beta)--------------------------------
    element_t omega,lambda, p1,p2,p3,p4,p5;
    element_init_GT(omega, gps->pairing); 
    element_init_GT(p1, gps->pairing); 
    pairing_apply(p1, gbs->PK->g, gbs->PK->gg, gps->pairing);
    element_init_Zr(p2, gps->pairing); 
    element_mul(p2,alpha,beta1); 
    element_pow_zn(omega, p1, p2);
    //element_printf("omega = %B\n\n", omega);
    element_init_GT(gbs->PK->g_i[2], gps->pairing);
    element_set(gbs->PK->g_i[2], omega);
    //element_printf("omega = %B\n\n", gbs->PK->g_i[2]);
     
    
    //-------------------------------Set the first element to Lambda= e(g, ghat)^(alpha.(beta-1))--------------------------------
    element_init_GT(lambda, gps->pairing); 
    element_init_Zr(p3, gps->pairing);
    element_init_Zr(p5, gps->pairing);
    element_set1(p5);
    element_sub(p3,beta1,p5);
    element_init_Zr(p4, gps->pairing);
    element_mul(p4,alpha,p3);
    element_pow_zn(lambda, p1, p4);
    //element_printf("lambda = %B\n\n", lambda);
    element_init_GT(gbs->PK->g_i[3], gps->pairing);
    element_set(gbs->PK->g_i[3], lambda);
    //element_printf("lambda = %B\n\n", gbs->PK->g_i[3]);
     
    
    //-------------------------------Set the first element to Xhat=(ghat)^xhat-------------------------------------
    element_init_G2(gbs->PK->g_i[4], gps->pairing);
    element_pow_zn(gbs->PK->g_i[4], gbs->PK->gg, xhat);
    //element_printf("Xhat = %B\n\n", gbs->PK->g_i[4]);
    
    //------------------------------Set the first element to Yhat=(ghat)^yhat----------------------------------------
    element_init_G2(gbs->PK->g_i[5], gps->pairing);
    element_pow_zn(gbs->PK->g_i[5], gbs->PK->gg, yhat);
    //element_printf("Yhat = %B\n\n", gbs->PK->g_i[5]);
    

    //t0 = clock() - t0;
    double time_taken0 = ((double)t0)/CLOCKS_PER_SEC; // in seconds 
    //printf("Setup took %f seconds to execute \n\n", time_taken0);  
    
     
    int size_of_MSK=3 * sizeof(element_t);
    //element_printf("size_of_MSK = %d in bytes\n\n", size_of_MSK);
   
   //------------------MPK and MSK generation is done ----------------------------------------------------------------
   
  
   //------------------------ Compute the private keys SK_j_i -----------------------------------------------------
   int i,j;
   for(i=0;i<4;i++)
   {
   	element_t ttt;
   	element_init_Zr(ttt, gps->pairing);
   	element_random(ttt);
   	element_init_Zr(gbs->t[i], gps->pairing);
   	element_set(gbs->t[i],ttt);
   }
  //------------------------------------------------------------
  
   element_t d,d1,d2,d3,d4,t,t1,t2,t3,r5,F,FF,d_40,d_41;
   element_init_G2(d_40, gps->pairing);
   element_pow_zn(d_40, gbs->PK->gg, alpha);
   element_init_G2(gbs->SK[0], gps->pairing);
   element_set(gbs->SK[0],d_40);
   //element_printf("d_40= %B\n\n", d_40); //1st component of secret key. 
   element_init_G2(d_41, gps->pairing);
   element_init_Zr(r5, gps->pairing);
   element_random(r5);
   element_pow_zn(d_41, gbs->PK->gg ,r5);
   element_init_G2(gbs->SK[1], gps->pairing);
   element_set(gbs->SK[1],d_41);
   //element_printf("d_41= %B\n\n", d_41); //2nd component of secret key. 
   
 
   
 	//t0 = clock() - t0;
    	//double time_taken1 = ((double)t0)/CLOCKS_PER_SEC; // in seconds 
    	//printf("KeyGen took %f seconds to execute \n\n", time_taken1);  
    	
       *sys = gbs;
    	element_clear(alpha);
    	element_clear(beta1);
	element_clear(xhat);
	element_clear(yhat);
   
 }
//----------------------------Key Gen is done -----------------------------------------------------------------


//----------------------------------------Encryption ---------------------------------------------------------

void get_enc_key(header_t hdr,  bkem_system_t gbs, bkem_global_params_t gps) 
{	
        
        element_t M,s,t1,t2,t3,t4,t5,t6,t7,tt,r1;
	element_init_Zr(s, gps->pairing);
	element_random(s);
	element_init_GT(M, gps->pairing);
      	element_random(M);
      	//element_printf("The original message= %B\n\n", M);
      	
      	//-------------------------------------1st ciphertext component (C_0) --------------------------------
      	element_init_GT(gbs->C_0, gps->pairing);
      	element_init_GT(tt, gps->pairing);
        element_pow_zn(tt,gbs->PK->g_i[2],s);
        element_mul(gbs->C_0,M,tt);
        //element_printf("C_0= %B\n\n", gbs->C_0);
	
	//------------------------------------- ciphertext component (C_1) --------------------------------
        element_init_GT(gbs->C_1, gps->pairing);
        element_pow_zn(gbs->C_1,gbs->PK->g_i[3],s);
        //element_printf("C_1= %B\n\n", gbs->C_1);
	
	//------------------------------------- ciphertext component (C_2) --------------------------------
        element_init_G1(gbs->C_2, gps->pairing);
        element_pow_zn(gbs->C_2,gbs->PK->g,s);
        //element_printf("C_2= %B\n\n", gbs->C_2);
        
       //------------------------------------- ciphertext component (C_31) --------------------------------
        element_t b1;
        element_init_Zr(b1, gps->pairing);
        element_mul(b1,s,gbs->t[1]);
        element_init_G1(gbs->C_31, gps->pairing);
        element_pow_zn(gbs->C_31,gbs->PK->g,b1);
        //element_printf("C_31= %B\n\n", gbs->C_31);
        
        //------------------------------------- ciphertext component (C_32) --------------------------------
        element_t b2;
        element_init_Zr(b2, gps->pairing);
        element_mul(b2,s,gbs->t[2]);
        element_init_G1(gbs->C_32, gps->pairing);
        element_pow_zn(gbs->C_32,gbs->PK->g,b2);
        //element_printf("C_32= %B\n\n", gbs->C_32);
        
        //------------------------------------- ciphertext component (C_33) --------------------------------
        element_t b3,b4;
        element_init_Zr(b3, gps->pairing);
        element_add(b3,gbs->t[1],gbs->t[3]);
        element_init_Zr(b4, gps->pairing);
        element_mul(b4,b3,s);
        element_init_G1(gbs->C_33, gps->pairing);
        element_pow_zn(gbs->C_33,gbs->PK->g,b4);
        //element_printf("C_33= %B\n\n", gbs->C_33);
	
	
       element_clear(s);         	
}


void get_decryption_key(bkem_global_params_t gps, bkem_system_t gbs, pubkey_t PK)
 {
 //---------------------------------------------------------------------------------------------------
 	element_t b6,b7,b8,b9,b10;
 	element_init_GT(b6, gps->pairing);
 	element_set1(b6);
 	element_init_GT(b7, gps->pairing);
 	pairing_apply(b7, gbs->C_2, gbs->SK[0], gps->pairing);
 	element_init_GT(b8,gps->pairing);
 	element_div(b8,b6,b7);
 	element_init_GT(b9,gps->pairing);
 	element_div(b9,gbs->C_0,gbs->C_1);
	element_init_GT(b10,gps->pairing);
 	element_mul(b10,b9,b8);
 	//element_printf("The message after decryption = %B\n\n", b10);
 	
}


void free_global_params(bkem_global_params_t gbs) {
    if (!gbs)
        return;

    pairing_clear(gbs->pairing);
    free(gbs);
}

void free_pubkey(pubkey_t pk, bkem_global_params_t gbs) {
    if (!pk)
        return;

    element_clear(pk->g);

    int i;
    for (i = 0; i <= gbs->N; ++i) {
        element_clear(pk->g_i[i]);
    }

    //for (i = 0; i < gbs->A; ++i) {
       // element_clear(pk->v_i[0]);
    //}

}

void free_bkem_system(bkem_system_t sys, bkem_global_params_t gbs) {
    if (!sys)
        return;

    free_pubkey(sys->PK, gbs);

    int i;
    /*for (i = 0; i < gbs->N; ++i) {
        element_clear(sys->d_i[i]);
    }*/
}
