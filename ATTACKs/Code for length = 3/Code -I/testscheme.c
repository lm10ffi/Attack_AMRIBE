#include "bkem.h"
#include <time.h>
clock_t t,t1,t0,t2,t4; 
     
int main(int argc, const char *argv[]) {

	FILE *param = fopen("a.param", "r");
	char buf[4096];
	fread(buf, 1, 4096, param);
    
    		//printf("\nSystem setup Key\n\n");

	bkem_global_params_t gps;
	setup_global_system(&gps, (const char*) buf, (argc > 1) ? atoi(argv[1]) : 1024);

		//printf("Global System parameters: N = %d\n\n", gps->N);

	bkem_system_t sys;
	
		t4 = clock();
		setup(&sys, gps);
      		t4 = clock() - t4;
      	
 	double time_taken4 = ((double)t4)/(CLOCKS_PER_SEC); // in seconds 
 	printf("Setup & KeyGen algorithm took %f seconds to execute \n", time_taken4); 
    
		t = clock();
  		header_t hdr;
		get_enc_key(hdr,sys,gps);
        	t = clock() - t; 

   	double time_taken = ((double)t)/(CLOCKS_PER_SEC); // in seconds 
  	printf("Encryption algorithm took %f seconds to execute \n", time_taken); 

    		t2 = clock();
          	get_decryption_key(gps, sys, sys->PK);
          	t2 = clock() - t2;
    
     	double time_taken2 = ((double)t2)/(CLOCKS_PER_SEC); // in seconds 
 	printf("decryption algorithm took %f seconds to execute \n\n", time_taken2);      
      

    }
    
