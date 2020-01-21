# LACAttack

This code uses the LAC implementation, that can be found at : https://csrc.nist.gov/projects/post-quantum-cryptography/round-2-submissions

1. Add our code in the folder optimized or reference implementation

2. Add to the Makefile:
  * Add to object the line: attaque.o
  * In the following add the line : attaque.o: attaque.c api.h rand.h ecc.h lac_param.h
	                                      gcc -c attaque.c $(cflags)
                                       
To launch our attack, you need to use the function recover_s() that:
  1. Generate private and public keys using LAC key generation function
  2. Recover the secret key
  3. Print the recover secret key and after the original secret key
