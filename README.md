# LACAttack

This code uses the LAC implementation, that can be found at : https://csrc.nist.gov/projects/post-quantum-cryptography/round-2-submissions

To launch our attack:
1. Add our code in the folder optimized or reference implementation

2. Add to the Makefile :
  * Add to object (at the end of the line): <pre><code>attack.o</code></pre>
  * Add to main.o: <pre><code>attack.h</code></pre> 
  * Between rng.o and clean, add the line : <pre><code>attack.o: attack.c api.h rand.h ecc.h lac_param.h attack.h
<br/>    gcc -c attack.c $(cflags)</code></pre>
3. Add to main.c <pre><code>#include "attack.h"</code></pre>  

You can modify the level of security in lac_param.h. Don't use the constant bch implementation.

You need to use the function recover_s() that:
  1. Generate private and public keys using LAC key generation function
  2. Recover the secret key
  3. Print the recover secret key and the original one
