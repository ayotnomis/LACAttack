#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "api.h"
#include "lac_param.h"
#include "ecc.h"
#include "bin-lwe.h"


int oracle(unsigned char *m, unsigned char *_m, int size)
{
    for(int i=0; i<size; i++)
    {
        if(m[i] != _m[i])
        {
            return 0;//mismatch
        }
    }
    return 1;
}

int forge(int cas, int hyp, unsigned int bit, unsigned char *m, unsigned char *c)
{
    unsigned int shift_bit = DIM_N - bit ; //The shifted value (n-w)
    unsigned char code[CODE_LEN];  
    unsigned char m_buf[MESSAGE_LEN]; 
    unsigned char c2[C2_VEC_NUM]; 
    unsigned long long mlen=CRYPTO_BYTES;
    int c2_len=(mlen+ECC_LEN)*8; //Compute the length of c2

    memset(m,0,CRYPTO_BYTES);
    memset(c,0,CRYPTO_CIPHERTEXTBYTES);
    memset(m_buf,0,MESSAGE_LEN);
    memset(c2,0,C2_VEC_NUM); 
    memset(code,0,CODE_LEN);

    m[0] = 0x80; //Generate a message with the first bit at 1
    memcpy(m_buf+(DATA_LEN-mlen),m,mlen);//Set data
    ecc_enc(m_buf,code);//Encode m with bch code.

    //Inject 8 errors for LAC192 and 16 errors for LAC128-256
    #if defined LAC192 
    code[2] = 0xff;
    #else 
    code[2] = 0xff;
    code[3] = 0xff;
    #endif
    

    #if defined LAC256 
    if(cas==1 || cas==2 || cas==3 || cas==4)
        if (bit == 0)
            c[0] = 0x20; //c1=q/7 
        else
            c[shift_bit] = 0xd0; //c1=-q/7X^(n-w) 
    else
        if (bit == 0)
            c[0] = 0x30; //c1=q/5
        else
            c[shift_bit] = 0xc0; //c1 = -q/5X^(n-w)

    //The first bit and the c2_len/2 bit of c2 contain our keys hypothesis    
    if (cas == 1)
    {
        c2[0] = 0x20; //q/7
        c2[c2_len] = 0x20; //q/7
    }
    else if (cas == 2)
    {
        c2[0] = 0xe0; //-q/7 
        c2[c2_len] = 0xd0; //-q/7  different values to compensate approximation
    }
    else if (cas == 3)
    {
        c2[0] = 0x20; //q/7
        c2[c2_len] = 0xd0; //-q/7
    }
    else if (cas == 4)
    {
        c2[0] = 0xd0; //-q/7
        c2[c2_len] = 0x20; //q/7
    }
    else if (cas == 5)
    {
        c2[0] = 0x30; //q/5
        c2[c2_len] = 0x30;
    }
    else if (cas == 6)
    {
        c2[0] = 0x30; //q/5
        c2[c2_len] = 0xc0; //-q/5
    }
    else if (cas == 7)
    {
        c2[0] = 0xc0; //-q/5 
        c2[c2_len] = 0xc0; //-q/5
    }
    else if (cas == 8)
    {
        c2[0] = 0xc0; //-q/5
        c2[c2_len] = 0x30; //q/5
    }

    #else // LAC126 and 192
    if (bit == 0)
        c[0] = 0x20; //c1=q/7 
    else
        c[shift_bit] = 0xd0; //c1=-q/7X^(n-w)  
    //The first bit of c2 contains our key hypothesis
    if (hyp == 1)
    {
        c2[0] = 0x20; //q/7
    }
    else
    {
        c2[0] = 0xd0; //6q/7
    }
    #endif
    //Construct the others bits of c2 to monitor Alice's decryption 
    for(int i=1; i<c2_len; i++)
    {
        if(code[i/8]&1<<((i%8)))
        {
            c2[i] = 0x80; //q/2
            #if defined LAC256 
            c2[i+c2_len] = 0x80; //q/2
            #endif 
        }
        else
        {
            c2[i] = 0x00;
            #if defined LAC256 
            c2[i+c2_len] = 0x00; //q/2
            #endif      
        }
    }
    #if defined LAC256 
    poly_compress(c2,c+DIM_N,c2_len*2);//compress c2
    #else
	poly_compress(c2,c+DIM_N,c2_len);//compress c2
    #endif

    return 0;
}

char recover_bit_s(unsigned int bit, unsigned char *sk)
{
    unsigned char m[CRYPTO_BYTES]; // taille 32
    unsigned char c[CRYPTO_CIPHERTEXTBYTES]; // taille 712 : 512 pour c1 et 200 pour c2
    unsigned char m_recover[CRYPTO_BYTES];
    unsigned long long mlen=CRYPTO_BYTES, clen=CRYPTO_CIPHERTEXTBYTES;

    memset(m_recover,0,CRYPTO_BYTES);

    forge(0, -1, bit, m, c);
    crypto_encrypt_open(m_recover, &mlen, c, clen, sk);
    if(!oracle(m, m_recover, CRYPTO_BYTES))
    {
        return 0x01;
    }

    memset(m_recover,0,CRYPTO_BYTES);

    forge(0, 1, bit, m, c);
    crypto_encrypt_open(m_recover, &mlen, c, clen, sk);
    if (!oracle(m, m_recover, CRYPTO_BYTES))
    {
        return 0xFF;
    }

    return 0x00;
}

int recover_bit_s_256(unsigned int bit, unsigned char *sk, unsigned char *recover)
{
    unsigned char m[CRYPTO_BYTES]; // taille 32
    unsigned char c[CRYPTO_CIPHERTEXTBYTES]; // taille 712 : 512 pour c1 et 200 pour c2
    unsigned char m_recover[CRYPTO_BYTES];
    unsigned long long mlen=CRYPTO_BYTES, clen=CRYPTO_CIPHERTEXTBYTES;

    clen=CRYPTO_CIPHERTEXTBYTES;

    memset(m_recover,0,CRYPTO_BYTES);

    forge(1, 0, bit, m, c);
    crypto_encrypt_open(m_recover, &mlen, c, clen, sk);
    if(!oracle(m, m_recover, CRYPTO_BYTES))
    {
        recover[0] = 0xff;
        recover[1] = 0xff;
        return 0;
    }

    forge(2, 0, bit, m, c);
    crypto_encrypt_open(m_recover, &mlen, c, clen, sk);
    if(!oracle(m, m_recover, CRYPTO_BYTES))
    {
        recover[0] = 0x01;
        recover[1] = 0x01;
        return 0;
    }

    forge(3, 0, bit, m, c);
    crypto_encrypt_open(m_recover, &mlen, c, clen, sk);
    if(!oracle(m, m_recover, CRYPTO_BYTES))
    {
        recover[0] = 0xff;
        recover[1] = 0x01;
        return 0;
    }

    forge(4, 0, bit, m, c);
    crypto_encrypt_open(m_recover, &mlen, c, clen, sk);
    if(!oracle(m, m_recover, CRYPTO_BYTES))
    {
        recover[0] = 0x01;
        recover[1] = 0xff;
        return 0;
    }

    forge(5, 0, bit, m, c);
    crypto_encrypt_open(m_recover, &mlen, c, clen, sk);
    if(!oracle(m, m_recover, CRYPTO_BYTES))
    {
        forge(6, 0, bit, m, c);
        crypto_encrypt_open(m_recover, &mlen, c, clen, sk);
        if(!oracle(m, m_recover, CRYPTO_BYTES))
        {
            recover[0] = 0xff;
            recover[1] = 0x00;
            return 0;
        }
        recover[0] = 0x00;
        recover[1] = 0xff;
        return 0;
    }

    
    forge(7, 0, bit, m, c);
    crypto_encrypt_open(m_recover, &mlen, c, clen, sk);
    if(!oracle(m, m_recover, CRYPTO_BYTES))
    {
        forge(8, 0, bit, m, c);
        crypto_encrypt_open(m_recover, &mlen, c, clen, sk);
        if(!oracle(m, m_recover, CRYPTO_BYTES))
        {
            recover[0] = 0x01;
            recover[1] = 0x00;
            return 0;
        }
        recover[0] = 0x00;
        recover[1] = 0x01;
        return 0;
    }

    recover[0] = 0x00;
    recover[1] = 0x00;
    return 0;
}

int recover_s()
{
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[DIM_N];
    unsigned char sk_recover[DIM_N];
    unsigned char recover[2];
    int diff = 0;
    int random = 0;
    time_t t;
    /* Intializes random number generator */
    srand((unsigned) time(&t));
    //Generate a random between 1 and 151
    random = rand() % 150 + 1;
    
    for (int i=0; i<random; i++)
    {
        kg(pk,sk); //Lac function to generate keys
    }

    memset(sk_recover,0,DIM_N);
    memset(recover,0, 2);

    #if defined LAC256
    for (int i=0; i<DIM_N - C2_VEC_NUM/2; i++)
    {
        recover_bit_s_256(i, sk, recover);
        sk_recover[i] = recover[0];
        sk_recover[i + C2_VEC_NUM/2] = recover[1];
    }
    #else
    for (int i=0; i<DIM_N; i++)
    {
        sk_recover[i] = recover_bit_s(i, sk);
    }
    #endif

    for (int i=0; i<DIM_N; i++)
    {
        if(sk_recover[i] != sk[i])
        {     
            printf("%i\n", i);           
            diff += 1;
        }
    }
    printf("diff = %i\n\n", diff);

    printf("-------Alice secret key--------\n");
    for(int i=0; i<DIM_N; i++)
    {
	printf("%02x.", sk[i]);
    }
    printf ("\n");
    printf("------------------------------\n");
    printf("-----Recovered secret key-----\n");
    for(int i=0; i<DIM_N; i++)
    {
	printf("%02x.", sk_recover[i]);
    }
    printf ("\n"); 
    printf("------------------------------\n");
    
    return diff;
}
