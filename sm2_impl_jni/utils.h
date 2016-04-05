#ifndef ___UTILS__H____
#define  ___UTILS__H____


int GetPubkeyFromSM2Cert(unsigned char  szPubkey_XY[64], 
						const unsigned char * derSm2Cert, 
						unsigned long  ulderSm2CertLen);


int genRand(unsigned char rand[32]);

int XOR_STRING(unsigned char * tar, unsigned char * x, unsigned char * y, int l);

#endif //___UTILS__H____