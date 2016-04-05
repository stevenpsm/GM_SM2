


#ifndef ___LIB_SM2_DER_LIB_H____
#define ___LIB_SM2_DER_LIB_H____
#ifndef OUT
#define IN
#define OUT
#endif //OUT


#define ERROR_PARAM    -1
#define ERROR_UNKNOWN  -2

#define ERROR_DECODE   65
#define ERROR_ENCODE   66

#define ERROR_MEM_LOW  -3    
#define ERROR_MEM_CALLOC -4
#define ERROR_NO_ISSUER_CERT -5


#ifdef _LINUX 
#define BYTE unsigned char
#endif //_LINUX


#ifdef __cplusplus
extern "C"{
#endif


int sm2EncodePubkey(OUT unsigned char * derPubkey, OUT unsigned long * ulDerPubl, 
					IN unsigned char pub_XY[64]);

int sm2DecodePubkey(OUT unsigned char pub_XY[64], 
					IN unsigned char * derPubkey, IN unsigned long ulDerPubl);

int sm2EncodePrikey(OUT unsigned char * derPrikey, OUT unsigned long * ulDerPrikl,
					IN unsigned char randPrikey[32], IN unsigned char pub_XY[64]);

int sm2DecodePrikey(OUT unsigned char sm2_prikey[32], OUT unsigned char sm2_pubXY[64], 
					IN unsigned char * derPrikey, IN unsigned long ulderPrikeyLen);

int sm2EncodeCipher(OUT unsigned char * SM2CipherDer, OUT unsigned long * ulSM2CipherDerLen, 
					IN unsigned char * Cipher, IN unsigned long ulCipherLen,
					IN unsigned char pub_XY[64], IN unsigned char sm3hash[32]);

int sm2DecodeCipher(OUT unsigned char pub_XY[64], OUT unsigned char sm3hash[32],
					OUT unsigned char * Cipher, OUT unsigned long * ulCipherLen,
					IN unsigned char * SM2CipherDer, IN unsigned long SM2CipherDerLen);

// R\S will always be positive
int sm2EncodeSignature(OUT unsigned char * derSig, OUT unsigned long * ulderSigL,
					   IN unsigned char sig[64]);

int sm2DecodeSignature(OUT unsigned char sig[64], 
					   IN unsigned char * derSig, IN unsigned long ulderSigL);
#ifdef __cplusplus
};
#endif


#endif //___LIB_SM2_DER_LIB_H____
