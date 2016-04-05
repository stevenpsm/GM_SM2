#include "libSm2der.h"
#include "EccPublicKey.h"
#include "ECPrivateKey.h"
#include "SM2Cipher.h"
#include "SM2Signature.h"

//回调函数，将编解码值输出缓冲
static int write_out(const void *buffer, size_t size, void **app_key) 
{
	BYTE *out_fp = (BYTE *)*app_key;
	memcpy(out_fp, buffer, size);
	out_fp += size;
	*app_key = (void*)out_fp;
	return 0;
}

int sm2EncodePubkey(OUT unsigned char * derPubkey, OUT unsigned long * ulDerPubl, 
					IN unsigned char pub_XY[64])
{
	/* Define an OBJECT IDENTIFIER value */
	EccPublicKey_t *myEccPub;
	int ret = 0;
	unsigned char target[2000] = {0};
	BYTE * bp = NULL;
	
	int oid1[] = { 1, 2, 840, 10045, 2, 1}; /* or whatever */
	int oid2[] = { 1, 2, 156, 10197, 1, 301};
	OBJECT_IDENTIFIER_t *p_oid1 = NULL;
	OBJECT_IDENTIFIER_t *p_oid2 = NULL;
	asn_enc_rval_t ec; /* Encoder return value */
	
	if ( NULL == derPubkey || 0 == *ulDerPubl)
	{
		return -1;
	}
	
	p_oid1 = calloc(1,sizeof(OBJECT_IDENTIFIER_t));
	if (p_oid1 == NULL)
	{
		ret = ERROR_MEM_CALLOC;
		goto END;
	}
	p_oid2 = calloc(1,sizeof(OBJECT_IDENTIFIER_t));
	if (p_oid2 == NULL)
	{
		ret = ERROR_MEM_CALLOC;
		goto END;
	}
	
	memset(p_oid1, 0x00, sizeof(OBJECT_IDENTIFIER_t));
	memset(p_oid2, 0x00, sizeof(OBJECT_IDENTIFIER_t));
	
	/* Allocate an instance of MyTypes */
	myEccPub = calloc(1, sizeof(EccPublicKey_t));
	if (myEccPub == NULL)
	{
		ret = ERROR_MEM_CALLOC;
		goto END;
	}
	
	memset(myEccPub, 0x00, sizeof(EccPublicKey_t));
	
	/*
	* Fill in myObjectId
	*/
	ret = OBJECT_IDENTIFIER_set_arcs(p_oid1,
		oid1, sizeof(oid1[0]), sizeof(oid1) / sizeof(oid1[0]));
	if (ret)
	{
		goto END;
	}
	
	ret = OBJECT_IDENTIFIER_set_arcs(p_oid2,
		oid2, sizeof(oid2[0]), sizeof(oid2) / sizeof(oid2[0]));
	if (ret)
	{
		goto END;
	}
	
	/* Fill in mySeqOf with the prepared INTEGER */
	ret = ASN_SEQUENCE_ADD(&myEccPub->objIds, p_oid1);
	if (ret)
	{
		goto END;
	}
	
	ret = ASN_SEQUENCE_ADD(&myEccPub->objIds, p_oid2);
	if (ret)
	{
		goto END;
	}
	
	/* Allocate some space for bitmask */
	myEccPub->eccPublicKey.buf = calloc(1, 65);
	if (NULL == myEccPub->eccPublicKey.buf)
	{
		ret = ERROR_MEM_CALLOC;
		goto END;
	}

	myEccPub->eccPublicKey.size = 65;
	memset(myEccPub->eccPublicKey.buf, 0x00, sizeof(myEccPub->eccPublicKey.buf));
	myEccPub->eccPublicKey.buf[0] = 0x04;
	memcpy(myEccPub->eccPublicKey.buf+1, pub_XY, 64);
	myEccPub->eccPublicKey.bits_unused = 0;
	
	bp = target;
	if(!bp) {
		ret = 71; 
		goto END;
	}
	/* Encode the Rectangle type as BER (DER) */
	ec = der_encode(&asn_DEF_EccPublicKey,
		myEccPub, write_out , &bp);
	
	if(ec.encoded == -1) {
		fprintf(stderr,
			"Could not encode myEccPub (at %s)\n",
			ec.failed_type ? ec.failed_type->name : "unknown");
		ret = 65;
		goto END;
	} else {
		fprintf(stderr, "Created with BER encoded myEccPub\n");
	}
	
	if (NULL == derPubkey)
	{
		*ulDerPubl = ec.encoded;
		ret = 0;
		goto END;
	}

	if (*ulDerPubl < ec.encoded)
	{
		*ulDerPubl = ec.encoded;
		ret = ERROR_MEM_LOW;
		goto END;
	}
	
	memcpy(derPubkey, target, ec.encoded);
	*ulDerPubl = ec.encoded;
	ret = 0;
	
END:
	if (p_oid1 != NULL)
	{
		free (p_oid1);
	}
	if (p_oid2 != NULL)
	{
		free (p_oid2) ;
	}
	if (NULL != myEccPub->eccPublicKey.buf)
	{
		free (myEccPub->eccPublicKey.buf) ;
	}
	if (NULL != myEccPub)
	{
		free (myEccPub) ;
	}
	return ret;
}

int sm2DecodePubkey(OUT unsigned char pub_XY[64], 
					IN unsigned char * derPubkey, IN unsigned long ulDerPubl)
{
	EccPublicKey_t *p_EccPub = 0;
	int ret = 0;
	asn_dec_rval_t rval; 
	
	if ( NULL == derPubkey || 0 == ulDerPubl)
	{
		return -1;
	}
	
	/* Encode the Rectangle type as BER (DER) */
	rval = ber_decode(0, &asn_DEF_EccPublicKey,
		(void **)&p_EccPub, derPubkey , ulDerPubl);
	
	if(rval.code != RC_OK) 
	{
		fprintf(stderr,
			"%s: Broken EccPubkey encoding at byte %ld\n",
			"EccPubkey", (long)rval.consumed);
		ret = 65; /* better, EX_DATAERR */
		goto END;
	}

	if (p_EccPub->eccPublicKey.size > 65)
	{
		ret = ERROR_PARAM;
		goto END;
	}
	if (p_EccPub->eccPublicKey.buf[0] != 0x04)
	{
		ret = ERROR_PARAM;
		goto END;
	}

	memcpy(pub_XY, p_EccPub->eccPublicKey.buf+1, p_EccPub->eccPublicKey.size-1);
	
	ret = 0;
	
END:
	if (p_EccPub != NULL)
	{
		free (p_EccPub);
	}
	
	return ret;
}

int sm2EncodePrikey(OUT unsigned char * derPrikey, OUT unsigned long * ulDerPrikl,
					IN unsigned char randPrikey[32], IN unsigned char pub_XY[64])
{
	ECPrivateKey_t * p_sm2Prikey;
	int ret = 0;
	unsigned char target[4000] = {0};
	BYTE * bp = NULL;
//	long *p_ver = NULL;
	

	int asym_with_hash_oid[] = { 1, 2, 156, 10197, 1, 301};//国密oid
	asn_enc_rval_t ec; /* Encoder return value */
	
	if (*ulDerPrikl == 0 || NULL == ulDerPrikl  || NULL ==  derPrikey)
	{
		return -1;
	}
	
	p_sm2Prikey = calloc(1, sizeof(ECPrivateKey_t));
	if (p_sm2Prikey == NULL)
	{
		ret = ERROR_MEM_CALLOC;
		goto END;
	}
	
	memset(p_sm2Prikey, 0x00, sizeof(ECPrivateKey_t));

	p_sm2Prikey->version.buf = calloc(1, 1);
	if (NULL == p_sm2Prikey->version.buf)
	{
		ret = ERROR_MEM_CALLOC;
		goto END;
	}
//	p_ver = p_sm2Prikey->version;
//	*p_ver = 1;
	memset(p_sm2Prikey->version.buf,0x01, 1);
	p_sm2Prikey->version.size = 1;

	p_sm2Prikey->privateKey.buf = calloc(1, 32);
	if (NULL == p_sm2Prikey->privateKey.buf)
	{
		ret = ERROR_MEM_CALLOC;
		goto END;
	}
	p_sm2Prikey->privateKey.size = 32;
	memset(p_sm2Prikey->privateKey.buf, 0x00, 32);
	memcpy(p_sm2Prikey->privateKey.buf, randPrikey, 32);
	

//	optional的节点是一个指针
	p_sm2Prikey->parameters = calloc(1, sizeof(struct Parameters));
	if (NULL == p_sm2Prikey->parameters )
	{
		ret = ERROR_MEM_CALLOC;
		goto END;
	}
	memset(p_sm2Prikey->parameters, 0x00, sizeof(struct Parameters));
	p_sm2Prikey->parameters->present = Parameters_PR_namedCurve;
	/*
	* Fill in myObjectId
	*/	
	ret = OBJECT_IDENTIFIER_set_arcs(&p_sm2Prikey->parameters->choice.namedCurve,
		asym_with_hash_oid, sizeof(asym_with_hash_oid[0]), sizeof(asym_with_hash_oid) / sizeof(asym_with_hash_oid[0]));
	if (ret)
	{
		goto END;
	}
	
	p_sm2Prikey->publicKey.buf = calloc(1, 65);
	if (NULL == p_sm2Prikey->publicKey.buf)
	{
		ret = ERROR_MEM_CALLOC;
		goto END;
	}
	memset(p_sm2Prikey->publicKey.buf, 0x00, 65);
	p_sm2Prikey->publicKey.size = 65;
	p_sm2Prikey->publicKey.buf[0] = 0x04;
	memcpy(p_sm2Prikey->publicKey.buf+1, pub_XY, 64);

	bp = target;
	if(!bp) {
		ret = 71; 
		goto END;
	}
	/* Encode the Rectangle type as BER (DER) */
	ec = der_encode(&asn_DEF_ECPrivateKey,
		p_sm2Prikey, write_out , &bp);
	
	if(ec.encoded == -1) {
		fprintf(stderr,
			"Could not encode asn_DEF_ECPrivateKey (at %s)\n",
			ec.failed_type ? ec.failed_type->name : "unknown");
		ret = 65;
		goto END;
	} else {
		fprintf(stderr, "Created with BER encoded asn_DEF_ECPrivateKey\n");
	}
	
	if (NULL == derPrikey)
	{
		*ulDerPrikl = ec.encoded;
		ret = 0;
		goto END;
	}

	if (*ulDerPrikl < ec.encoded)
	{
		*ulDerPrikl = ec.encoded;
		ret = ERROR_MEM_LOW;
		goto END;
	}
	
	memcpy(derPrikey, target, ec.encoded);
	*ulDerPrikl = ec.encoded;
	ret = 0;
	
END:
	if (p_sm2Prikey->privateKey.buf != NULL)
	{
		free (p_sm2Prikey->privateKey.buf);
	}

	if (p_sm2Prikey->publicKey.buf != NULL)
	{
		free (p_sm2Prikey->publicKey.buf);
	}

	if (p_sm2Prikey->parameters != NULL)
	{
		free (p_sm2Prikey->parameters);
	}
/// Strange????? Crashed!!!
	if (p_sm2Prikey->version.buf != NULL)
	{
		free (p_sm2Prikey->version.buf);
	}

	if (NULL != p_sm2Prikey)
	{
		free (p_sm2Prikey) ;
	}

	return ret;
}

int sm2DecodePrikey(OUT unsigned char sm2_prikey[32], OUT unsigned char sm2_pubXY[64], 
					IN unsigned char * derPrikey, IN unsigned long ulderPrikeyLen)
{
	ECPrivateKey_t * p_sm2Prikey = 0;
	asn_dec_rval_t rval;
	int ret = 0;
	
	
	if (NULL == derPrikey || 0 == ulderPrikeyLen)
	{
		return -1;
	}
	
	//两个返回参数要么都为NULL，要么都不为NULL
	if (!  ((NULL == sm2_prikey && NULL == sm2_pubXY) || (NULL != sm2_prikey && NULL != sm2_pubXY)))
	{
		return -1;
	}
	
	rval = ber_decode(0, &asn_DEF_ECPrivateKey,
		(void **)&p_sm2Prikey, derPrikey , ulderPrikeyLen);
	
	if(rval.code != RC_OK) 
	{
		fprintf(stderr,
			"%s: Broken ECPrivateKey encoding at byte %ld\n",
			"derPrikey", (long)rval.consumed);
		ret = 65; /* better, EX_DATAERR */
		goto END;
	}
	
	if (p_sm2Prikey->publicKey.buf[0] != 0x04)
	{
		ret = ERROR_PARAM;
		goto END;
	}
	memcpy(sm2_prikey, p_sm2Prikey->privateKey.buf, p_sm2Prikey->privateKey.size);
	memcpy(sm2_pubXY, p_sm2Prikey->publicKey.buf+1, p_sm2Prikey->publicKey.size-1);
	
	ret = 0;
	
END:
	if (p_sm2Prikey)
	{
		free(p_sm2Prikey);
	}
	return ret;
}

int sm2EncodeCipher(OUT unsigned char * SM2CipherDer, OUT unsigned long * ulSM2CipherDerLen, 
					IN unsigned char * Cipher, IN unsigned long ulCipherLen,
					IN unsigned char pub_XY[64], IN unsigned char sm3hash[32])
{
	SM2Cipher_t * p_sm2Cipher = 0;
	int ret = 0;
	asn_enc_rval_t ec; 
	unsigned char * target = 0;
	BYTE * bp = NULL;

	if (NULL  == Cipher || 0 == ulCipherLen)
	{
		return -1;
	}

	p_sm2Cipher = calloc(1, sizeof(SM2Cipher_t));
	if (NULL == p_sm2Cipher)
	{
		ret = ERROR_MEM_LOW;
		goto END;
	}
	memset(p_sm2Cipher, 0x00, sizeof(SM2Cipher_t));
	if (pub_XY[0]>=128)
	{
		p_sm2Cipher->xCoordinate.size = 33;
		p_sm2Cipher->xCoordinate.buf = calloc(1, 33);
		
		if (NULL == p_sm2Cipher->xCoordinate.buf )
		{
			ret = ERROR_MEM_LOW;
			goto END;
		}
		p_sm2Cipher->xCoordinate.buf[0] =0x00;
		memcpy(p_sm2Cipher->xCoordinate.buf+1, pub_XY, 32);
		
	}
	else
	{
		p_sm2Cipher->xCoordinate.size = 32;
		p_sm2Cipher->xCoordinate.buf = calloc(1, 32);
		
		if (NULL == p_sm2Cipher->xCoordinate.buf )
		{
			ret = ERROR_MEM_LOW;
			goto END;
		}
		memcpy(p_sm2Cipher->xCoordinate.buf, pub_XY, 32);
	}

	if (pub_XY[32] >= 128)
	{
		p_sm2Cipher->yCoordinate.size = 33;
		p_sm2Cipher->yCoordinate.buf = calloc(1, 33);
		
		if ( NULL == p_sm2Cipher->yCoordinate.buf)
		{
			ret = ERROR_MEM_LOW;
			goto END;
		}
		p_sm2Cipher->yCoordinate.buf[0] = 0x00;
		memcpy(p_sm2Cipher->yCoordinate.buf+1, pub_XY+32, 32);
	}
	else
	{
		p_sm2Cipher->yCoordinate.size = 32;
		p_sm2Cipher->yCoordinate.buf = calloc(1, 32);
		
		if ( NULL == p_sm2Cipher->yCoordinate.buf)
		{
			ret = ERROR_MEM_LOW;
			goto END;
		}
		memcpy(p_sm2Cipher->yCoordinate.buf, pub_XY+32, 32);
	}

	p_sm2Cipher->hash.size = 32;
	p_sm2Cipher->hash.buf = calloc(1, 32);
	if (NULL == p_sm2Cipher->hash.buf)
	{
		ret = ERROR_MEM_LOW;
		goto END;
	}
	memcpy(p_sm2Cipher->hash.buf , sm3hash, 32);

	p_sm2Cipher->cipher.size = ulCipherLen;
	p_sm2Cipher->cipher.buf = calloc(1, ulCipherLen);
	if (NULL == p_sm2Cipher->cipher.buf)
	{	
		ret = ERROR_MEM_LOW;
		goto END;
	}
	memcpy(p_sm2Cipher->cipher.buf , Cipher, ulCipherLen);

	target = calloc(1, 96+ulCipherLen + 100);
	if (NULL == target)
	{
		ret = ERROR_MEM_LOW;
		goto END;
	}
	memset(target, 0x00, 96+ulCipherLen + 100);

	bp = target;
	if(!bp) {
		ret = 71; 
		goto END;
	}
	/* Encode the Rectangle type as BER (DER) */
	ec = der_encode(&asn_DEF_SM2Cipher,
		p_sm2Cipher, write_out , &bp);
	
	if(ec.encoded == -1) {
		fprintf(stderr,
			"Could not encode sm2Cipher (at %s)\n",
			ec.failed_type ? ec.failed_type->name : "unknown");
		ret = 65;
		goto END;
	} else {
		fprintf(stderr, "Created with BER encoded sm2Cipher\n");
	}
	
	if (NULL == SM2CipherDer)
	{
		*ulSM2CipherDerLen = ec.encoded;
		ret = 0;
		goto END;
	}
	
	if (*ulSM2CipherDerLen < ec.encoded)
	{
		*ulSM2CipherDerLen = ec.encoded;
		ret = ERROR_MEM_LOW;
		goto END;
	}
	
	memcpy(SM2CipherDer, target, ec.encoded);
	*ulSM2CipherDerLen = ec.encoded;
	ret = 0;

END:
	if (target)
	{
		free(target);
	}
	if (p_sm2Cipher->cipher.buf)
	{
		free(p_sm2Cipher->cipher.buf);
	}
	if (p_sm2Cipher->hash.buf)
	{
		free(p_sm2Cipher->hash.buf);
	}
	if (p_sm2Cipher->xCoordinate.buf)
	{
		free(p_sm2Cipher->xCoordinate.buf);
	}

	if (p_sm2Cipher->yCoordinate.buf)
	{
		free(p_sm2Cipher->yCoordinate.buf);
	}
	if(p_sm2Cipher)
	{
		free(p_sm2Cipher);
	}
	return ret;
}

int sm2DecodeCipher(OUT unsigned char pub_XY[64], OUT unsigned char sm3hash[32],
					OUT unsigned char * Cipher, OUT unsigned long * ulCipherLen,
					IN unsigned char * SM2CipherDer, IN unsigned long SM2CipherDerLen)
{
	SM2Cipher_t * p_sm2Cipher = 0;
	int ret = 0;
	asn_dec_rval_t rval; 
	int xLen=0,yLen=0;
	int ciLen = 0;
	int hashL = 0;
	
	if ( NULL == SM2CipherDer || 0 == SM2CipherDerLen || 0 == *ulCipherLen )
	{
		return -1;
	}
	
	/* Encode the Rectangle type as BER (DER) */
	rval = ber_decode(0, &asn_DEF_SM2Cipher,
		(void **)&p_sm2Cipher, SM2CipherDer , SM2CipherDerLen);
	
	if(rval.code != RC_OK) 
	{
		fprintf(stderr,
			"%s: Broken Sm2Cipher encoding at byte %ld\n",
			"Sm2Cipher", (long)rval.consumed);
		ret = 65; /* better, EX_DATAERR */
		goto END;
	}
	
	xLen = p_sm2Cipher->xCoordinate.size;
	yLen = p_sm2Cipher->yCoordinate.size;
	ciLen = p_sm2Cipher->cipher.size;
	hashL = p_sm2Cipher->hash.size;
	if (NULL == Cipher || NULL == sm3hash)
	{
		*ulCipherLen = ciLen;
		ret =  0;
		goto END;
	}
	if (xLen + yLen > 66 || xLen >33 || yLen > 33)
	{
		ret = ERROR_PARAM;
		goto END;
	}
	
	*ulCipherLen = ciLen;
	if (hashL != 32)
	{
		ret = ERROR_PARAM;
		goto END;
	}
	if (xLen <= 32)
	{
		memcpy(pub_XY+32-xLen, p_sm2Cipher->xCoordinate.buf, xLen);
	}
	else
	{
		memcpy(pub_XY, p_sm2Cipher->xCoordinate.buf+xLen-32, 32);
	}
	if (yLen <=32 )
	{
		memcpy(pub_XY+64-yLen, p_sm2Cipher->yCoordinate.buf, yLen);
	}
	else
	{
		memcpy(pub_XY+32, p_sm2Cipher->yCoordinate.buf+yLen-32, 32);
	}
	
	
	memcpy(Cipher, p_sm2Cipher->cipher.buf, ciLen);
	memcpy(sm3hash, p_sm2Cipher->hash.buf, hashL);
	
	ret = 0;
END:
	if (p_sm2Cipher != NULL)
	{
		free (p_sm2Cipher);
	}
	
	return ret;
}

int sm2EncodeSignature(OUT unsigned char * derSig, OUT unsigned long * ulderSigL,
					   IN unsigned char sig[64])
{
	SM2Signature_t * p_sm2Sig = 0;
	int ret = 0;
	asn_enc_rval_t ec; 
	unsigned char  target[100] = {0};
	BYTE * bp = NULL;

	p_sm2Sig = calloc(1, sizeof(SM2Signature_t));
	if(NULL == p_sm2Sig)
	{
		ret = ERROR_PARAM;
		goto END;
	}
	memset(p_sm2Sig, 0x00, sizeof(SM2Signature_t));
	
	if (sig[0] >= 128)
	{
		p_sm2Sig->r.size = 33;
		p_sm2Sig->r.buf = calloc(1, 33);
		if(NULL == p_sm2Sig->r.buf)
		{
			ret = ERROR_PARAM;
			goto END;
		}
		p_sm2Sig->r.buf[0] = 0x00;
		memcpy(p_sm2Sig->r.buf+1, sig, 32);
	}
	else
	{
		p_sm2Sig->r.size = 32;
		p_sm2Sig->r.buf = calloc(1, 32);
		if(NULL == p_sm2Sig->r.buf)
		{
			ret = ERROR_PARAM;
			goto END;
		}
		memcpy(p_sm2Sig->r.buf, sig, 32);
	}
	
	if (sig[32] >= 128)
	{
		p_sm2Sig->s.size = 33;
		p_sm2Sig->s.buf = calloc(1, 33);
		if(NULL == p_sm2Sig->s.buf)
		{
			ret = ERROR_PARAM;
			goto END;
		}
		p_sm2Sig->s.buf[0] = 0x00;
		memcpy(p_sm2Sig->s.buf+1, sig+32, 32);
	}
	else
	{
		p_sm2Sig->s.size = 32;
		p_sm2Sig->s.buf = calloc(1, 32);
		if(NULL == p_sm2Sig->s.buf)
		{
			ret = ERROR_PARAM;
			goto END;
		}
		memcpy(p_sm2Sig->s.buf, sig+32, 32);
	}

	bp = target;
	if(!bp) {
		ret = 71; 
		goto END;
	}
	/* Encode the Rectangle type as BER (DER) */
	ec = der_encode(&asn_DEF_SM2Signature,
		p_sm2Sig, write_out , &bp);
	
	if(ec.encoded == -1) {
		fprintf(stderr,
			"Could not encode sm2Signature (at %s)\n",
			ec.failed_type ? ec.failed_type->name : "unknown");
		ret = 65;
		goto END;
	} else {
		fprintf(stderr, "Created with BER encoded sm2Signature\n");
	}
	
	if (NULL == derSig)
	{
		*ulderSigL = ec.encoded;
		ret = 0;
		goto END;
	}
	
	if (*ulderSigL < ec.encoded)
	{
		*ulderSigL = ec.encoded;
		ret = ERROR_MEM_LOW;
		goto END;
	}
	
	memcpy(derSig, target, ec.encoded);
	*ulderSigL = ec.encoded;
	ret = 0;
	
END:
	
	if (p_sm2Sig->r.buf)
	{
		free(p_sm2Sig->r.buf);
	}
	if (p_sm2Sig->s.buf)
	{
		free(p_sm2Sig->s.buf);
	}
	if (p_sm2Sig)
	{
		free(p_sm2Sig);
	}
	return ret;
}

int sm2DecodeSignature(OUT unsigned char sig[64], 
					   IN unsigned char * derSig, IN unsigned long ulderSigL)
{
	SM2Signature_t * p_sm2Sig = 0;
	int ret = 0;
	asn_dec_rval_t rval; 
	
	if (NULL == derSig || 0 == ulderSigL)
	{
		return -1;
	}

	/* Encode the Rectangle type as BER (DER) */
	rval = ber_decode(0, &asn_DEF_SM2Signature,
		(void **)&p_sm2Sig, derSig , ulderSigL);
	
	if(rval.code != RC_OK) 
	{
		fprintf(stderr,
			"%s: Broken SM2Signature encoding at byte %ld\n",
			"SM2Signature", (long)rval.consumed);
		ret = 65; /* better, EX_DATAERR */
		goto END;
	}
	
	if (p_sm2Sig->r.size > 33 || p_sm2Sig->s.size > 33)
	{
		ret = ERROR_PARAM;
		goto END;
	}
	memset(sig, 0x00, 64);
	if (p_sm2Sig->r.size <= 32)
	{
		memcpy(sig+32-p_sm2Sig->r.size, p_sm2Sig->r.buf, p_sm2Sig->r.size);
	}
	else
	{
		memcpy(sig, p_sm2Sig->r.buf+p_sm2Sig->r.size-32, 32);
	}

	if (p_sm2Sig->s.size <= 32)
	{
		memcpy(sig+64-p_sm2Sig->s.size, p_sm2Sig->s.buf, p_sm2Sig->s.size);
	}
	else
	{
		memcpy(sig+32, p_sm2Sig->s.buf+p_sm2Sig->s.size-32, 32);
	}
	
	
	ret = 0;
	
END:
	if (p_sm2Sig != NULL)
	{
		free (p_sm2Sig);
	}
	
	return ret;		

}

