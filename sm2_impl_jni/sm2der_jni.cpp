/************************************************************************/
/* Discr :  sm2 implementation Jni der encode & decode
/*  
/* Author:  simon Pang @ CATT 2009
/* Email :  simonpang1984@gmail.com / steven.psm@gmail.com
/************************************************************************/

#include "com_Simon_catt2009_Sm2CryptoCls.h"
#include "../sm2der/libSm2der.h"
#include "global.h"
#include "utils.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

/*
 * Class:     com_Simon_catt2009_Sm2CryptoCls
 * Method:    sm2PubKeyDerEncode
 * Signature: ([B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_Simon_1catt2009_Sm2CryptoCls_sm2PubKeyDerEncode
  (JNIEnv * jEnv, jobject jObj, jbyteArray jsm2pubkey_XY)
{
	if (NULL == jsm2pubkey_XY)
	{
		setLastErr(JNI_ERR_PARAM);
		return NULL;
	}
	jbyte * csm2pubkey_XY = jEnv->GetByteArrayElements(jsm2pubkey_XY, NULL);
	int Lensm2pubkey_XY = jEnv->GetArrayLength(jsm2pubkey_XY);
	unsigned char derPubkey[100] = {0};
	unsigned long ulDerPubLen = 100;
	int ret = 0;
	jbyteArray retByte = 0;
	char msg[100] = {0};

	if (Lensm2pubkey_XY < 64)
	{
		ret = JNI_ERR_PARAM;
		goto END;
	}

	ret = sm2EncodePubkey(derPubkey, &ulDerPubLen, (unsigned char *)csm2pubkey_XY);
	if (ret)
	{
		ret = JNI_ERR_PUBKEY_ENCODE_ERROR;
		goto END;
	}

	retByte = jEnv->NewByteArray(ulDerPubLen);
	if (NULL != retByte)
	{
		jEnv->SetByteArrayRegion(retByte, 0, ulDerPubLen, (jbyte*)derPubkey);
	}
	else
	{
		ret = JNI_ERR_MEM_ALLOC;
		goto END;
	}
END:
	if (0 != ret)
	{
		sprintf(msg, "pubkey Der encode failed err!code:0x%02x", ret);
		LOGI(msg);
	}
	
	jEnv->ReleaseByteArrayElements(jsm2pubkey_XY, csm2pubkey_XY, 0);
	setLastErr(ret);
	return retByte;
}

/*
 * Class:     com_Simon_catt2009_Sm2CryptoCls
 * Method:    sm2PubkeyDerDecode
 * Signature: ([B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_Simon_1catt2009_Sm2CryptoCls_sm2PubkeyDerDecode
  (JNIEnv * jEnv, jobject jObj, jbyteArray jsm2DerPub)
{
	if (NULL == jsm2DerPub)
	{
		setLastErr(JNI_ERR_PARAM);
		return NULL;
	}
	jbyte * csm2DerPub = jEnv->GetByteArrayElements(jsm2DerPub, NULL);
	int Lensm2DerPubkey = jEnv->GetArrayLength(jsm2DerPub);
	unsigned char Pubkey_XY[64] = {0};
	
	int ret = 0;
	jbyteArray retByte = 0;
	char msg[100] = {0};
	
	ret = sm2DecodePubkey(Pubkey_XY, (unsigned char *)csm2DerPub, Lensm2DerPubkey);
	if (ret)
	{
		ret = JNI_ERR_PUBKEY_DECODE_ERROR;
		goto END;
	}
	
	retByte = jEnv->NewByteArray(64);
	if (NULL != retByte)
	{
		jEnv->SetByteArrayRegion(retByte, 0, 64, (jbyte*)Pubkey_XY);
	}
	else
	{
		ret = JNI_ERR_MEM_ALLOC;
		goto END;
	}
END:
	if (0 != ret)
	{
		sprintf(msg, "pubkey Der decode failed err!code:0x%02x", ret);
		LOGI(msg);
	}
	
	jEnv->ReleaseByteArrayElements(jsm2DerPub, csm2DerPub, 0);
	setLastErr(ret);
	return retByte;
}

/*
 * Class:     com_Simon_catt2009_Sm2CryptoCls
 * Method:    sm2PrivateKeyDerEncode
 * Signature: ([B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_Simon_1catt2009_Sm2CryptoCls_sm2PrivateKeyDerEncode
  (JNIEnv * jEnv, jobject jObj, jbyteArray jprikeyRand, jbyteArray jsm2pubkey_XY)
{	
	if (NULL == jsm2pubkey_XY || NULL == jprikeyRand )
	{
		setLastErr(JNI_ERR_PARAM);
		return NULL;
	}
	jbyte * csm2pubkey_XY = jEnv->GetByteArrayElements(jsm2pubkey_XY, NULL);
	int Lensm2pubkey_XY = jEnv->GetArrayLength(jsm2pubkey_XY);
	jbyte * cprikeyRand = jEnv->GetByteArrayElements(jprikeyRand, NULL);
	int LenprikeyRand = jEnv->GetArrayLength(jprikeyRand);
	unsigned char derPrikey[500] = {0};
	unsigned long ulDerPriLen = 500;
	int ret = 0;
	jbyteArray retByte = 0;
	char msg[100] = {0};
	
	if (Lensm2pubkey_XY < 64 || LenprikeyRand < 32)
	{
		ret = JNI_ERR_PARAM;
		goto END;
	}
	
	ret = sm2EncodePrikey(derPrikey, &ulDerPriLen, (unsigned char *)cprikeyRand, (unsigned char *)csm2pubkey_XY);
	if (ret)
	{
		ret = JNI_ERR_PRIKEY_ENCODE_ERROR;
		goto END;
	}
	
	retByte = jEnv->NewByteArray(ulDerPriLen);
	if (NULL != retByte)
	{
		jEnv->SetByteArrayRegion(retByte, 0, ulDerPriLen, (jbyte*)derPrikey);
	}
	else
	{
		ret = JNI_ERR_MEM_ALLOC;
		goto END;
	}
END:
	if (0 != ret)
	{
		sprintf(msg, "prikey Der encode failed err!code:0x%02x", ret);
		LOGI(msg);
	}
	
	jEnv->ReleaseByteArrayElements(jsm2pubkey_XY, csm2pubkey_XY, 0);
	jEnv->ReleaseByteArrayElements(jprikeyRand, cprikeyRand, 0);
	setLastErr(ret);
	return retByte;
}

/*
 * Class:     com_Simon_catt2009_Sm2CryptoCls
 * Method:    sm2PrivateKeyDerDecode
 * Signature: ([B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_Simon_1catt2009_Sm2CryptoCls_sm2PrivateKeyDerDecode
  (JNIEnv * jEnv, jobject jObj, jbyteArray jsm2PrivateKeyDerStr, jbyteArray jsm2pubkey_XY)
{
	if (NULL == jsm2pubkey_XY || NULL == jsm2PrivateKeyDerStr )
	{
		setLastErr(JNI_ERR_PARAM);
		return NULL;
	}
	jbyte * csm2PrivateKeyDerStr = jEnv->GetByteArrayElements(jsm2PrivateKeyDerStr, NULL);
	int Lensm2PrivateKeyDerStr = jEnv->GetArrayLength(jsm2PrivateKeyDerStr);

	int Lensm2pubkey_XY = jEnv->GetArrayLength(jsm2pubkey_XY);

	unsigned char PrikeyRnd[32] = {0};
	unsigned long ulPriRndLen = 32;

	int ret = 0;
	jbyteArray retByte = 0;
	char msg[100] = {0};
	
	jbyte * csm2pubkey_XY = jEnv->GetByteArrayElements(jsm2pubkey_XY, JNI_FALSE);
	if (Lensm2pubkey_XY < 64 )
	{
		ret = JNI_ERR_PARAM;
		goto END;
	}

	ret = sm2DecodePrikey(PrikeyRnd, (unsigned char *)csm2pubkey_XY, (unsigned char *)csm2PrivateKeyDerStr, Lensm2PrivateKeyDerStr);
	if (ret)
	{
		ret = JNI_ERR_PRIKEY_DECODE_ERROR;
		goto END;
	}
	
	retByte = jEnv->NewByteArray(32);
	if (NULL != retByte)
	{
		jEnv->SetByteArrayRegion(retByte, 0, 32, (jbyte*)PrikeyRnd);
	}
	else
	{
		ret = JNI_ERR_MEM_ALLOC;
		goto END;
	}
END:
	if (0 != ret)
	{
		sprintf(msg, "prikey Der decode failed err!code:0x%02x", ret);
		LOGI(msg);
	}

	jEnv->ReleaseByteArrayElements(jsm2pubkey_XY, csm2pubkey_XY, JNI_COMMIT);
	jEnv->ReleaseByteArrayElements(jsm2PrivateKeyDerStr, csm2PrivateKeyDerStr, 0);
	setLastErr(ret);
	return retByte;
}

/*
 * Class:     com_Simon_catt2009_Sm2CryptoCls
 * Method:    sm2CipherDerEncode
 * Signature: ([B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_Simon_1catt2009_Sm2CryptoCls_sm2CipherDerEncode
  (JNIEnv *jEnv, jobject jObj, jbyteArray jCipher, jbyteArray jsm2pubkey_XY, jbyteArray jHashSM3)
{
	if (NULL == jsm2pubkey_XY || NULL == jCipher || NULL == jHashSM3 )
	{
		setLastErr(JNI_ERR_PARAM);
		return NULL;
	}
	jbyte * cCipher = jEnv->GetByteArrayElements(jCipher, NULL);
	int LenCipher = jEnv->GetArrayLength(jCipher);

	jbyte * cHashSM3 = jEnv->GetByteArrayElements(jHashSM3, NULL);
	int LenHashSM3 = jEnv->GetArrayLength(jHashSM3);
	
	int Lensm2pubkey_XY = jEnv->GetArrayLength(jsm2pubkey_XY);
	
	unsigned char * psm2CipherDer = new unsigned char [LenCipher + 500];
	memset(psm2CipherDer, 0x00, LenCipher + 500);
	unsigned long ulsm2CipherDerLen = LenCipher + 500;
	
	int ret = 0;
	jbyteArray retByte = 0;
	char msg[100] = {0};
	
	jbyte * csm2pubkey_XY = jEnv->GetByteArrayElements(jsm2pubkey_XY, NULL);
	if (Lensm2pubkey_XY < 64 || 32 != LenHashSM3)
	{
		ret = JNI_ERR_PARAM;
		goto END;
	}
	
	ret = sm2EncodeCipher(psm2CipherDer, &ulsm2CipherDerLen, (unsigned char *)cCipher, LenCipher, (unsigned char *)csm2pubkey_XY, (unsigned char *)cHashSM3);
	if (ret)
	{
		ret = JNI_ERR_CIPHER_ENCODE_ERROR;
		goto END;
	}
	
	retByte = jEnv->NewByteArray(ulsm2CipherDerLen);
	if (NULL != retByte)
	{
		jEnv->SetByteArrayRegion(retByte, 0, ulsm2CipherDerLen, (jbyte*)psm2CipherDer);
	}
	else
	{
		ret = JNI_ERR_MEM_ALLOC;
		goto END;
	}
END:
	if (0 != ret)
	{
		sprintf(msg, "sm2Cipher Der Encode failed err!code:0x%02x", ret);
		LOGI(msg);
	}
	
	jEnv->ReleaseByteArrayElements(jsm2pubkey_XY, csm2pubkey_XY, 0);
	jEnv->ReleaseByteArrayElements(jCipher, cCipher, 0);
	jEnv->ReleaseByteArrayElements(jHashSM3, cHashSM3, 0);
	if (psm2CipherDer)
	{
		delete [] psm2CipherDer;
	}
	setLastErr(ret);
	return retByte;
}

/*
 * Class:     com_Simon_catt2009_Sm2CryptoCls
 * Method:    sm2CipherDerDecode
 * Signature: ([B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_Simon_1catt2009_Sm2CryptoCls_sm2CipherDerDecode
  (JNIEnv *, jobject, jbyteArray, jbyteArray, jbyteArray)
{
	return 0;
}

/*
 * Class:     com_Simon_catt2009_Sm2CryptoCls
 * Method:    sm2SignatureDerEncode
 * Signature: ([B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_Simon_1catt2009_Sm2CryptoCls_sm2SignatureDerEncode
  (JNIEnv * jEnv, jobject jObj, jbyteArray jsignature_RS)
{
	if (NULL == jsignature_RS)
	{
		setLastErr(JNI_ERR_PARAM);
		return NULL;
	}
	jbyte * csignature_RS = jEnv->GetByteArrayElements(jsignature_RS, NULL);
	int LenSignature_RS = jEnv->GetArrayLength(jsignature_RS);
	unsigned char signatureDer[100] = {0};
	unsigned long ulLenDerSig = 100;
	int ret = 0;
	jbyteArray retByte = 0;
	char msg[100] = {0};
	
	if (LenSignature_RS < 64)
	{
		ret = JNI_ERR_PARAM;
		goto END;
	}
	
	ret = sm2EncodeSignature(signatureDer, &ulLenDerSig, (unsigned char *)csignature_RS);
	if (ret)
	{
		ret = JNI_ERR_SIGNATURE_ENCODE_ERROR;
		goto END;
	}
	
	retByte = jEnv->NewByteArray(ulLenDerSig);
	if (NULL != retByte)
	{
		jEnv->SetByteArrayRegion(retByte, 0, ulLenDerSig, (jbyte*)signatureDer);
	}
	else
	{
		ret = JNI_ERR_MEM_ALLOC;
	}
END:
	if (0 != ret)
	{
		sprintf(msg, "signature Der encode failed err!code:0x%02x", ret);
		LOGI(msg);
	}
	
	jEnv->ReleaseByteArrayElements(jsignature_RS, csignature_RS, 0);
	setLastErr(ret);
	return retByte;
}

/*
 * Class:     com_Simon_catt2009_Sm2CryptoCls
 * Method:    sm2SignatureDerDecode
 * Signature: ([B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_Simon_1catt2009_Sm2CryptoCls_sm2SignatureDerDecode
  (JNIEnv * jEnv, jobject jObj, jbyteArray jsigDer)
{
	if (NULL == jsigDer)
	{
		setLastErr(JNI_ERR_PARAM);
		return NULL;
	}
	jbyte * csigDer = jEnv->GetByteArrayElements(jsigDer, NULL);
	int LensigDer = jEnv->GetArrayLength(jsigDer);
	unsigned char signature_RS[64] = {0};
	
	int ret = 0;
	jbyteArray retByte = 0;
	char msg[100] = {0};
	
	ret = sm2DecodeSignature(signature_RS, (unsigned char *)csigDer, LensigDer);
	if (ret)
	{
		ret = JNI_ERR_SIGNATURE_DECODE_ERROR;
		goto END;
	}
	
	retByte = jEnv->NewByteArray(64);
	if (NULL != retByte)
	{
		jEnv->SetByteArrayRegion(retByte, 0, 64, (jbyte*)signature_RS);
	}
	else
	{
		ret = JNI_ERR_MEM_ALLOC;
	}
END:
	if (0 != ret)
	{
		sprintf(msg, "signature Der decode failed err!code:0x%02x", ret);
		LOGI(msg);
	}
	
	jEnv->ReleaseByteArrayElements(jsigDer, csigDer, 0);
	setLastErr(ret);
	return retByte;
}


JNIEXPORT jint JNICALL Java_com_Simon_1catt2009_Sm2CryptoCls_RandGenTest
  (JNIEnv * jEnv, jobject jObj, jstring jRandGenPath, jint jRandBytesLength)
{
	if (NULL == jRandGenPath || 0 >= jRandBytesLength)
	{
		return JNI_ERR_PARAM;
	}
	const char * cRandGenPath = jEnv->GetStringUTFChars(jRandGenPath, NULL);
	FILE * fp = NULL;
	int ret	= 0;
	int i = 0;
	int n = 0;
	char msg[100] = {0};
	unsigned char randTmpbuf[32] = {0};
	fp = fopen ((char *)cRandGenPath, "a+");
	if (NULL == fp)
	{
		ret = JNI_ERR_FILE_READ_WRITE_ERROR;
		goto END;
	}

	n = jRandBytesLength/32 + 1;

	for (i = 0; i < n; i++)
	{
		ret	= genRand(randTmpbuf);
		if (ret)
		{
			goto END;
		}
		fwrite(randTmpbuf, 32, 1, fp);
		if (0 == n%20)
		{
			sprintf(msg, "group num %d created...\n", n);
			LOGI(msg);
			//printf(msg);
		}
	}

END:
	if (NULL == cRandGenPath)
	{
		jEnv->ReleaseStringUTFChars(jRandGenPath, cRandGenPath);
	}
	if (NULL != fp)
	{
		fclose(fp);
	}
	setLastErr(ret);
	return ret;

}