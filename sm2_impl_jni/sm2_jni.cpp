/************************************************************************/
/* Discr :  sm2 implementation Jni lib
/*  
/* Author:  simon Pang @ CATT 2009
/* Email :  simonpang1984@gmail.com / steven.psm@gmail.com
/************************************************************************/

#include "com_Simon_catt2009_Sm2CryptoCls.h"
#include "global.h"
#include "../sm2_impl/sm2.h"
#include "../sm2_impl/sm3.h"
#include "utils.h"


#ifdef WIN32
#pragma comment(lib, "../win32Rls/sm2_impl.lib")
#pragma comment(lib, "../win32Rls/tommath.lib")
#pragma comment(lib, "../win32Rls/sm2derSimplfied.lib")
#else

// void BYTE_print(unsigned char * tar, unsigned long l)
// {
// 	for (int i = 0; i<l; i++)
// 	{
// 		if (i %4 ==0)
// 		{
// 			printf(" ");
// 		}
// 		printf("%02x", tar[i]);
// 	}
// 	printf("\n");
// }


#endif

const char * default_uid_str = "1234567812345678"; 
//const char * currVersion = "2012-09-23 night";
//const char * currVersion = "2012-12-14 night";
const char * currVersion = "2013-02-28 night";

int lastErr = 0;

void setLastErr(int Err)
{
	lastErr = Err;
}

int getLastErr()
{
	return lastErr;
}

//public native byte[] SignBySM2Privatekey(byte[] message, byte[] privateKey);
JNIEXPORT jbyteArray JNICALL Java_com_Simon_1catt2009_Sm2CryptoCls_SignBySm2Privatekey
  (JNIEnv * jEnv, jobject jObj, jbyteArray jmessage , jbyteArray jprivateKey)
{	
	if (NULL == jmessage || NULL == jprivateKey)
	{
		LOGI("param err!");
		setLastErr(JNI_ERR_PARAM);
		return NULL;

	}
	int ret = 0;
	jbyteArray byteRet = NULL;
	jbyte * cmessage = jEnv->GetByteArrayElements(jmessage, NULL);
	jint lenMsg = jEnv->GetArrayLength(jmessage);
	jbyte * cprivateKey = jEnv->GetByteArrayElements(jprivateKey, NULL);
	jint lenPrivateKey = jEnv->GetArrayLength(jprivateKey);

	unsigned char signature[64] = {0};
	unsigned long sigLen = 64;
	ret = GM_SM2Sign(signature, &sigLen, (unsigned char*)cmessage, (unsigned long)lenMsg, 
		(unsigned char*) default_uid_str, strlen(default_uid_str), (unsigned char*)cprivateKey, lenPrivateKey);
	if (ret)
	{
		setLastErr(ret);
		LOGI("signature failed!");
		goto END;
	}
	byteRet = jEnv->NewByteArray(64);
	if (NULL != byteRet)
	{
		jEnv->SetByteArrayRegion(byteRet, 0, 64, (jbyte *)signature);
		setLastErr(0);
	}
	else
	{
		ret = JNI_ERR_MEM_ALLOC;
		LOGI("mem alloc failed!");
		goto END;
	}

END:
	
	if (cmessage)
	{
		jEnv->ReleaseByteArrayElements(jmessage, cmessage, 0);
	}
	if (cprivateKey)
	{
		jEnv->ReleaseByteArrayElements(jprivateKey, cprivateKey, 0);
	}
	setLastErr(ret);
	return byteRet;
	
}

//public native int VerifySm2SignatureByCert(byte[] CertSm2, byte[] signature, byte[] src);
JNIEXPORT jint JNICALL Java_com_Simon_1catt2009_Sm2CryptoCls_VerifySm2SignatureByCert
  (JNIEnv * jEnv, jobject jObj,jbyteArray jderSm2Cert, jbyteArray jsignature, jbyteArray jplain)
{
	if (NULL == jderSm2Cert || NULL == jsignature || NULL == jplain)
	{
		LOGI("param err!");
		setLastErr(JNI_ERR_PARAM);
		return JNI_ERR_PARAM;
		
	}

	jint lenSig = jEnv->GetArrayLength(jsignature);
	if (64!= lenSig) 
	{
		LOGI("param err!");
		setLastErr(JNI_ERR_PARAM);
		return JNI_ERR_PARAM;
	}

	jint ret = 0;
	unsigned char sm2pubkey[64] = {0};
	char msg[100] = {0};

	jbyte * cplain = jEnv->GetByteArrayElements(jplain, NULL);
	jint LenPlain = jEnv->GetArrayLength(jplain);
	jbyte * cDerSm2Cert = jEnv->GetByteArrayElements(jderSm2Cert, NULL);
	jint LenDerSm2Cert = jEnv->GetArrayLength(jderSm2Cert);
	jbyte * csignature = jEnv->GetByteArrayElements(jsignature, NULL);
	jint LenSm2Sig = jEnv->GetArrayLength(jsignature);
	if(LenSm2Sig != 64)
	{
		LOGI("Sig length wrong!!");
		setLastErr(JNI_ERR_PARAM);
		goto END;
	}
	
	ret = GetPubkeyFromSM2Cert(sm2pubkey, (unsigned char *)cDerSm2Cert, LenDerSm2Cert);
	if (ret)
	{
		sprintf(msg, "get sm2 cert pubkey failed err!code:0x%02x", ret);
		LOGI(msg);
		goto END;
	}
	ret = GM_SM2VerifySig((unsigned char *)csignature, 64, (unsigned char *)cplain, LenPlain, 
		(unsigned char*) default_uid_str, strlen(default_uid_str), sm2pubkey, 64);
	if (0 != ret)
	{
		sprintf(msg, "signature verify failed err!code:0x%02x", ret);
		LOGI(msg);
	}

END:

	if (cDerSm2Cert)
	{
		jEnv->ReleaseByteArrayElements(jderSm2Cert,cDerSm2Cert,0);
	}
	
	if(cplain)
	{
		jEnv->ReleaseByteArrayElements(jplain,cplain,0);
	}
	if (csignature)
	{
		jEnv->ReleaseByteArrayElements(jsignature,csignature,0);
	}
	
	setLastErr(ret);
	return ret;
}

//	public native int VerifySm2SignatureByPubKey(byte[] PublicKeySm2, byte[] signature, byte[] src);
JNIEXPORT jint JNICALL Java_com_Simon_1catt2009_Sm2CryptoCls_VerifySm2SignatureByPubKey
  (JNIEnv * jEnv, jobject jObj, jbyteArray jPublicKeySm2, jbyteArray jsignature, jbyteArray jplain)
{

	if (NULL == jPublicKeySm2 || NULL == jsignature || NULL == jplain)
	{
		LOGI("param err!");
		setLastErr(JNI_ERR_PARAM);
		return JNI_ERR_PARAM;
	}
	
	jint lenSig = jEnv->GetArrayLength(jsignature);
	jint LenpubkeySm2 = jEnv->GetArrayLength(jPublicKeySm2);
	if (64!= lenSig || 64 != LenpubkeySm2) 
	{
		LOGI("param err!");
		setLastErr(JNI_ERR_PARAM);
		return JNI_ERR_PARAM;
	}
	
	jbyte * cplain = jEnv->GetByteArrayElements(jplain, NULL);
	jint LenPlain = jEnv->GetArrayLength(jplain);
	jbyte * cpubkeySm2 = jEnv->GetByteArrayElements(jPublicKeySm2, NULL);
	jbyte * csignature = jEnv->GetByteArrayElements(jsignature, NULL);

	char msg[100] = {0};
	int ret = 0;

// 	printf("signature:");
// 	BYTE_print((unsigned char *)csignature, 64);
// 	printf("\ncplain:len:%d", LenPlain);
// 	BYTE_print((unsigned char *)cplain, LenPlain);
// 	printf("\nuid is:");
// 	BYTE_print((unsigned char *)default_uid_str, strlen(default_uid_str));
// 	printf("\npubkey is:");
// 	BYTE_print((unsigned char *)cpubkeySm2, 64);
	ret = GM_SM2VerifySig((unsigned char *)csignature, 64, (unsigned char *)cplain, LenPlain, 
		(unsigned char*) default_uid_str, strlen(default_uid_str), (unsigned char *)cpubkeySm2, 64);
	if (0 != ret)
	{
		sprintf(msg, "signature verify failed err!code:0x%02x", ret);
		LOGI(msg);
	}
// 	else
// 	{
// 		sprintf(msg, "signature verify ok!");
// 		LOGI(msg);
// 	}
	
	jEnv->ReleaseByteArrayElements(jPublicKeySm2,cpubkeySm2,0);
	jEnv->ReleaseByteArrayElements(jplain,cplain,0);
	jEnv->ReleaseByteArrayElements(jsignature,csignature,0);
	setLastErr(ret);
	return ret;
}



//public native byte[] GenerateSm2KeyPair(byte[] privateKey);
JNIEXPORT jbyteArray JNICALL Java_com_Simon_1catt2009_Sm2CryptoCls_GenerateSm2KeyPair___3B
  (JNIEnv * jEnv, jobject jObj, jbyteArray jprivateKey)
{
	if (NULL == jprivateKey)
	{
		setLastErr(JNI_ERR_PARAM);
		LOGI("param err!");
		return NULL;
	}
	jbyteArray byteRet = NULL;
	jint LenPrikey = jEnv->GetArrayLength(jprivateKey);
	if (32 > LenPrikey)
	{
		setLastErr(JNI_ERR_PARAM);
		LOGI("private key buff too small err!");
		return NULL;
	}
	unsigned char pubkey [64] = {0};
	jbyte * cprivateKey = jEnv->GetByteArrayElements(jprivateKey, JNI_FALSE);
	int ret = genRand((unsigned char *)cprivateKey);
	if (ret)
	{
		setLastErr(ret);
		LOGI("rand number generate failed!");
		goto err;
	}
	
	ret = BYTE_Point_mul((unsigned char *)cprivateKey, pubkey);
	if (ret)
	{
		setLastErr(ret);
		LOGI("point multiply failed!");
		goto err;
	}
	
	byteRet = jEnv->NewByteArray(64);
	if (NULL != byteRet)
	{
		jEnv->SetByteArrayRegion(byteRet, 0, 64, (jbyte *)pubkey);
	}
	else
	{
		ret = JNI_ERR_MEM_ALLOC;
		LOGI("mem alloc failed!");
		goto err;
	}

	jEnv->ReleaseByteArrayElements(jprivateKey, cprivateKey, JNI_COMMIT);
	setLastErr(ret);
	return byteRet;

err:
	if (cprivateKey)
	{
		jEnv->ReleaseByteArrayElements(jprivateKey, cprivateKey, 0);
	}
	setLastErr(ret);
	return byteRet;
}



//public native byte[] GenerateSm2KeyPair(byte[] rand, byte[] privateKey);
JNIEXPORT jbyteArray JNICALL Java_com_Simon_1catt2009_Sm2CryptoCls_GenerateSm2KeyPair___3B_3B
  (JNIEnv * jEnv, jobject jObj, jbyteArray jrand, jbyteArray jprivateKey)
{
	if (NULL == jprivateKey || NULL == jrand)
	{
		setLastErr(JNI_ERR_PARAM);
		LOGI("param err!");
		return NULL;
	}
	
	jint LenPrikey = jEnv->GetArrayLength(jprivateKey);
	if (32 > LenPrikey)
	{
		setLastErr(JNI_ERR_PARAM);
		LOGI("private key buff too small err!");
		return NULL;
	}
	jbyteArray byteRet = NULL;
	unsigned char pubkey [64] = {0};
	jbyte * crand = jEnv->GetByteArrayElements(jrand, NULL);
	jint cLenRand = jEnv->GetArrayLength(jrand);
	unsigned char Tmp_buff[32] = {0};

	jbyte * cprivateKey = jEnv->GetByteArrayElements(jprivateKey, JNI_FALSE);
	int ret = genRand((unsigned char *)cprivateKey);
	if (ret)
	{
		setLastErr(ret);
		LOGI("rand number generate failed!");
		goto err;
	}
	
	
	sm3((unsigned char*)crand, cLenRand, Tmp_buff);
	XOR_STRING((unsigned char *)cprivateKey, Tmp_buff, (unsigned char *)cprivateKey, 32);

	
	ret = BYTE_Point_mul((unsigned char *)cprivateKey, pubkey);
	if (ret)
	{
		setLastErr(ret);
		LOGI("point multiply failed!");
		goto err;
	}
	
	
	byteRet = jEnv->NewByteArray(64);
	if (NULL != byteRet)
	{
		jEnv->SetByteArrayRegion(byteRet, 0, 64, (jbyte *)pubkey);
	}
	else
	{
		ret = JNI_ERR_MEM_ALLOC;
		setLastErr(ret);
		LOGI("mem alloc failed!");
		goto err;
	}
	
	jEnv->ReleaseByteArrayElements(jprivateKey, cprivateKey, JNI_COMMIT);
	if (crand)
	{
		jEnv->ReleaseByteArrayElements(jrand, crand, 0);
	}
	setLastErr(ret);
	return byteRet;

err:
	if (cprivateKey)
	{
		jEnv->ReleaseByteArrayElements(jprivateKey, cprivateKey, 0);
	}
	if (crand)
	{
		jEnv->ReleaseByteArrayElements(jrand, crand, 0);
	}
	setLastErr(ret);
	return byteRet;
}

//public native byte[] DecryptBySm2PrivateKey(byte[] inputCipher,byte[] privateKey);
JNIEXPORT jbyteArray JNICALL Java_com_Simon_1catt2009_Sm2CryptoCls_DecryptBySm2PrivateKey
  (JNIEnv * jEnv, jobject jObj, jbyteArray jinputCipher, jbyteArray jprivateKey)
{
	if (NULL == jprivateKey || NULL == jinputCipher )
	{
		LOGI("param err!");
		setLastErr(JNI_ERR_PARAM);
		return NULL;
	}

	jint LenPrivatekey = jEnv->GetArrayLength(jprivateKey);
	if (LenPrivatekey != 32)
	{
		LOGI("param err! private key length must be 32!");
		setLastErr(JNI_ERR_PARAM);
		return NULL;
	}
	
	char msg [100] = {0};
	jbyte *cprivateKey = jEnv->GetByteArrayElements(jprivateKey,NULL);
	jbyte * cinput = jEnv->GetByteArrayElements(jinputCipher, NULL);
	unsigned long LenInputCipher = jEnv->GetArrayLength(jinputCipher);
	int ret = 0;
	
	jbyteArray retbytes = 0;
	unsigned long LenDecdata = LenInputCipher;
	unsigned char * cdecData = new unsigned char [LenInputCipher];
	if (NULL == cdecData)
	{
		ret = JNI_ERR_MEM_ALLOC;
		goto END;
	}
	
	ret = GM_SM2Decrypt(cdecData, &LenDecdata, (unsigned char *)cinput, LenInputCipher, 
		(unsigned char *)cprivateKey, 32);
	if (0 != ret)
	{
		goto END;
	}
	retbytes = jEnv->NewByteArray(LenDecdata);
	if (NULL != retbytes)
	{
		jEnv->SetByteArrayRegion(retbytes, 0, LenDecdata, (jbyte *)cdecData);
	}
	else
	{
		ret = JNI_ERR_MEM_ALLOC;
	}
	
END:
	if (0 != ret)
	{
		sprintf(msg, "decrypt by user key failed err!code:0x%02x", ret);
		setLastErr(ret);
		LOGI(msg);
	}
	if (cprivateKey)
	{
		jEnv->ReleaseByteArrayElements(jprivateKey,cprivateKey, NULL);
	}
	
	if(cinput)
	{
		jEnv->ReleaseByteArrayElements(jinputCipher, cinput, NULL);
	}
	
	if (cdecData)
	{
		delete []cdecData;
	}
	return retbytes;
}



//public native byte[] EncryptBySM2PublicKey(byte[] plain, byte[] Sm2Pubkey);
JNIEXPORT jbyteArray JNICALL Java_com_Simon_1catt2009_Sm2CryptoCls_EncryptBySm2PublicKey
  (JNIEnv * jEnv, jobject jObj, jbyteArray jplain, jbyteArray jSm2Pubkey)
{
	if (NULL == jplain || NULL == jSm2Pubkey )
	{
		LOGI("param err!");
		setLastErr(JNI_ERR_PARAM);
		return NULL;
	}
	char msg[100] = {0};
	unsigned char * cPubkey = new unsigned char [64];
	if (NULL == cPubkey)
	{
		LOGI("mem alloc failed!");
		setLastErr(JNI_ERR_PARAM);
		return NULL;
	}
	memset(cPubkey, 0x00, 64);
	jEnv->GetByteArrayRegion(jSm2Pubkey, 0, 64, (jbyte *)cPubkey);
	
	jbyte * cplain = jEnv->GetByteArrayElements(jplain, NULL);
	jint LenPlain = jEnv->GetArrayLength(jplain);
	jbyteArray retByte = 0;
	jint ret = 0;int i= 0;
	unsigned long lenCipher = LenPlain + 200;
	unsigned char * ccipher = new unsigned char[lenCipher];
	if (NULL == ccipher)
	{
		ret = JNI_ERR_MEM_ALLOC;
		setLastErr(ret);
		goto END;
	}
	memset(ccipher, 0x00, lenCipher);
	ret = GM_SM2Encrypt((unsigned char *)ccipher, &lenCipher, (unsigned char *)cplain, LenPlain, cPubkey, 64);
	if (0 != ret)
	{
		ret = JNI_ERR_SM2_ENCRYPTION;
		setLastErr(ret);
		goto END;
	}
	retByte = jEnv->NewByteArray(lenCipher);
	if (NULL != retByte)
	{
		jEnv->SetByteArrayRegion(retByte, 0, lenCipher, (jbyte *)ccipher);
	}
	else
	{
		ret = JNI_ERR_MEM_ALLOC;
		setLastErr(ret);
	}
	
#ifdef  _DEBUG
	printf("cipher len : %d\n", lenCipher);
	for ( i= 0; i<lenCipher ; i++)
	{
		printf(" %02x", ccipher[i]);
	}
#endif
	
END:
	if (0 != ret)
	{
		sprintf(msg, "sm2 pubkey encrypt failed err!code:0x%02x", ret);
		LOGI(msg);
	}
	
	if (ccipher)
	{
		delete []ccipher;
	}
	if (cPubkey)
	{
		delete []cPubkey;
	}
	jEnv->ReleaseByteArrayElements(jplain, cplain, NULL);
	setLastErr(ret);
	return retByte;
}


//public native byte[] EncryptBySM2Cert(byte[] plain, byte[] derSm2Cert);
JNIEXPORT jbyteArray JNICALL Java_com_Simon_1catt2009_Sm2CryptoCls_EncryptBySm2Cert
  (JNIEnv * jEnv, jobject jObj, jbyteArray jplain, jbyteArray jderSm2Cert)
{
	if (NULL == jplain || NULL == jderSm2Cert )
	{
		LOGI("param err!");
		setLastErr(JNI_ERR_PARAM);
		return NULL;
	}
	
	jbyte * cplain = jEnv->GetByteArrayElements(jplain, NULL);
	jint LenPlain = jEnv->GetArrayLength(jplain);
	jbyte * cDerSm2Cert = jEnv->GetByteArrayElements(jderSm2Cert, NULL);
	jint LenDerSm2Cert = jEnv->GetArrayLength(jderSm2Cert);
	
	char msg[100] = {0};
	jbyteArray retByte = 0;
	jint ret = 0;
	unsigned char sm2pubkey[64] = {0};
	unsigned long lenCipher = LenPlain + 200;
	unsigned char * ccipher = new unsigned char[lenCipher];
	if (NULL == ccipher)
	{
		ret = JNI_ERR_MEM_ALLOC;
		setLastErr(ret);
		goto END;
	}
	memset(ccipher, 0x00, lenCipher);
	
	ret = GetPubkeyFromSM2Cert(sm2pubkey, (unsigned char *)cDerSm2Cert, LenDerSm2Cert);
	if (ret)
	{
		ret = JNI_ERR_CERT_PARSE;
		setLastErr(ret);
		goto END;
	}

	ret = GM_SM2Encrypt(ccipher, &lenCipher, (unsigned char*)cplain, LenPlain, sm2pubkey, 64);
	if (0 != ret)
	{
		ret = JNI_ERR_SM2_ENCRYPTION;
		setLastErr(ret);
		goto END;
	}
	retByte = jEnv->NewByteArray(lenCipher);
	if (NULL != retByte)
	{
		jEnv->SetByteArrayRegion(retByte, 0, lenCipher, (jbyte *)ccipher);
	}
	else
	{
		ret = JNI_ERR_MEM_ALLOC;
		setLastErr(ret);
	}
END:
	if (0 != ret)
	{
		sprintf(msg, "sm2 cert encrypt failed err!code:0x%02x", ret);
		LOGI(msg);
	}
	
	if (ccipher)
	{
		delete []ccipher;
	}
	
	jEnv->ReleaseByteArrayElements(jderSm2Cert,cDerSm2Cert,0);
	jEnv->ReleaseByteArrayElements(jplain,cplain,0);
	setLastErr(ret);
	return retByte;
}

//public native byte[] GetPublicKeyFromSm2Cert(byte[] CertSm2);
JNIEXPORT jbyteArray JNICALL Java_com_Simon_1catt2009_Sm2CryptoCls_GetPublicKeyFromSm2Cert
  (JNIEnv * jEnv, jobject jObj, jbyteArray jsm2Cert)
{
	if(NULL == jsm2Cert)
	{
		LOGI("param err!");
		return NULL;
	}
	int ret = 0;char msg[100] = {0};
	jbyte * derSm2Cert = jEnv->GetByteArrayElements(jsm2Cert, NULL);
	jint LenSm2Cert = jEnv->GetArrayLength(jsm2Cert);
	jbyteArray retByte = 0;
	unsigned char pubkey[64] = {0};
	ret = GetPubkeyFromSM2Cert(pubkey, (unsigned char *)derSm2Cert, LenSm2Cert);
	if (ret)
	{
		ret = JNI_ERR_CERT_PARSE;
		setLastErr(ret);
		LOGI("JNI_ERR_CERT_PARSE");
		goto END;
	}
	retByte = jEnv->NewByteArray(64);
	if (NULL != retByte)
	{
		jEnv->SetByteArrayRegion(retByte, 0, 64, (jbyte*)pubkey);
	}
	else
	{
		ret = JNI_ERR_MEM_ALLOC;
		LOGI("MEMORY_ALLOC_ERROR");
		goto END;
	}
	
END:
	if (0 != ret)
	{
		sprintf(msg, "sm2 pubkey getting failed err!code:0x%02x", ret);
		LOGI(msg);
	}
	jEnv->ReleaseByteArrayElements(jsm2Cert, derSm2Cert, 0);
	setLastErr(ret);
	return retByte;
}


JNIEXPORT jbyteArray JNICALL Java_com_Simon_1catt2009_Sm2CryptoCls_Sm3Hash
  (JNIEnv * jEnv, jobject jObj, jbyteArray jmsg)
{
	if (NULL == jmsg)
	{
		setLastErr(JNI_ERR_PARAM);
		LOGI("PARAM_ERROR");
		return NULL;
	}

	int ret = 0;
	jbyte * cMsg = jEnv->GetByteArrayElements(jmsg, NULL);
	jint LenMsg = jEnv->GetArrayLength(jmsg);
	unsigned char sm3hashTar[32] = {0};
	sm3((unsigned char*)cMsg, LenMsg, sm3hashTar);
	jbyteArray retByte = jEnv->NewByteArray(32);
	if (NULL != retByte)
	{
		jEnv->SetByteArrayRegion(retByte, 0, 32, (jbyte*)sm3hashTar);
	}
	else
	{
		ret = JNI_ERR_MEM_ALLOC;
		LOGI("MEMORY_ALLOC_ERROR");
		goto END;
	}

END:
	if (cMsg)
	{
		jEnv->ReleaseByteArrayElements(jmsg, cMsg, 0);
	}
	setLastErr(ret);
	return retByte;
}


JNIEXPORT jstring JNICALL Java_com_Simon_1catt2009_Sm2CryptoCls_getLibVersion
(JNIEnv * jEnv, jobject jObj)
{
	return jEnv->NewStringUTF(currVersion);
}


JNIEXPORT jint JNICALL Java_com_Simon_1catt2009_Sm2CryptoCls_getLastError
(JNIEnv *, jobject)
{
	return getLastErr();
}


JNIEXPORT jbyteArray JNICALL Java_com_Simon_1catt2009_Sm2CryptoCls_CalcSm2PublicKeyFromPrivateKey
(JNIEnv * jEnv, jobject jObj, jbyteArray jprivateKey)
{
	if (NULL == jprivateKey)
	{
		setLastErr(JNI_ERR_PARAM);
		LOGI("param err!");
		return NULL;
	}
	
	jint LenPrikey = jEnv->GetArrayLength(jprivateKey);
	if (32 != LenPrikey)
	{
		setLastErr(JNI_ERR_PARAM);
		LOGI("private key length err!");
		return NULL;
	}
	
	jbyte * cprivateKey = jEnv->GetByteArrayElements(jprivateKey, NULL);
	int ret = 0;
	unsigned char pubkey [64] = {0};
	ret = BYTE_Point_mul((unsigned char *)cprivateKey, pubkey);
	if (ret)
	{
		setLastErr(ret);
		LOGI("point multiply failed!");
		return NULL;
	}
	
	jbyteArray byteRet = NULL;
	byteRet = jEnv->NewByteArray(64);
	if (NULL != byteRet)
	{
		jEnv->SetByteArrayRegion(byteRet, 0, 64, (jbyte *)pubkey);
		setLastErr(0);
	}
	else
	{
		setLastErr(JNI_ERR_MEM_ALLOC);
		LOGI("mem alloc failed!");
	}
	
	jEnv->ReleaseByteArrayElements(jprivateKey, cprivateKey, 0);
	return byteRet;
}


