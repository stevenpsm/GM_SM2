

#ifdef WIN32
#pragma comment(lib, "../lib/libeay32.lib")
#endif

#ifdef   _LINUX
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#include "../sm2_impl/sm3.h"
#include "global.h"
#include "string.h"
#include "openssl/x509.h"
#include "openssl/rand.h"
#include "utils.h"



int GetPubkeyFromSM2Cert(unsigned char  szPubkey_XY[64], 
						 const unsigned char * derSm2Cert, 
						 unsigned long  ulderSm2CertLen)
{
	if (NULL == szPubkey_XY || NULL == derSm2Cert || 0 == ulderSm2CertLen)
	{
		return JNI_ERR_PARAM;
	}
	//LOGI("GetPubkeyFromSM2Cert:Begin");
	OpenSSL_add_all_algorithms();
	X509 * pX509 = NULL;
	const unsigned char * p = derSm2Cert;
	pX509 = d2i_X509(NULL, &p, ulderSm2CertLen);
	if (NULL == pX509)
	{
		return JNI_ERR_CERT_PARSE;
	}
	
	int sm2PubkeyLen = pX509->cert_info->key->public_key->length;
	unsigned char * p_sm2_pubkey_data  = pX509->cert_info->key->public_key->data;
	if (sm2PubkeyLen<64 || sm2PubkeyLen > 80)
	{
		if (pX509)
		{
			X509_free(pX509);
		}
		
		return JNI_ERR_SM2PUBKEY_PARSE;
	}
	int headerLen = sm2PubkeyLen - 64;
	
	memcpy(szPubkey_XY, p_sm2_pubkey_data+headerLen, 64);
	
	
	if (pX509)
	{
		X509_free(pX509);
	}
	//LOGI("GetPubkeyFromSM2Cert:Finish!");
	return JNI_OK;
	
}


int genRand(unsigned char rand[32])
{
	unsigned char rand_tar[32] = {0};
	unsigned char seedbuf[32] = {0};
	const time_t t = time(NULL);
	struct tm* current_time = localtime(&t);
	int ret = 0;
	sm3((unsigned char *)current_time, sizeof(struct tm), seedbuf);
	RAND_seed(seedbuf, 32);
	//保证具有足够的随机性
	while (1)
	{
		ret = RAND_status();
		if (ret == 1)
		{
			break;
		}
		else
		{
			RAND_poll();
		}
	}
	ret = RAND_bytes(rand_tar, 32);
	RAND_cleanup();

#ifdef _LINUX
	int fd;
	fd = open("/dev/random", O_RDONLY);
	if (fd == -1)
	{
		//free(buf);
		close(fd);
		return JNI_ERR_FILE_READ_WRITE_ERROR;	
	}
	unsigned char rand_file_buf[32] = {0};
	read(fd, rand_file_buf, 32);
	sm3(rand_file_buf, 32, seedbuf);
	XOR_STRING(rand_tar, rand_tar, seedbuf, 32);

#endif
	
	memcpy(rand, rand_tar, 32);
	return 0;
}



int XOR_STRING(unsigned char * tar, unsigned char * x, unsigned char * y, int l)
{
	for (int i = 0; i<l; i++)
	{
		tar[i] = x[i]^y[i];
	}
	
	return 0;
}
