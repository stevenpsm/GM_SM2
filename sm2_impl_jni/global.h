
#ifndef WIN32
#ifndef _LINUX
#include <android/log.h>
#define  LOGRECORD
#endif
#endif

#ifdef LOGRECORD
#define LOGI(message...) __android_log_print(ANDROID_LOG_INFO,"CORE-JNILOG",message)
#else 
#define LOGI(message)  printf("\n%s\n", message);
#endif //LOGRECORD


extern const char * default_uid_str;
extern int lastErr;

void setLastErr(int Err);

//err code
#define  JNI_OK						0
#define  JNI_ERR_PARAM				1
#define  JNI_ERR_MEM_ALLOC			2
#define  JNI_ERR_SM2_SIGNATURE		3
#define  JNI_ERR_SM2_SIG_VERIFY		4
#define  JNI_ERR_SM2_ENCRYPTION		5
#define  JNI_ERR_SM2_DECRYPTION		6
#define  JNI_ERR_SM4_ENCRYPTION		7
#define  JNI_ERR_SM4_DECRYPTION		8
#define  JNI_ERR_SM3_HASH			9
#define  JNI_ERR_CERT_PARSE			10
#define  JNI_ERR_SM2PUBKEY_PARSE		11
#define  JNI_ERR_FILE_READ_WRITE_ERROR	12
#define  JNI_ERR_BUFFER_TOO_SMALL		13

#define  JNI_ERR_PUBKEY_ENCODE_ERROR    14
#define  JNI_ERR_PRIKEY_ENCODE_ERROR    15
#define  JNI_ERR_CIPHER_ENCODE_ERROR    16
#define  JNI_ERR_SIGNATURE_ENCODE_ERROR    17
#define  JNI_ERR_PUBKEY_DECODE_ERROR    18
#define  JNI_ERR_PRIKEY_DECODE_ERROR    19
#define  JNI_ERR_CIPHER_DECODE_ERROR    20
#define  JNI_ERR_SIGNATURE_DECODE_ERROR    21