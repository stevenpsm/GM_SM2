// sm2_libtom.cpp : Defines the entry point for the console application.
//
#include "stdio.h"
#include "stdlib.h"
#include "sm2.h"
#include "base64.h"

#ifdef WIN32
#if 1 // sm2_impl static lib
#pragma comment (lib , "../win32rls/tommath.lib")
#pragma comment (lib , "../win32rls/sm2_impl.lib")
#endif //
#if 0 // sm2_impl_dll
#pragma comment (lib , "../win32rls/sm2_dll.lib")
#endif
#endif // WIN32


#define CHECK_RET_TEST(x) {if(x) {printf("err!code:%04x\n", x);exit(x);}};

int main(int argc, char* argv[])
{
	printf("Hello World!\n");
	printf("%s", getVersion());
	printf("any problem, contact me! thanx!\n");
#ifdef _DEBUG
//	printf("_DEBUG macro:%d",_DEBUG);
#endif
	int ret = 0;

// 	ret = test_Ecc_Intrfs_sig_veri();
// 	ret = test_SM3_withZ_value_process();
 	ret = test_GM_encryption_and_decryption();
 	ret = test_GM_signature_and_verify();
// 	ret = test_gen_SM2_GM_keypair();


	return ret;
}

