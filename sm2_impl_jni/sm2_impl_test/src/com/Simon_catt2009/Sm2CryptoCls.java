package com.Simon_catt2009;

/**
 * 
 * @description sm2 implimentation based upon libTomMath library and goldbar's
 *              sm3 project
 * @version 1.0
 * @author simonPang of catt2009 
 * @reference : 1. Public Key Cryptographic Algorithm SM2 Based on Elliptic
 *            Curves [Part 1: General] page 18/93 (or page 12 of part one) and
 *            28/93(page 22 of part one); 57/93(page 7 of part two) 2. bn.pdf of
 *            LibTomMath User Manual 3. Guide to Elliptic Curve Cryptography
 * @update 2012-9-25 下午5:32:54
 */
public class Sm2CryptoCls {

	private static Sm2CryptoCls jni = new Sm2CryptoCls();

	protected Sm2CryptoCls() {
		System.loadLibrary("sm2_impl_jni");
	}

	public static Sm2CryptoCls getInstance() {
		return jni;
	}

	/**
	 * @param message
	 *            [in]message that you wanna sign about
	 * @param privateKey
	 *            [in]input private key,should be 32 bytes
	 * @return signature will be 64 bytes
	 * @description
	 * @version 1.0
	 * @author simonPang
	 * @update 2012-9-25 下午5:30:37
	 */
	public native byte[] SignBySm2Privatekey(byte[] message, byte[] privateKey);

	/**
	 * @param CertSm2
	 *            [in]input sm2 certificate
	 * @param signature
	 *            [in]should be 64 bytes
	 * @param src
	 *            [in]source data
	 * @return whether or not ok of the signature ,if 0 returned, verification
	 *         success!
	 * @description
	 * @version 1.0
	 * @author simonPang
	 * @update 2012-9-25 下午5:31:26
	 */
	public native int VerifySm2SignatureByCert(byte[] CertSm2,
			byte[] signature, byte[] src);

	/**
	 * 
	 * @param PublicKeySm2
	 *            [in]input sm2 public key
	 * @param signature
	 *            [in]should be 64 bytes
	 * @param src
	 *            [in]source data
	 * @return whether or not ok of the signature ,if 0 returned, verification
	 *         success!
	 * @description
	 * @version 1.0
	 * @author simonPang
	 * @update 2012-9-25 下午5:31:40
	 */
	public native int VerifySm2SignatureByPubKey(byte[] PublicKeySm2,
			byte[] signature, byte[] src);

	/**
	 * 
	 * @param privateKey
	 *            [in,out]buffer to save returned private key,should be 32 bytes
	 * @return public key to be returned, will be 64 bytes
	 * @description
	 * @version 1.0
	 * @author simonPang
	 * @update 2012-9-25 下午5:31:48
	 */
	public native byte[] GenerateSm2KeyPair(byte[] privateKey);

	/**
	 * 
	 * @param rand
	 *            [in]input random number
	 * @param privateKey
	 *            [in,out]buffer to save returned private key,should be 32 bytes
	 * @return public key to be returned, will be 64 bytes
	 * @description
	 * @version 1.0
	 * @author simonPang
	 * @update 2012-9-25 下午5:31:54
	 */
	public native byte[] GenerateSm2KeyPair(byte[] rand, byte[] privateKey);

	/**
	 * 
	 * @param privateKey
	 *            [in]input private key,should be 32 bytes
	 * @return public key returned corresponding to the private key provided
	 *         above, will be 64 bytes
	 * @description
	 * @version 1.0
	 * @author simonPang
	 * @update 2012-9-25 下午5:31:59
	 */
	public native byte[] CalcSm2PublicKeyFromPrivateKey(byte[] privateKey);

	/**
	 * 
	 * @param inputCipher
	 *            [in]Cipher to decrypt
	 * @param privateKey
	 *            [in]private key to decrypt the cipher
	 * @return decrypted plain text, if null returned ,represent decryption
	 *         failed!
	 * @description
	 * @version 1.0
	 * @author simonPang
	 * @update 2012-9-25 下午5:32:05
	 */
	public native byte[] DecryptBySm2PrivateKey(byte[] inputCipher,
			byte[] privateKey);

	/**
	 * 
	 * @param plain
	 *            [in]text to be encrypted to
	 * @param Sm2Pubkey
	 *            [in]input sm2 public key XY;
	 * @return cipher of sm2 encryption
	 * @description
	 * @version 1.0
	 * @author simonPang
	 * @update 2012-9-25 下午5:32:10
	 */
	public native byte[] EncryptBySm2PublicKey(byte[] plain, byte[] Sm2Pubkey);

	/**
	 * 
	 * @param plain
	 *            [in]text to be encrypted to
	 * @param derSm2Cert
	 *            [in]input sm2 cert
	 * @return cipher of sm2 encryption
	 * @description
	 * @version 1.0
	 * @author simonPang
	 * @update 2012-9-25 下午5:32:15
	 */
	public native byte[] EncryptBySm2Cert(byte[] plain, byte[] derSm2Cert);

	/**
	 * 
	 * @param CertSm2
	 *            [in]input cert to decode
	 * @return sm2 public key corresponding to the input cert
	 * @description
	 * @version 1.0
	 * @author simonPang
	 * @update 2012-9-25 下午5:32:19
	 */
	public native byte[] GetPublicKeyFromSm2Cert(byte[] CertSm2);

	/**
	 * 
	 * @param srcdata
	 *            [in]source data to be hashed
	 * @return sm3 hash data,null if error happens
	 * @description
	 * @version 1.0
	 * @author simonPang
	 * @update 2012-9-25 下午5:32:23
	 */
	public native byte[] Sm3Hash(byte[] srcdata);


	/**
	 * 
	 * @return version
	 * @description
	 * @version 1.0
	 * @author simonPang
	 * @update 2012-9-25 下午5:32:35
	 */
	public native String getLibVersion();

	/**
	 * 
	 * @return last err code
	 * @description
	 * @version 1.0
	 * @author simonPang
	 * @update 2012-9-25 下午5:32:38
	 */
	public native int getLastError();

	/**
	 * 
	 * @param key
	 *            [in]sm2pubkey_XY,length should be 64 bytes
	 * @return Der encoded sm2 public key,null if error happens
	 * @description
	 * @version 1.0
	 * @author simonPang
	 * @update 2012-12-14 下午4:36:40
	 */
	public native byte[] sm2PubKeyDerEncode(byte[] sm2pubkey_XY);

	/**
	 * 
	 * @param sm2DerPub
	 *            [in]sm2 pubkey of der format,
	 * @return sm2 public key xy coordinate,should be 64 bytes,null if error
	 *         happens
	 * @description
	 * @version 1.0
	 * @author simonPang
	 * @update 2012-12-14 下午4:36:40
	 */
	public native byte[] sm2PubkeyDerDecode(byte[] sm2DerPub);

	/**
	 * 
	 * @param prikeyRand
	 *            [in] private key random number, should be 32 bytes long;
	 * @param sm2pubkey_XY
	 *            [in]pubkey xy coordinates,should be 64 bytes long;
	 * @return sm2 private key der format;,null if error happens
	 * @description
	 * @version 1.0
	 * @author simonPang
	 * @update 2012-12-14 下午4:53:17
	 */
	public native byte[] sm2PrivateKeyDerEncode(byte[] prikeyRand,
			byte[] sm2pubkey_XY);

	/**
	 * 
	 * @param sm2PrivateKeyDerStr
	 *            [in]input private key der format;
	 * @param sm2PubKey_XY
	 *            [in/out]out put buffer of pubkey XY coodinates,len=64
	 * @return derDecoded privatekey ,will be 32 bytes long ,null if error
	 *         happens
	 * @description
	 * @version 1.0
	 * @author simonPang
	 * @update 2012-12-14 下午4:58:28
	 */
	public native byte[] sm2PrivateKeyDerDecode(byte[] sm2PrivateKeyDerStr,
			byte[] sm2PubKey_XY);

	/**
	 * 
	 * @param ci
	 *            [in]cipher data,any length
	 * @param pub_XY
	 *            [in]pubkey xy coordinate,len=64
	 * @param sm3hash
	 *            [in]sm3 hash,len=32
	 * @return der encoded cipher data,null if error happens
	 * @description
	 * @version 1.0
	 * @author simonPang
	 * @update 2012-12-14 下午5:03:10
	 */
	public native byte[] sm2CipherDerEncode(byte[] ci, byte[] pub_XY,
			byte[] sm3hash);

	/**
	 * not apllicable yet!!!
	 * @param derCipher
	 *            [in]input der cipher data waiting to decode;
	 * @param pubkey_XY
	 *            [in/out]output buffer for pubkey_XY,will be 64bytes long;
	 * @param sm3hash
	 *            [in/out]output buffer for sm3hash,will be 32bytes long;
	 * @return der decoded cipher data,any length,null if error happens
	 * @description
	 * @version 1.0
	 * @author simonPang
	 * @update 2012-12-14 下午5:10:28
	 */
	public native byte[] sm2CipherDerDecode(byte[] derCipher, byte[] pubkey_XY,
			byte[] sm3hash);

	/**
	 * 
	 * @param signature_RS
	 *            [in]signature data waiting to encode to der format,len=64
	 * @return der format of signature
	 * @description
	 * @version 1.0
	 * @author simonPang
	 * @update 2012-12-14 下午5:15:11
	 */
	public native byte[] sm2SignatureDerEncode(byte[] signature_RS);

	/**
	 * 
	 * @param derSig
	 *            [in]der format signature
	 * @return decoded signature,len=64,[r,s];null if error happens
	 * @description
	 * @version 1.0
	 * @author simonPang
	 * @update 2012-12-14 下午5:16:03
	 */
	public native byte[] sm2SignatureDerDecode(byte[] derSig);
	
	/**
	 * 
			* @return error code;
			* @description random generation test,used to supply source for nist test tool ;
			* @version 1.0
			* @author simonPang
			* @update 2013-1-18 上午11:08:28
	 */
	public native int RandGenTest(String genPath, int randBytesLength);

}
