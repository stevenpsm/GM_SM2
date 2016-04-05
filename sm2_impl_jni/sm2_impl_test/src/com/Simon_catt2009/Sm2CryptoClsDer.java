/**
		* @title Sm2CryptoClsDer.java
		* @package com.Simon_catt2009
		* @description 
		* @author simonPang
		* @update 2013-1-4 下午4:48:05
		* @version V1.0
		*/
package com.Simon_catt2009;

/**
 * @description 
 * @version 1.0
 * @author simonPang
 * @update 2013-1-4 下午4:48:05
 */

public class Sm2CryptoClsDer extends Sm2CryptoCls {
	private static Sm2CryptoClsDer ins = new Sm2CryptoClsDer();

	public static Sm2CryptoClsDer getInstance() {
		return ins;
	}
	
	/**
	 * @param message
	 *            [in]message that you wanna sign about
	 * @param privateKeyDerStr
	 *            [in]input private key,should be der encoded
	 * @return signature will be der encoded signature data
	 * @description
	 * @version 1.0
	 * @author simonPang
	 * @update 2012-9-25 下午5:30:37
	 */
	public byte[] SignBySm2PrivatekeyDer(byte[] message, byte[] privateKeyDerStr)
	{
		byte[] sm2PubKey_XY = new byte [64];
		byte[] sm2PrikeyRnd = sm2PrivateKeyDerDecode(privateKeyDerStr, sm2PubKey_XY);
		byte[] sig_RS = SignBySm2Privatekey(message, sm2PrikeyRnd);
		return sm2SignatureDerEncode(sig_RS);
	}

	/**
	 * @param CertSm2
	 *            [in]input sm2 certificate
	 * @param signatureDer
	 *            [in]should be der encoded signature 
	 * @param src
	 *            [in]source data
	 * @return whether or not ok of the signature ,if 0 returned, verification
	 *         success!
	 * @description
	 * @version 1.0
	 * @author simonPang
	 * @update 2012-9-25 下午5:31:26
	 */
	public  int VerifySm2SignatureDerByCert(byte[] CertSm2,
			byte[] signatureDer, byte[] src)
	{
		byte [] sign_rs = sm2SignatureDerDecode(signatureDer);
		return VerifySm2SignatureByCert(CertSm2, sign_rs, src);
	}

	/**
	 * 
	 * @param PublicKeySm2Der
	 *            [in]input sm2 public key,should be der encoded
	 * @param signatureDer
	 *            [in]should be der encoded signature
	 * @param src
	 *            [in]source data
	 * @return whether or not ok of the signature ,if 0 returned, verification
	 *         success!
	 * @description
	 * @version 1.0
	 * @author simonPang
	 * @update 2012-9-25 下午5:31:40
	 */
	public int VerifySm2SignatureDerByPubKeyDer(byte[] PublicKeySm2Der,
			byte[] signatureDer, byte[] src)
	{
		byte [] sig_rs = sm2SignatureDerDecode(signatureDer);
		byte [] pubkey_XY = sm2PubkeyDerDecode(PublicKeySm2Der);
		return VerifySm2SignatureByPubKey(pubkey_XY, sig_rs, src);
	}

	/**
	 *  
	 * @return der encoded private key
	 * @description
	 * @version 1.0
	 * @author simonPang
	 * @update 2012-9-25 下午5:31:48
	 */
	public byte[] GenerateSm2PrikeyDer()
	{
		byte [] prikRnd = new byte [32];
		byte [] pubkey_XY = GenerateSm2KeyPair(prikRnd);
		return  sm2PrivateKeyDerEncode(prikRnd, pubkey_XY);
	}

	/**
	 * 
	 * @param rand
	 *            [in]input random number
	 * @return der encoded private key
	 * @description
	 * @version 1.0
	 * @author simonPang
	 * @update 2012-9-25 下午5:31:54
	 */
	public byte[] GenerateSm2PrikeyDer(byte[] rand)
	{
		byte [] prikRnd = new byte [32];
		byte [] pubkey_XY = GenerateSm2KeyPair(rand , prikRnd);
		return  sm2PrivateKeyDerEncode(prikRnd, pubkey_XY);
	}

	/**
	 * 
	 * @param privateKeyDer
	 *            [in]input private key,should be der encoded
	 * @return public key returned corresponding to the private key provided
	 *         above, will be der encoded
	 * @description
	 * @version 1.0
	 * @author simonPang
	 * @update 2012-9-25 下午5:31:59
	 */
	public byte[] GetSm2PublicKeyDerFromPrivateKeyDer(byte[] privateKeyDer)
	{
		byte pubkey_XY[]  = new byte[64];
		sm2PrivateKeyDerDecode(privateKeyDer, pubkey_XY);
		return sm2PubKeyDerEncode(pubkey_XY);
	}



	/**
	 * 
	 * @param CertSm2
	 *            [in]input cert to decode
	 * @return sm2 derencoded public key corresponding to the input cert
	 * @description
	 * @version 1.0
	 * @author simonPang
	 * @update 2012-9-25 下午5:32:19
	 */
	public byte[] GetPublicKeyDerFromSm2Cert(byte[] CertSm2)
	{
		 byte [] pubkey_xy = GetPublicKeyFromSm2Cert(CertSm2);
		 return sm2PubKeyDerEncode(pubkey_xy);
	}
	
	//begin from 0;
	public byte[] getSubByteArray(byte[] src, int iter_begin, int iter_end)
	{
		if(iter_end <= iter_begin)
		  return null;//error
		
		int len = iter_end-iter_begin+1;
		byte [] returnBytes = new byte [len];
		for(int i = 0; i<len; i++)
		{
			returnBytes[i] = src[i+iter_begin];
		}
		
		return returnBytes;
	}
	
	public byte[] bytesMerge(byte [] src1, byte[] src2)
	{
		byte[] returnBytes = new byte [src1.length + src2.length];
		for (int i = 0; i < src1.length; i++) {
			returnBytes[i] = src1[i];
		}
		for (int j = 0; j < src2.length; j++) {
			returnBytes[src1.length+j] = src2[j];
		}
		return returnBytes;
	}
	
	public byte[] EncryptBySm2PublicKeyDer(byte[] plain, byte[] Sm2PubkeyDer)
	{
		byte [] pubkey_xy = sm2PubkeyDerDecode(Sm2PubkeyDer);
		int pubkey_length = pubkey_xy.length;
		byte [] encDataPlain = EncryptBySm2PublicKey(plain, pubkey_xy);
		if (encDataPlain.length < plain.length + 97  || encDataPlain.length > plain.length + 99) {
			// throw exeption or?
			// length error!!
			return null;
		}
		
		byte [] C1_XY = new byte[64];
		int C1_XY_origin_len = encDataPlain.length-32-plain.length-1;
		if (64 == C1_XY_origin_len) {
			C1_XY = getSubByteArray(encDataPlain, 1, 64);
		}
		else if(65 == C1_XY_origin_len  && 0x00 == encDataPlain[1])
		{
			C1_XY = getSubByteArray(encDataPlain, 2, 65);
		}
		else if(65 == C1_XY_origin_len && 0x00 == encDataPlain[33]){
			byte[] C1_XY_left = getSubByteArray(encDataPlain, 1,32);
			byte[] C1_XY_right = getSubByteArray(encDataPlain, 34,65);
			C1_XY = bytesMerge(C1_XY_left , C1_XY_right);
		}
		else if (66 == C1_XY_origin_len && 0x00 == encDataPlain[1] && 0x00 == encDataPlain[34]) {
			byte[] C1_XY_left = getSubByteArray(encDataPlain, 2,33);
			byte[] C1_XY_right = getSubByteArray(encDataPlain, 35,66);
			C1_XY = bytesMerge(C1_XY_left , C1_XY_right);
		}
		else
		{
			// throw exeption or?
			// length error!!
			return null;
		}
		byte [] C2_cipher = getSubByteArray(encDataPlain, encDataPlain.length-32-plain.length, encDataPlain.length-32-1);
		byte [] C3_hash = getSubByteArray(encDataPlain,encDataPlain.length-32,  encDataPlain.length-1);
		
		byte[] returnData = sm2CipherDerEncode(C2_cipher, C1_XY, C3_hash); 
		return returnData;
	}


}
