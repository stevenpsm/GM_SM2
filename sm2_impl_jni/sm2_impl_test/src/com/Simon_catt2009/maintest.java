package com.Simon_catt2009;

import java.io.*;

class MultiThreadTest extends Thread {
	public MultiThreadTest(String threadName) {
		super(threadName);
	}

	public void run() {
		System.out.println(getName() + " test Thread start...");
		try {
			// sleep((int) Math.random() * 10);
			 for (int i = 1; i< 100; i++)
			 {
			normalTestCls.testEfficiency();
			 }
		} catch (/* InterruptedException e */Exception e) {
			e.printStackTrace();
		}

		System.out.println(getName() + " test Thread end...");
	}
}

class normalTestCls {
	static int iter = 10;

	public static int testCrypto() {

		String msg = "helloworld!";
		String sm2CertBase64Str = "MIIBwzCCAXCgAwIBAgIDBpLWMAoGCCqBHM9VAYN1MCoxCzAJBgNVBAYTAkNOMRswGQYDVQQDDBLkuKrkurrkuoznuqdDQV9TTTIwHhcNMTIwNzMwMDgwOTM1WhcNMTMwNzMwMDgwOTM1WjAoMQswCQYDVQQGEwJDTjEKMAgGA1UECAwBMDENMAsGA1UEAwwEZmFzZjBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABHm+kPUBN3cCqnxexr8Dc+S7JnJ63L0Bjw+7rge7w5RFhDCm6/Y3xR3AqSnr+0s8rCMmfHy3Y6BheDbASxmKXpajgYYwgYMwHwYDVR0jBBgwFoAUzqZvnoUUwEjzX5r4j4cWVgJPpPkwNAYDVR0gBC0wKzApBgUqVgsHATAgMB4GCCsGAQUFBwIBFhJodHRwOi8vY2NpdC5jcG0uY24wCwYDVR0PBAQDAgbAMB0GA1UdDgQWBBQSIz8x6O+Zi1jZm0S0z8D+D5mlgDAKBggqgRzPVQGDdQNBAFO4kZzf58FK2LKAkYPEd6lOjV4pwyB+Xz2xA1YiK1LkADkqVbX7v9zMaxMAItZSBlAZP0zdDW7c8zPJITK5n7M=";

		byte[] sm2PrivateKey = new byte[32];
		byte[] sm2Pubkey = Sm2CryptoCls.getInstance().GenerateSm2KeyPair(
				sm2PrivateKey);
		CheckRet(sm2Pubkey);
		CheckRet(sm2PrivateKey);

		byte[] sm2PrivateKeyNew = new byte[32];
		byte[] rand = "jaslkdfhyui4".getBytes();
		byte[] sm2PubkeyNew = Sm2CryptoCls.getInstance().GenerateSm2KeyPair(
				rand, sm2PrivateKeyNew);
		CheckRet(sm2PubkeyNew.length == 64);
		CheckRet(sm2PrivateKeyNew.length == 32);

		byte[] pubNew = Sm2CryptoCls.getInstance()
				.CalcSm2PublicKeyFromPrivateKey(sm2PrivateKeyNew);
		CheckRet(CheckEql(sm2PubkeyNew, pubNew));

		byte[] signature = Sm2CryptoCls.getInstance().SignBySm2Privatekey(
				msg.getBytes(), sm2PrivateKeyNew);
		CheckRet(signature);

		int ret = Sm2CryptoCls.getInstance().VerifySm2SignatureByPubKey(
				sm2PubkeyNew, signature, msg.getBytes());
		CheckRet(ret);

		byte[] encdata = Sm2CryptoCls.getInstance().EncryptBySm2PublicKey(
				msg.getBytes(), sm2PubkeyNew);
		CheckRet(encdata);

		byte[] decdata = Sm2CryptoCls.getInstance().DecryptBySm2PrivateKey(
				encdata, sm2PrivateKeyNew);
		CheckRet(CheckEql(decdata, msg.getBytes()));
		String decString = new String(decdata);

		byte[] derSm2Cert = Base64.decode(sm2CertBase64Str);
		CheckRet(derSm2Cert);
		encdata = Sm2CryptoCls.getInstance().EncryptBySm2Cert(msg.getBytes(),
				derSm2Cert);
		CheckRet(encdata);

		byte[] sm4key = "helloworld!".getBytes();
		byte[] sm4cipher = Sm2CryptoCls.getInstance().Sm4SymEncrypt(sm4key,
				msg.getBytes());
		CheckRet(sm4cipher);
		byte[] sm4DecData = Sm2CryptoCls.getInstance().Sm4SymDecrypt(sm4key,
				sm4cipher);
		CheckRet(CheckEql(sm4DecData, msg.getBytes()));
		decString = new String(sm4DecData);

		byte[] sm3HashData = Sm2CryptoCls.getInstance().Sm3Hash(msg.getBytes());
		CheckRet(sm3HashData);

		return 0;
	}

	// average 600 millis for a keypair generation
	public static byte[] testGenkeyPairEfficiency(byte[] privateKey) {
		CheckRet(privateKey);

		byte[] publicKey = new byte[64];
		long timeStart = System.currentTimeMillis();
		for (int i = 0; i < iter; i++) {
			publicKey = Sm2CryptoCls.getInstance().GenerateSm2KeyPair(
					privateKey);
		}
		long timeEnd = System.currentTimeMillis();
		// step1;
		double diff = timeEnd - timeStart;
		double calcTimeForKeyGen = (diff) / (double) iter;
		System.out.println("effi (millis):" + "\n...key gen time claps:"
				+ calcTimeForKeyGen + "...\n");
		return publicKey;
	}

	public static int testEncryptAndDecEfficiency(byte[] privateKey,
			byte[] publicKey, byte[] src) {
		CheckRet(privateKey);
		CheckRet(publicKey);
		CheckRet(src);
		long timeStart = System.currentTimeMillis();
		for (int i = 0; i < iter; i++) {
			byte[] encdata = Sm2CryptoCls.getInstance().EncryptBySm2PublicKey(
					src, publicKey);
			CheckRet(encdata);
		}
		long timeEnd = System.currentTimeMillis();
		// step 4, encryption
		double diff = timeEnd - timeStart;
		double calcTimeForEncryption = (diff) / (double) iter;
		System.out.println("effi (millis):" + "\n...encryption time claps:"
				+ calcTimeForEncryption + "...\n");

		byte[] encdata = Sm2CryptoCls.getInstance().EncryptBySm2PublicKey(src,
				publicKey);
		timeStart = System.currentTimeMillis();
		for (int i = 0; i < iter; i++) {
			byte[] decdata = Sm2CryptoCls.getInstance().DecryptBySm2PrivateKey(
					encdata, privateKey);
			CheckRet(CheckEql(decdata, src));
		}
		timeEnd = System.currentTimeMillis();

		// step 5, decryption
		diff = timeEnd - timeStart;
		double calcTimeForDecryption = (diff) / (double) iter;
		System.out.println("effi (millis):" + "\n...decryption time claps:"
				+ calcTimeForDecryption + "...\n");

		return 0;
	}

	public static int testSymAndHashFucsEfficiency(byte[] src, byte[] key) {
		CheckRet(src);
		CheckRet(key);
		long timeStart = System.currentTimeMillis();
		for (int i = 0; i < iter; i++) {
			byte[] sm4cipher = Sm2CryptoCls.getInstance().Sm4SymEncrypt(key,
					src);
			CheckRet(sm4cipher);
		}
		long timeEnd = System.currentTimeMillis();
		// step 4, encryption
		double diff = timeEnd - timeStart;
		double calcTimeForSymEncryption = ((diff) / (double) iter)
				* (128.0 / (double) src.length);
		System.out.println("effi (millis/128bytes):"
				+ "\n...SymEncryption time claps:" + calcTimeForSymEncryption
				+ "...\n");

		byte[] sm4cipher = Sm2CryptoCls.getInstance().Sm4SymEncrypt(key, src);
		CheckRet(sm4cipher);
		timeStart = System.currentTimeMillis();
		for (int i = 0; i < iter; i++) {
			// CheckRet(sm4cipher);
			byte[] sm4DecData = Sm2CryptoCls.getInstance().Sm4SymDecrypt(key,
					sm4cipher);
			CheckRet(CheckEql(sm4DecData, src));
		}
		timeEnd = System.currentTimeMillis();
		// step 4, encryption
		diff = timeEnd - timeStart;
		double calcTimeForSymDecryption = ((diff) / (double) iter)
				* (128.0 / (double) src.length);
		System.out.println("effi (millis/128bytes):"
				+ "\n...SymDecryption time claps:" + calcTimeForSymDecryption
				+ "...\n");

		timeStart = System.currentTimeMillis();
		for (int i = 0; i < iter; i++) {
			byte[] hash = Sm2CryptoCls.getInstance().Sm3Hash(src);
			CheckRet(hash);
		}
		timeEnd = System.currentTimeMillis();
		// step 4, encryption
		diff = timeEnd - timeStart;
		double calcTimeForHash = ((diff) / (double) iter)
				* (128.0 / (double) src.length);
		System.out.println("effi (millis/128bytes):" + "\n...Hash time claps:"
				+ calcTimeForHash + "...\n");

		return 0;
	}

	public static int testSignAndVerifyEfficiency(byte[] privateKey,
			byte[] publicKey, byte[] src) {
		CheckRet(privateKey);
		CheckRet(publicKey);
		CheckRet(src);
		byte[] signature = new byte[64];
		int ret = 0;
		long timeStart = System.currentTimeMillis();
		for (int i = 0; i < iter; i++) {
			signature = Sm2CryptoCls.getInstance().SignBySm2Privatekey(src,
					privateKey);
			CheckRet(signature);
		}
		long timeEnd = System.currentTimeMillis();
		// step 2 signature
		double diff = timeEnd - timeStart;
		double calcTimeForSign = (diff) / (double) iter;
		System.out.println("effi (millis):" + "\n...signature time claps:"
				+ calcTimeForSign + "...\n");

		timeStart = System.currentTimeMillis();
		for (int i = 0; i < iter; i++) {
			// publicKey =
			// Sm2CryptoCls.getInstance().CalcSm2PublicKeyFromPrivateKey(privateKey);
			// signature = Sm2CryptoCls.getInstance().SignBySm2Privatekey(src,
			// privateKey);
			ret = Sm2CryptoCls.getInstance().VerifySm2SignatureByPubKey(
					publicKey, signature, src);
			CheckRet(ret);
		}
		timeEnd = System.currentTimeMillis();
		// step 3 verification
		diff = timeEnd - timeStart;
		double calcTimeForVerification = (diff) / (double) iter;
		System.out.println("effi (millis):" + "\n...verify time claps:"
				+ calcTimeForVerification + "...\n");

		return 0;
	}

	/**
	 * 
	 * @return
	 * @description efficiency test!!!
	 * @version 1.0
	 * @author simonPang
	 * @update 2012-9-25 ÏÂÎç5:55:06
	 */
	public static int testEfficiency() {
		byte[] src = "helloworld!".getBytes();
		byte[] key = "wooo".getBytes();
		byte[] privateKey = new byte[32];
		byte[] pubkey = new byte[64];
		pubkey = testGenkeyPairEfficiency(privateKey);
		testSignAndVerifyEfficiency(privateKey, pubkey, src);
		testEncryptAndDecEfficiency(privateKey, pubkey, src);
		//testSymAndHashFucsEfficiency(src, key);

		return 0;
	}

	public static int CheckRet(int ret) {
		if (0 != ret) {
			System.out.println("error! code" + ret);
			System.exit(-1);// if err occurs, terminate the programme!!
		}
		return 0;
	}

	public static int CheckRet(boolean ret) {
		if (true != ret) {
			System.out.println("error! code" + ret);
			System.exit(-3);// if err occurs, terminate the programme!!
		}
		return 0;
	}

	public static int CheckEql(byte[] by1, byte[] by2) {
		// System.out.println("check by1");
		CheckRet(by1);
		// System.out.println("check by2");
		CheckRet(by2);
		if (by1.length != by2.length) {
			return -1;
		}
		for (int i = 0; i < by1.length; i++) {
			if (by1[i] != by2[i]) {
				return -2;
			}
		}

		return 0;// if equal return 0

	}

	public static int CheckRet(byte[] ret) {
		if (null == ret) {
			System.out.println("NULL Catched!");
			System.exit(-2);
		}
		return 0;
	}

	public static int CheckRet(int ret, String dispOK) {
		if (0 != ret) {
			System.out.println("error! code" + ret);
			System.exit(-1);// if err occurs, terminate the programme!!
		} else {
			System.out.println(dispOK);
		}
		return 0;
	}

	public static int testDer() {
		byte[] sm2PrivateKey = new byte[32];
		byte[] sm2Pubkey = Sm2CryptoCls.getInstance().GenerateSm2KeyPair(
				sm2PrivateKey);
		CheckRet(sm2Pubkey);
		CheckRet(sm2PrivateKey);
		byte[] dersm2pub = Sm2CryptoCls.getInstance().sm2PubKeyDerEncode(
				sm2Pubkey);

		try {
			FileOutputStream out = new FileOutputStream(new File(
					"test8989asdfasdf.txt"));
			out.write(dersm2pub);
		} catch (Exception e) {
			// TODO: handle exception
		}

		return 0;
	}

	public static int write(String fileName, byte[] src) {
		try {
			FileOutputStream out = new FileOutputStream(new File(fileName));
			out.write(src);
		} catch (Exception e) {
			// TODO: handle exception
			return -1;
		}
		return 0;
	}

	public static int testGenkeyDer() {
		byte[] prikeyder1 = Sm2CryptoClsDer.getInstance()
				.GenerateSm2PrikeyDer();
		byte[] prikeyder2 = Sm2CryptoClsDer.getInstance().GenerateSm2PrikeyDer(
				"helloworld!".getBytes());
		write("prikeyder1.txt", prikeyder1);
		write("prikeyder2.txt", prikeyder2);
		byte[] pubkeyDer1 = Sm2CryptoClsDer.getInstance()
				.GetSm2PublicKeyDerFromPrivateKeyDer(prikeyder1);
		byte[] pubkeyDer2 = Sm2CryptoClsDer.getInstance()
				.GetSm2PublicKeyDerFromPrivateKeyDer(prikeyder2);
		write("pubkeyDer1.txt", pubkeyDer1);
		write("pubkeyDer2.txt", pubkeyDer2);
		return 0;
	}

	public static int testSignatureAndVerifyDer(String msg) {
		byte[] prikeyder1 = Sm2CryptoClsDer.getInstance()
				.GenerateSm2PrikeyDer();
		byte[] signatureder = Sm2CryptoClsDer.getInstance()
				.SignBySm2PrivatekeyDer(msg.getBytes(), prikeyder1);
		write("signData.txt", signatureder);
		byte[] pubkeyDer1 = Sm2CryptoClsDer.getInstance()
				.GetSm2PublicKeyDerFromPrivateKeyDer(prikeyder1);
		int ret = Sm2CryptoClsDer.getInstance()
				.VerifySm2SignatureDerByPubKeyDer(pubkeyDer1, signatureder,
						msg.getBytes());
		CheckRet(ret, "self sign and verify ok..");
		String sm2Certba64strString = "MIIBgTCCASegAwIBAgIDE/AmMAoGCCqBHM9VAYN1MDkxCzAJBgNVBAYTAkNOMSowKAYDVQQDDCHnp7vliqjkupLogZTnvZHlronlhajmnI3liqHlubPlj7AwHhcNMTMwMjE5MDkyOTA5WhcNMTQwMjE5MDkyOTA5WjAoMQswCQYDVQQGEwJDTjEZMBcGA1UEAwwQMTExMUAxMzg1NjU2NTY1NjBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABHdixSrSwdwBDQWPF00xTagX7AmnDHJNfK73mgg+Mlc+xzNLT2/Cw7Uj88vorW8bQS5jZ5QUogcnfAGM2CYkGlyjLzAtMAsGA1UdDwQEAwIE8DATBgNVHSUEDDAKBggrBgEFBQcDATAJBgNVHRMEAjAAMAoGCCqBHM9VAYN1A0gAMEUCIQDCuQrfwpupmH2qHbsPyJYD9NU/zQbe+D4fif6EczRigAIgV/Gxqcw9rNhhdYVPn6Rc3W+kFfI69/qXeL/n0CM6EyU=";
		String signatureBa64Str = "HBMBRrgQGp+f4728Yn3HYTeEd4zAyjJG8uig93DKL/6omfqxhS94d3GASgWJ78pJa7hzAQdzs01dYLxW5cLRQQ==";
		String srcStr = "12344600012916391342013021810230215354T1254";
		// ret =
		// Sm2CryptoClsDer.getInstance().VerifySm2SignatureDerByCert(Base64.decode(sm2Certba64strString),
		// Base64.decode(signatureBa64Str) , srcStr.getBytes());
		byte[] pubkey = Sm2CryptoClsDer.getInstance().GetPublicKeyFromSm2Cert(
				Base64.decode(sm2Certba64strString));
		// ret =
		// Sm2CryptoClsDer.getInstance().VerifySm2SignatureByCert(Base64.decode(sm2Certba64strString),
		// Base64.decode(signatureBa64Str) , srcStr.getBytes());
		ret = Sm2CryptoClsDer.getInstance().VerifySm2SignatureByPubKey(pubkey,
				Base64.decode(signatureBa64Str), srcStr.getBytes());
		CheckRet(ret, "outer verify ok..");
		return 0;
	}

	public static int testVerifyBySm2Cert() {
		byte[] src = "1234567460036811933213wA9IiZlqjq1CYWDHwdFlnbec1mOiZ+bT1254ab"
				.getBytes();
		byte[] sig = Base64
				.decode("V996Imbz5jgRz+706mbJe9RbKmjrAsHvz9m26WGCBp8qEr23vqZwg5yuNqg8BdhOMHgeLWPoLEaGgyGKhb1skg==");
		byte[] sm2Cert = Base64
				.decode("MIIBfDCCASOgAwIBAgIDD7ByMAoGCCqBHM9VAYN1MDkxCzAJBgNVBAYTAkNOMSowKAYDVQQDDCHnp7vliqjkupLogZTnvZHlronlhajmnI3liqHlubPlj7AwHhcNMTMwMjI4MDEwNjQyWhcNMTQwMjI4MDEwNjQyWjAkMQswCQYDVQQGEwJDTjEVMBMGA1UEAwwMMTIzNDU2N0BURVNUMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAExOV2HpfHnexZzGKexyn8jZy5FyBPhqibM/FwfapUWMAlnzEndQTtzHRcRj+/udRuWNCiHUnC2YTSWdwt8OB04qMvMC0wCwYDVR0PBAQDAgTwMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAkGA1UdEwQCMAAwCgYIKoEcz1UBg3UDRwAwRAIgJrR1N3bfX5gKGY4Fge0Wrkcc95/Agm9/KiWql71o50QCIHzuFQ4uvI2hgR4qEUJGV9UPY/u/NDopoo3F84vMS+lF");
		for (int i = 0; i < 1000; i++) {
			int ret = Sm2CryptoCls.getInstance().VerifySm2SignatureByCert(
					sm2Cert, sig, "hello".getBytes());
			if (ret != 0) {
				System.out.println("test f ok..ret:" + ret);
			}

			ret = Sm2CryptoCls.getInstance().VerifySm2SignatureByCert(sm2Cert,
					sig, src);
			System.out.println("contNum:" + i);
			CheckRet(ret, "verify sm2 signature ok...");
		}
		return 0;

	}
	
	
	public static int testEncryptAndDecryptSM2Der()
	{
		byte [] src = "helloworld".getBytes();
		byte[] prikeyder1 = Sm2CryptoClsDer.getInstance()
				.GenerateSm2PrikeyDer();
		byte[] pubkeyDer1 = Sm2CryptoClsDer.getInstance()
				.GetSm2PublicKeyDerFromPrivateKeyDer(prikeyder1);
		
		byte [] encData = Sm2CryptoClsDer.getInstance().EncryptBySm2PublicKeyDer(src, pubkeyDer1);
		if(null != encData)
		{
			write("sm2cipher_output.asn1", encData);
			return 1;
		}
		else {
			return 0;
		}
	}

	public static int randGenT() {
		int len = 1024;
		int ret = 0;
		for (int i = 0; i < 1024; i++) {
			CheckRet(ret, "group" + i + "test..");
			ret = Sm2CryptoCls.getInstance().RandGenTest("./randfile1234.txt",
					len);
		}

		CheckRet(ret, "genRandTest Ok..");
		return 0;
	}
}

/**
 * 
 * @description efficiency test and call routine
 * @version 1.0
 * @author simonPang
 * @update 2012-9-25 ÏÂÎç5:55:36
 */
public class maintest {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		// normalTestCls.testDer();
		normalTestCls.testEncryptAndDecryptSM2Der();
		//
		String ver = Sm2CryptoCls.getInstance().getLibVersion();
		System.out.println(ver);
		System.out.println(System.getProperty("java.library.path"));
		System.setProperty("java.library.path", ".");

		//
		// normalTestCls.randGenT();
		// normalTestCls.testGenkeyDer();
		// normalTestCls.testSignatureAndVerifyDer("helloworld!");

		//normalTestCls.testVerifyBySm2Cert();

		boolean trigger = false;

		long timeStart = 0;
		long timeEnd = 0;
		long timeSpend = 0;

		if (trigger) {
			timeStart = System.currentTimeMillis();
			normalTestCls.testEfficiency();
			timeEnd = System.currentTimeMillis();
			timeSpend = timeEnd - timeStart;
			System.out.println("1.the whole time spended by single-thread:"
					+ timeSpend + " millis...\n");
		}

		timeStart = System.currentTimeMillis();
		new MultiThreadTest("A ").start(); 
		// new MultiThreadTest("B ").start();
		// new MultiThreadTest("C ").start(); timeEnd =
		System.currentTimeMillis();
		timeSpend = timeEnd - timeStart; //
		System.out.println("2.the whole time spended by multi-thread:"
				+ timeSpend + " millis...\n"); 
		// testCrypto(); String srcString
												
		// = "helloworld!";

	}

}