package core;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import encryptutils.RSAUtil;

public class Test {
	public static void main(String[] args) {

//		KeyPair generateKeyPair = RSAUtil.generateKeyPair();
//		try {
//			RSAUtil.keyToFile(generateKeyPair);
//		} catch (IOException e) {
//			e.printStackTrace();
//		}
		
		try {
			
			
			RSAPublicKey publicKey = RSAUtil.loadPublicKeyFromFile();
			System.out.println("===== Public Key is =====\n"+publicKey);
			
			RSAPrivateKey privateKey = RSAUtil.loadPrivateKeyFromFile();
			System.out.println("===== Private Key is =====\n" + privateKey);
			
			String data = "加密专用的明文";
			byte[] decryptData = RSAUtil.encryptOrDecrypt(publicKey, data.getBytes("utf-8"), Cipher.ENCRYPT_MODE);
			
			String encryptBase64Data = RSAUtil.encryptBase64(decryptData);
			System.out.println("===== Data after encrypt =====\n" + encryptBase64Data);
			
			
			/*
			 * 解密
			 */
			byte[] decryptBase64 = RSAUtil.decryptBase64(encryptBase64Data);
			byte[] deccryptData = RSAUtil.encryptOrDecrypt(privateKey, decryptBase64, Cipher.DECRYPT_MODE);
			
			System.out.println("===== Data after decrypt =====\n" + new String(deccryptData,"utf-8"));
			
			//////////////////////////////////////////////////////////////
			
			String context = RSAUtil.generateMessageDigsetSHA(data);
			System.out.println("context string : "+ context);
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

	public static void main1(String[] args) {
		try {
			/*
			 * ��ȡ����Կ��
			 */
			KeyPairGenerator instance = KeyPairGenerator.getInstance("RSA");
			instance.initialize(1024);
			KeyPair genKeyPair = instance.genKeyPair();
			System.out.println("Public Key : ");
			System.out.println(genKeyPair.getPublic());
			System.out.println("Private Key : ");
			System.out.println(genKeyPair.getPrivate());

			String encryptBase64 = RSAUtil.encryptBase64(genKeyPair.getPublic().getEncoded());
			System.out.println(
					"\n\n================================\n" + encryptBase64 + "\n\n================================");
			byte[] decryptBase64 = RSAUtil.decryptBase64(encryptBase64);
			System.out.println("\n\n============byte================\n" + String.valueOf(decryptBase64)
					+ "\n\n================================");
			/*
			 * �õ�Public Key
			 */
			PublicKey publicKey = genKeyPair.getPublic();
			PrivateKey privateKey = genKeyPair.getPrivate();
			byte[] bytes = publicKey.getEncoded();
			byte[] bytes2 = privateKey.getEncoded();
			System.out.println(String.valueOf(bytes));
			System.out.println(String.valueOf(bytes2));

			/*
			 * 
			 */
			// new X509EncodedKeySpec(publicKey)

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
}
