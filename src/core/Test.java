package core;

import java.io.File;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;

import encryptutils.RSAUtil;

public class Test {
	public static void main(String[] args) {
		
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
			
			//计算出HexBinary摘要
			String context = RSAUtil.generateMessageDigestSHA(data);
			System.out.println("context string : "+ context);
			
			//加签
			String addSign = RSAUtil.addSign(privateKey, context);
			
			//验签
			boolean verifySign = RSAUtil.verifySign(publicKey, context, addSign);
			if (verifySign) {
				System.out.println("验签成功");
			}else {
				System.out.println("验签失败");				
			}
			
			/////////////////////////////////////////////////////////////////
			
			File file = new File("data/test.txt");
			if(file.exists()) {
				System.out.println("=====准备计时=====");
				long start = System.currentTimeMillis();
				String generateFileMessageDigestSHA = RSAUtil.generateFileMessageDigestSHA(file);
				long cost = System.currentTimeMillis() - start;
				float time = (cost / 1000f);
				System.out.println("共计用时 ： " + time + "秒");
				System.out.println("文件大小 ： " + file.length());
				System.out.println(file.getName() + " 文件摘要（SHA）： "+ generateFileMessageDigestSHA);
			}
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
