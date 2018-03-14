package core;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import encryptutils.RSAUtil;
import encryptutils.SimpleRSAUtil;
import encryptutils.SimpleRSAUtil.ICallback;

public class Test {

	static boolean onResult = false;
	
	public static void main(String[] args) {
		File file = new File("data/test_file.docx.enc");
//		File file = new File("data/test_file.docx");
//		File file = new File("data/test.txt");
		if (file.exists()) {
			
			try {
				int read_ = 8192;
				int decrypt = read_ + 16;
				FileInputStream fis = new FileInputStream(file);
				BufferedInputStream bis = new BufferedInputStream(fis);
//				byte[] bytes = new byte[read_];
				byte[] bytes = new byte[decrypt];
				System.out.println("byte length = " + bytes.length + ", str length = " + new String(bytes).length());
				
				int read = bis.read(bytes);
				System.out.println("read = " + read + ", byte length = " + bytes.length);
				
//				System.out.println("asdf1234qwer4532 's length = " + "asdf1234qwer4532".getBytes().length);
				
				IvParameterSpec ivParams = RSAUtil.getIvParams("asdf1234qwer4532".getBytes());
				SecretKeySpec keySpec = RSAUtil.loadAESKeyFromFile();
				
				FileOutputStream fos = new FileOutputStream(new File(file.getAbsolutePath() + ".ori"));
				BufferedOutputStream bos = new BufferedOutputStream(fos);
				
				while(read != -1) {
					byte[] copyBytes = Arrays.copyOfRange(bytes, 0, read);
					byte[] decryptAES = RSAUtil.decryptAES(keySpec, copyBytes, ivParams);
//					byte[] encryptAES = RSAUtil.encryptAES(keySpec, copyBytes, ivParams);
					bos.write(decryptAES);
//					bos.write(encryptAES);
					read = bis.read(bytes);
				}
				
				fos.flush();
				bos.flush();
				fos.close();
				bos.close();
				
				bis.close();
				fis.close();
				
				System.out.println("\nclose!");
//				System.out.println(new String(encryptAES) + ",\n encrypt lenght = " + encryptAES.length);
				
//				byte[] decryptAES = RSAUtil.decryptAES(keySpec, encryptAES, ivParams);
				
//				System.out.println(new String(decryptAES));
				
				
			} catch (Exception e) {
				e.printStackTrace();
			}
			
		}
	}

	public static void main2(String[] args) {

		try {

			RSAPublicKey publicKey = RSAUtil.loadPublicKeyFromFile();
			System.out.println("===== Public Key is =====\n" + publicKey);

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

			System.out.println("===== Data after decrypt =====\n" + new String(deccryptData, "utf-8"));

			//////////////////////////////////////////////////////////////

			// 计算出HexBinary摘要
			String context = RSAUtil.generateMessageDigestSHA(data);
			System.out.println("context string : " + context);

			// 加签
			String addSign = RSAUtil.addSign(privateKey, context);

			// 验签
			boolean verifySign = RSAUtil.verifySign(publicKey, context, addSign);
			if (verifySign) {
				System.out.println("验签成功");
			} else {
				System.out.println("验签失败");
			}

			/////////////////////////////////////////////////////////////////

			File file = new File("data/test.txt");
			if (file.exists()) {
				System.out.println("=====准备计时=====");
				long start = System.currentTimeMillis();
				String generateFileMessageDigestSHA = RSAUtil.generateFileMessageDigestSHA(file);
				long cost = System.currentTimeMillis() - start;
				float time = (cost / 1000f);
				System.out.println("共计用时 ： " + time + "秒");
				System.out.println("文件大小 ： " + file.length());
				System.out.println(file.getName() + " 文件摘要（SHA）： " + generateFileMessageDigestSHA);
			}

			/////////////////////////////////////////////////////////////////

			File file2 = new File("data/app.apk");
			SimpleRSAUtil.generateFileDigest(file2, new ICallback() {

				@Override
				public void error() {
					System.out.println("error");
					onResult = true;
				}

				@Override
				public void callback(String data) {
					System.out.println("异步文件摘要（SHA）：" + data);
					onResult = true;
				}
			});
			long time = System.currentTimeMillis();
			long time_start = time;
			System.out.println("time :" + time);
			while (!onResult) {
				long time_now = System.currentTimeMillis();
				if (time_now - time > 1000) {
					time = time_now;
					if (!onResult) {						
						System.out.println("running in " + Thread.currentThread().getName() + " ...");
					}
				}
				if(time_now - time_start > 120000) {
					onResult = true;
					System.out.println("shutdown!");
				}
			}
			
//			SecretKey generateAESKey = RSAUtil.generateAESKey();
//			String aesKey64 = RSAUtil.encryptBase64(generateAESKey.getEncoded());
//			System.out.println("aes key = " + aesKey64);
//			RSAUtil.ketToFile(generateAESKey);
				
			SecretKeySpec loadAESKeyFromFile = RSAUtil.loadAESKeyFromFile();
			System.out.println("AES Key(Base64) : " + RSAUtil.encryptBase64(loadAESKeyFromFile.getEncoded()));
			System.out.println(loadAESKeyFromFile);
			
			byte[] generateAESIvParamsBytes = RSAUtil.generateAESIvParamsBytes();
			String encryptBase64Iv = RSAUtil.encryptBase64(generateAESIvParamsBytes);
			System.out.println("加密用Iv bytes(Base64) ： " + encryptBase64Iv);
			IvParameterSpec ivParamsEn = RSAUtil.getIvParams(generateAESIvParamsBytes);
			
			byte[] decryptBase64Iv = RSAUtil.decryptBase64(encryptBase64Iv);
			IvParameterSpec ivParamsDe = RSAUtil.getIvParams(decryptBase64Iv);
			
			String aesText = "AES 加密用明文";
			byte[] encryptAES = RSAUtil.encryptAES(loadAESKeyFromFile, aesText, ivParamsEn);
			String encryptBase64 = RSAUtil.encryptBase64(encryptAES);
			System.out.println("AES明文加密后： " + encryptBase64);
			byte[] decryptBase64AES = RSAUtil.decryptBase64(encryptBase64);
			byte[] decryptAES = RSAUtil.decryptAES(loadAESKeyFromFile, decryptBase64AES, ivParamsDe);
			String aesDecryptText = new String(decryptAES, "utf-8");
			
			System.out.println("AES密文解密后： " + aesDecryptText);			
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
