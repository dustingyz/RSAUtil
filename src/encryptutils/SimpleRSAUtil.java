package encryptutils;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.Arrays;

import encryptutils.RSAUtil;

public class SimpleRSAUtil {

	/**
	 * 需要加密的内容的字节组，字符串请使用utf-8
	 * @param data
	 * @return
	 * @throws Exception
	 */
	public static String encrypt(byte[] data) throws Exception {
		RSAPublicKey rsaPublicKey = RSAUtil.loadPublicKeyFromFile();
		byte[] encryptOrDecrypt = RSAUtil.encrypt(rsaPublicKey, data);
		String encryptBase64 = RSAUtil.encryptBase64(encryptOrDecrypt);
		return encryptBase64;
	}
	
	/**
	 * 字符串加密，使用utf-8编码
	 * @param data
	 * @return
	 * @throws Exception
	 */
	public static String encrypt(String data) throws Exception {
		
		String encrypt = encrypt(data.getBytes("utf-8"));
		return encrypt;
	}
	
	/**
	 * 解密成字节序列
	 * @param data
	 * @return
	 * @throws Exception
	 */
	public static byte[] decrypt(String data) throws Exception {
		
		RSAPrivateKey loadPrivateKeyFromFile = RSAUtil.loadPrivateKeyFromFile();
		byte[] decryptBase64 = RSAUtil.decryptBase64(data);
		byte[] decrypt = RSAUtil.decrypt(loadPrivateKeyFromFile, decryptBase64);
		return decrypt;
		
	}
	
	/**
	 * 解密成字符串，使用utf-8对解密的字节编码
	 * @param data
	 * @return
	 * @throws Exception
	 */
	public static String decryptToString(String data) throws Exception {
		
		byte[] decrypt = decrypt(data);
		String result = new String(decrypt, "utf-8");
		return result;
	}
	
	/**
	 * 获取文件摘要
	 * @param file
	 * @param callback
	 * @throws IOException
	 */
	public static void generateFileDigest(File file, ICallback callback) throws IOException {
		
		Runnable callable = new Runnable() {

			@Override
			public void run() {
				String fileMessageDigest;
				try {
					System.out.println("execute in " + Thread.currentThread().getName() + " ...");
					fileMessageDigest = RSAUtil.generateFileMessageDigestSHA(file);
					callback.callback(fileMessageDigest);
				} catch (IOException e) {
					e.printStackTrace();
					callback.error();
				}
			}
			
		};
		
		ExecutorService executor = Executors.newSingleThreadExecutor();
		
		executor.submit(callable);
		
		new Thread(new Runnable() {
			
			@Override
			public void run() {
				try {
					while(executor.awaitTermination(60, TimeUnit.SECONDS)) {
						executor.shutdownNow();
					}
				} catch (InterruptedException e) {
					executor.shutdownNow();
				}
			}
		}).start();
		
		executor.shutdown();
	}
	
	public static interface ICallback{
		
		void callback(String data);
		
		void error();
	}
	
	public static int encryptLength = 8192;
	public static int decryptLength = encryptLength + 16;
	
	public static void fileEncrypt(File file, byte[] ivBytesPassword) throws Exception {
		FileInputStream fis = new FileInputStream(file);
		BufferedInputStream bis = new BufferedInputStream(fis);
		byte[] bytes = new byte[encryptLength];
		int read = bis.read(bytes);
		if (ivBytesPassword == null || ivBytesPassword.length < 16) {
			bis.close();
			fis.close();
			throw new RuntimeException("ivBytes need as least 16 bit length");
		}
		byte[] ivBytes = null;
		if (ivBytesPassword.length > 16) {
			ivBytes = Arrays.copyOfRange(ivBytesPassword, 0, 16);
		}else {
			ivBytes = ivBytesPassword;
		}
		IvParameterSpec ivParams = RSAUtil.getIvParams(ivBytes);
		SecretKeySpec keySpec = RSAUtil.loadAESKeyFromFile();
		
		FileOutputStream fos = new FileOutputStream(new File(file.getAbsolutePath() + ".enc"));
		BufferedOutputStream bos = new BufferedOutputStream(fos);
		
		while(read != -1) {
			byte[] copyBytes = Arrays.copyOfRange(bytes, 0, read);
//			byte[] decryptAES = RSAUtil.decryptAES(keySpec, copyBytes, ivParams);
			byte[] encryptAES = RSAUtil.encryptAES(keySpec, copyBytes, ivParams);
			bos.write(encryptAES);
			read = bis.read(bytes);
		}
		
		fos.flush();
		bos.flush();
		fos.close();
		bos.close();
		
		bis.close();
		fis.close();
		if (file.exists()) {
			file.delete();
		}
	}
	
	public static void fileDecrypt(File file, byte[] ivBytesPassword) throws Exception {
		FileInputStream fis = new FileInputStream(file);
		BufferedInputStream bis = new BufferedInputStream(fis);
		byte[] bytes = new byte[decryptLength];
		int read = bis.read(bytes);
		if (ivBytesPassword == null || ivBytesPassword.length < 16) {
			bis.close();
			fis.close();
			throw new RuntimeException("ivBytes need as least 16 bit length");
		}
		byte[] ivBytes = null;
		if (ivBytesPassword.length > 16) {
			ivBytes = Arrays.copyOfRange(ivBytesPassword, 0, 16);
		}else {
			ivBytes = ivBytesPassword;
		}
		IvParameterSpec ivParams = RSAUtil.getIvParams(ivBytes);
		SecretKeySpec keySpec = RSAUtil.loadAESKeyFromFile();
		String absolutePath = file.getAbsolutePath();
		String replaceAll = absolutePath.replaceAll(".enc$", "");
		FileOutputStream fos = new FileOutputStream(new File(replaceAll));
		BufferedOutputStream bos = new BufferedOutputStream(fos);
		
		while(read != -1) {
			byte[] copyBytes = Arrays.copyOfRange(bytes, 0, read);
			byte[] decryptAES = RSAUtil.decryptAES(keySpec, copyBytes, ivParams);
			bos.write(decryptAES);
			read = bis.read(bytes);
		}
		
		fos.flush();
		bos.flush();
		fos.close();
		bos.close();
		
		bis.close();
		fis.close();
		
		if (file.exists()) {
			file.delete();
		}
	}
}
