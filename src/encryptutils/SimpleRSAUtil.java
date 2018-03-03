package encryptutils;

import java.io.File;
import java.io.IOException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.Callable;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;
import javax.security.auth.callback.Callback;

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
		
		executor.shutdown();
		
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
		
	}
	
	public static interface ICallback{
		
		void callback(String data);
		
		void error();
	}
}
