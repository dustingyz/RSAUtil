package encryptutils;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.DigestInputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
//import java.util.Base64;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class RSAUtil {

	private static final String AES = "AES";
	private static final String RSA = "RSA";
	private static final String UTF_8 = "utf-8";
	
	private static final String publicPath = "data\\pub.pem";
	private static final String privatePath = "data\\pri.pem";
	private static final String secretkeyPath = "data\\aes.key";
	
	public static String encryptBase64(byte[] key) {
		String encodeKey = Base64.encodeBase64URLSafeString(key);
//		String encodeKey = Base64.getEncoder().encodeToString(key);
		return encodeKey;
	}

	public static byte[] decryptBase64(String key) {
		byte[] keyBytes = Base64.decodeBase64(key);
//		byte[] keyBytes = Base64.getDecoder().decode(key);
		return keyBytes;
	}

	public static KeyPair generateKeyPair(){
		return generateKeyPair(2048);
	}
	
	private static BouncyCastleProvider bouncyCastleProvider = null;
	
	private static BouncyCastleProvider getProvider() {
		if (bouncyCastleProvider == null) {
			synchronized(RSAUtil.class) {
				if (bouncyCastleProvider == null) {
					bouncyCastleProvider = new BouncyCastleProvider();
				}
			}
		}
		return bouncyCastleProvider;
	}

	/**
	 * RSA key pair 生成
	 * @param keySize key 的长度
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static KeyPair generateKeyPair(int keySize){
		KeyPairGenerator keyPairGenerator;
		try {
			keyPairGenerator = KeyPairGenerator.getInstance(RSA);
			keyPairGenerator.initialize(keySize);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			return keyPair;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
	}
	
	/**
	 * Save Key Pair as xxx.pem files.
	 * @param keyPair
	 * @throws IOException
	 */
	public synchronized static void keyToFile(KeyPair keyPair) throws IOException {
		File publicFile = new File(publicPath);
		File privateFile = new File(privatePath);
		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();
		String publicKeyStr = encryptBase64(publicKey.getEncoded());
		String privateKetStr = encryptBase64(privateKey.getEncoded());
		FileWriter fileWriter = new FileWriter(publicFile);
		fileWriter.write(publicKeyStr);
		fileWriter.flush();
		fileWriter.close();
		fileWriter = new FileWriter(privateFile);
		fileWriter.write(privateKetStr);
		fileWriter.flush();
		fileWriter.close();
	}
	
	public static RSAPublicKey loadPublicKeyFromFile() throws IOException, InvalidKeySpecException {
		
		FileInputStream fis = new FileInputStream(new File(publicPath));
		BufferedReader br = new BufferedReader(new InputStreamReader(fis));
		StringBuffer sb = new StringBuffer(1024);
		String line = null;
		
		while((line = br.readLine()) != null) {
			sb.append(line);
		}
		br.close();
		
		String publicKey = sb.toString();
		byte[] publicKeyBytes = decryptBase64(publicKey);
		X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(publicKeyBytes);
		
		try {
			KeyFactory factory = KeyFactory.getInstance(RSA);
			RSAPublicKey generatePublic = (RSAPublicKey) factory.generatePublic(encodedKeySpec);
			return generatePublic;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		} finally {
			fis.close();
			br.close();
		}
 	}
	
	public static RSAPrivateKey loadPrivateKeyFromFile() throws IOException, InvalidKeySpecException {
		
		FileInputStream fis = new FileInputStream(new File(privatePath));
		BufferedReader br = new BufferedReader(new InputStreamReader(fis));
		StringBuffer sb = new StringBuffer(1024);
		String line = null;
		
		while((line = br.readLine()) != null) {
			sb.append(line);
		}
		br.close();
		
		String privateKey = sb.toString();
		byte[] privateKeyBytes = decryptBase64(privateKey);
		PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
		
		try {
			KeyFactory factory = KeyFactory.getInstance(RSA);
			RSAPrivateKey generatePrivate = (RSAPrivateKey) factory.generatePrivate(encodedKeySpec);
			return generatePrivate;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
 	}
	
	
	/**
	 * 公钥加密 / 私钥解密
	 * @param key
	 * @param data
	 * @param mode
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptOrDecrypt(Key key, byte[] data, int mode) throws Exception {
		
		String ENCRYPT_ALGORITHM = "RSA/ECB/PKCS1Padding";
		
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		
		BouncyCastleProvider provider = getProvider();
		Cipher cipher = Cipher.getInstance(ENCRYPT_ALGORITHM,provider);
		cipher.init(mode, key);
		int blockSize = cipher.getBlockSize();
		int length = data.length;
		int num = length / blockSize + 1;
		int cache = blockSize;
		byte[] bytes = null;
		for (int i = 0; i < num; i++) {
			if (i == num - 1) {
				cache = length % blockSize;
				if (cache == 0) {
					return out.toByteArray();
				}
			}
			bytes = cipher.doFinal(data, i * blockSize, cache);
			out.write(bytes);
		}
		return out.toByteArray();
	}
	
	
	public static byte[] encrypt(Key key, String data) throws Exception {
		
		return encryptOrDecrypt(key, data.getBytes(UTF_8), Cipher.ENCRYPT_MODE);
	}
	
	
	public static byte[] decrypt(Key key, String data) throws Exception {
		
		return encryptOrDecrypt(key, data.getBytes(UTF_8), Cipher.ENCRYPT_MODE);
	}
	
	public static byte[] encrypt(Key key, byte[] data) throws Exception {
		
		return encryptOrDecrypt(key, data, Cipher.ENCRYPT_MODE);
	}
	
	
	public static byte[] decrypt(Key key, byte[] data) throws Exception {
		
		return encryptOrDecrypt(key, data, Cipher.ENCRYPT_MODE);
	}
	
	
	/**
	 * 加签
	 * @param privateKey
	 * @param context
	 * @return
	 * @throws Exception
	 */
	public static String addSign(PrivateKey privateKey, String context) throws Exception {
		
		String SIGN_ALGORITHM = "SHA1WithRSA";
		
		Signature signature = Signature.getInstance(SIGN_ALGORITHM);
		signature.initSign(privateKey);
		signature.update(context.getBytes(UTF_8));
		byte[] sign = signature.sign();
		return encryptBase64(sign);
	}
	
	/**
	 * 验签
	 * @param publicKey
	 * @param context
	 * @param sign
	 * @return
	 * @throws Exception
	 */
	public static boolean verifySign(PublicKey publicKey, String context, String signData) throws Exception {
		
		String SIGN_ALGORITHM = "SHA1WithRSA";
		
		Signature signature = Signature.getInstance(SIGN_ALGORITHM);
		signature.initVerify(publicKey);
		byte[] decryptBase64 = decryptBase64(signData);
		signature.update(context.getBytes(UTF_8));
		boolean verify = signature.verify(decryptBase64);
		return verify;
	}
	
	
	
	public static String generateMessageDigestSHA(byte[] data) throws Exception {
		
		MessageDigest digest = MessageDigest.getInstance("SHA");
		digest.update(data);//.getBytes(UTF_8));
		byte[] digestEncode = digest.digest();		
//		String base64String = Base64.encodeBase64URLSafeString(digestEncode);
		String hexBinary = DatatypeConverter.printHexBinary(digestEncode);
		return hexBinary;
	}
	
	public static String generateMessageDigestSHA(String data) throws Exception {
		
		return generateMessageDigestSHA(data.getBytes(UTF_8));
	}
	
	/**
	 * 文件消息摘要，耗时操作
	 * @throws IOException 
	 * 
	 */
	public static String generateFileMessageDigestSHA(File file) throws IOException {
		
		FileInputStream fis = new FileInputStream(file);
		///
		BufferedInputStream bis = new BufferedInputStream(fis, 65536);
		///
		MessageDigest messageDigest;
		DigestInputStream digestInputStream = null;
		
		try {
			
			messageDigest = MessageDigest.getInstance("SHA");
			digestInputStream = new DigestInputStream(bis, messageDigest);
			//this method will then call update on the message digest associated with this stream
			while(digestInputStream.read() != -1);
			byte[] digestBytes = messageDigest.digest();
			String hexBinaryDigest = DatatypeConverter.printHexBinary(digestBytes);
			
			return hexBinaryDigest;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		} finally {
			fis.close();			
			if (digestInputStream != null) {
				digestInputStream.close();
			}
			///
			bis.close();
			///
		}
	}
	
	public static byte[] generateAESIvParamsBytes() {
		byte[] bytes = new byte[128/8];
		SecureRandom secureRandom = new SecureRandom();
		secureRandom.nextBytes(bytes);
		return bytes;
	}
	
	public static IvParameterSpec getIvParams(byte[] ivBytes) {
		IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
		return ivParameterSpec;
	}
	
	public static SecretKey generateAESKey(byte[] randomSeed) {
		try {
			KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);

			if (randomSeed == null || randomSeed.length <= 0) {				
				keyGenerator.init(128, new SecureRandom());
			}else {				
				keyGenerator.init(128, new SecureRandom(randomSeed));
			}
			SecretKey secretKey = keyGenerator.generateKey();
			return secretKey;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public static SecretKey generateAESKey() {
		return generateAESKey(null);
	}
	
	public static void ketToFile(SecretKey key) throws IOException {
		File file = new File(secretkeyPath);
		String encryptKey = encryptBase64(key.getEncoded());
		FileWriter fileWriter = new FileWriter(file);
		BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
		bufferedWriter.write(encryptKey);
		fileWriter.flush();
		bufferedWriter.close();
		fileWriter.close();
	}
	
	public static SecretKeySpec loadAESKeyFromFile() throws IOException {
		try {			
			FileInputStream fis = new FileInputStream(new File(secretkeyPath));
			BufferedInputStream bis = new BufferedInputStream(fis);
			StringBuilder sb = new StringBuilder();
			
			byte[] bytes = new byte[128];
			while(bis.read(bytes) != -1) {
				sb.append(new String(bytes, UTF_8));
			}
			String key64 = sb.toString();
			System.out.println("file key = " + key64);
			byte[] decryptBase64 = decryptBase64(key64);
			System.out.println("key length = " + decryptBase64.length + ", key = " + new String(decryptBase64, "ascii"));
			SecretKeySpec secretKeySpec = new SecretKeySpec(decryptBase64, AES);
			bis.close();
			fis.close();
			return secretKeySpec;
		}catch (FileNotFoundException e) {
			throw new RuntimeException("Key文件不存在");
		}
	}
	
	public static byte[] encryptOrDecryptAES(SecretKeySpec keySpec, byte[] bytes, int mode, IvParameterSpec ivspec) throws Exception{
			
		Cipher instance;
		try {
			instance = Cipher.getInstance("AES/CBC/PKCS5Padding");
			instance.init(mode, keySpec, ivspec);
			byte[] data = instance.doFinal(bytes);
			return data;
		} catch (NoSuchAlgorithmException e) {
			return null;
		} catch (NoSuchPaddingException e) {
			return null;
		}
	
	}
	
	public static byte[] encryptAES(SecretKeySpec keySpec, byte[] data, IvParameterSpec ivspec) throws Exception{
		return encryptOrDecryptAES(keySpec, data, Cipher.ENCRYPT_MODE, ivspec);
	}
	
	public static byte[] decryptAES(SecretKeySpec keySpec, byte[] data, IvParameterSpec ivspec) throws Exception {
		return encryptOrDecryptAES(keySpec, data, Cipher.DECRYPT_MODE, ivspec);
	}
	
	public static byte[] encryptAES(SecretKeySpec keySpec, String data, IvParameterSpec ivspec) throws Exception{
		return encryptOrDecryptAES(keySpec, data.getBytes(UTF_8), Cipher.ENCRYPT_MODE, ivspec);
	}
	
	public static byte[] decryptAES(SecretKeySpec keySpec, String data, IvParameterSpec ivspec) throws Exception {
		return encryptOrDecryptAES(keySpec, data.getBytes(UTF_8), Cipher.DECRYPT_MODE, ivspec);
	}

}
