package encryptutils;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Array;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
//import java.util.Base64;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class RSAUtil {

	private static final String RSA = "RSA";
	private static final String UTF_8 = "utf-8";
	
	private static final String publicPath = "data\\pub.pem";
	private static final String privatePath = "data\\pri.pem";
	
	public static String encryptBase64(byte[] key) {
		String encodeKey = Base64.encodeBase64String(key);
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
	
	
	
	public static String generateMessageDigsetSHA(byte[] data) throws Exception {
		
		MessageDigest digest = MessageDigest.getInstance("SHA");
		digest.update(data);//.getBytes(UTF_8));
		byte[] digestEncode = digest.digest();
		
//		String printHexBinary = DatatypeConverter.printHexBinary(digestEncode);
//		byte[] parseHexBinary = DatatypeConverter.parseHexBinary(printHexBinary);
//		System.out.println(digestEncode.equals(parseHexBinary));
//		System.out.println(printHexBinary);
//		System.out.println(digestEncode.length == parseHexBinary.length);
//		for (int i = 0; i < parseHexBinary.length; i++) {
//			byte b = parseHexBinary[i];
//			byte c = digestEncode[i];
//			System.out.println(b == c);
//		}
		
//		String base64String = Base64.encodeBase64URLSafeString(digestEncode);
		String hexBinary = DatatypeConverter.printHexBinary(digestEncode);
		return hexBinary;
	}
	
	public static String generateMessageDigsetSHA(String data) throws Exception {
		return generateMessageDigsetSHA(data.getBytes(UTF_8));
	}

}
