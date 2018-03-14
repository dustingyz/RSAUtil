package core;

import java.io.File;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import encryptutils.SimpleRSAUtil;

public class FileEncrypt {

	private static ThreadPoolExecutor executor;
	private static byte[] password;

	public static void main(String[] args) {
//		String a = "asda.encsd.a.enc";
//		String replaceAll = a.replaceAll(".enc$", "");
//		System.out.println(replaceAll);
		
		/*
		 * 危险，会向下加密所有文件
		 */
		File file = new File(".");
//		
//		byte[] ivBytesPassword = "passworddesuyooo".getBytes();
//		try {
//			
//			SimpleRSAUtil.fileDecrypt(file, ivBytesPassword);
//			
//		} catch (Exception e) {
//			e.printStackTrace();
//		}
//				
		System.out.println("start");
		executor = new ThreadPoolExecutor(8,16,60,TimeUnit.SECONDS, new LinkedBlockingQueue<>());
		password = "passworddesuyooo".getBytes();
		processFileDecrypt(file);
		System.out.println("run");
	}
	
	public static void processFile(File file) {
		if(file.exists()) {
			if (file.isFile()) {
//				System.out.println("file");
				FileEncryptTask fileEncryptTask = new FileEncryptTask(file, password);
//				System.out.println("enc");
				executor.execute(fileEncryptTask);
			} else if (file.isDirectory()) {
				processDir(file);
			}
		}
	}
	
	public static void processDir(File file) {
		if (file.exists() && file.isDirectory()) {
//			System.out.println("get sub file");
			File[] listFiles = file.listFiles();
			for (File f : listFiles) {
				if (f.exists()) {
					if (f.isFile()) {
						processFile(f);
					}else if (f.isDirectory()) {
						processDir(f);
					}
				}
			}
		}
	}
	
	public static void processFileDecrypt(File file) {
		if(file.exists()) {
			if (file.isFile()) {
//				System.out.println("file");
				FileDecryptTask fileDecryptTask = new FileDecryptTask(file, password);
//				System.out.println("enc");
				executor.execute(fileDecryptTask);
			} else if (file.isDirectory()) {
				processDirDecrypt(file);
			}
		}
	}
	
	public static void processDirDecrypt(File file) {
		if (file.exists() && file.isDirectory()) {
//			System.out.println("get sub file");
			File[] listFiles = file.listFiles();
			for (File f : listFiles) {
				if (f.exists()) {
					if (f.isFile()) {
						processFileDecrypt(f);
					}else if (f.isDirectory()) {
						processDirDecrypt(f);
					}
				}
			}
		}
	}
	
	static class FileEncryptTask implements Runnable{

		private File file;
		private byte[] password;

		public FileEncryptTask(File file, byte[] password) {
			this.file = file;
			this.password = password;
		}
		
		@Override
		public void run() {
			
			String name = file.getName();
			
			if (file.exists() && file.isFile() 
					&& !name.endsWith(".jar")
					&& !name.endsWith(".enc")
					&& !name.endsWith(".pem")
					&& !name.endsWith(".key")) {
				try {
					SimpleRSAUtil.fileEncrypt(file, password);
				} catch (Exception e) {
					e.printStackTrace();
					executor.shutdown();
				}
			}
		}
		
	}
	
	static class FileDecryptTask implements Runnable{

		private File file;
		private byte[] password;
		
		public FileDecryptTask(File file, byte[] password) {
			this.file = file;
			this.password = password;
		}
		
		@Override
		public void run() {
			
			if (file.exists() && file.isFile() && file.getAbsolutePath().endsWith(".enc")) {
				
				try {
					SimpleRSAUtil.fileDecrypt(file, password);
				} catch (Exception e) {
					e.printStackTrace();
					executor.shutdown();
				}
			}
		}
		
	}
}
