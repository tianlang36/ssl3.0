package cn.rdtimes.tls.util;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.io.Closeable;

/**
 * 有关证书操作的工具类
 * 
 * @author BZ
 * Date: 2015-09-17
 */

public final class EapTLSCertUtil {
	/**
	 * 数字签名的通用算法
	 */
	public static String SIGNATURE_ALG_SHA1RSA = "SHA1withRSA"; 
	public static String SIGNATURE_ALG_MD5RSA = "MD5withRSA"; 
	
	/**
	 * 通过证书文件获得x509
	 * @param certFileName 证书文件名称
	 * @return
	 */
	public static X509Certificate getX509CertificateFromFile(String certFileName) {
		InputStream input = null;
		try {
			input = new FileInputStream(certFileName);
			CertificateFactory factory = CertificateFactory.getInstance("X.509");
			X509Certificate cert = (X509Certificate)factory.generateCertificate(input);
			return cert;
		} catch (Exception e) {
			e.printStackTrace();
			
			return null;
		}
		finally {
			closeStream(input);
		}
	}
	
	/**
	 * 从keystore中获取证书
	 * @param keystore 库的文件名称
	 * @param keystorePwd 库的密码
	 * @param alias 证书的别名
	 * @return
	 */
	public static X509Certificate getX509CertificateFromKeyStore(String keystore,String keystorePwd,String alias) {
		InputStream input = null;
		try {
			input = new FileInputStream(keystore);
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(input,keystorePwd.toCharArray());
			X509Certificate cert = (X509Certificate)ks.getCertificate(alias);
			return cert;
		} catch (Exception e) {
			e.printStackTrace();
			
			return null;
		}
		finally {
			closeStream(input);
		}
	}
	
	/**
	 * 从证书文件中读取证书到字节数组中
	 * @param certFileName 证书文件名称
	 * @return
	 */
	public static byte[] getX509CertificateBytes(String certFileName) {
		InputStream input = null;
		try {
			input = new FileInputStream(certFileName);
			
			byte[] buff = new byte[input.available()];
			input.read(buff);
			
			return buff;
		} catch (Exception e) {
			e.printStackTrace();
			
			return null;
		}
		finally {
			closeStream(input);
		}
	}
	
	/**
	 * 从keystore中获取私钥
	 * @param keystore 库文件名称
	 * @param keystorePwd 库密码
	 * @param alias 证书别名
	 * @param privatekeyPwd 私钥密码
	 * @return
	 */
	public static PrivateKey getPriveKeyFromKeyStore(String keystore,String keystorePwd,
													 String alias,String privatekeyPwd) {
		InputStream input = null;
		try {
			input = new FileInputStream(keystore);
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(input,keystorePwd.toCharArray());
			
			return (PrivateKey)ks.getKey(alias, privatekeyPwd.toCharArray());
		} catch (Exception e) {
			e.printStackTrace();
			
			return null;
		}
		finally {
			closeStream(input);
		}
	}
	
	/**
	 * 通过证书验证签名
	 * @param alg 签名算法("SHA1WithRSA")
	 * @param cert 证书
	 * @param msg 消息
	 * @param signature 本验证的签名
	 * @return
	 */
	public static boolean verifySignature(String alg, X509Certificate cert, byte[] msg, byte[] signature) {
		try {
			Signature sign = Signature.getInstance(alg);
			sign.initVerify(cert);
			sign.update(msg);
			return sign.verify(signature);
		}catch(Exception e) {
			return false;
		}
	}
	
	/**
	 * 生成一个数字签名
	 * @param alg 签名算法("SHA1WithRSA")
	 * @param pk 私钥
	 * @param msg 消息
	 * @return
	 */
	public static byte[] getSignatureByPrivateKey(String alg, PrivateKey pk, byte[] msg) {
		try {
			Signature sign = Signature.getInstance(alg);
			sign.initSign(pk);
			sign.update(msg);
			return sign.sign();
		}catch(Exception e) {
			return null;
		}
	}
	
	public static void printX509Certificate(X509Certificate cert) {
		if (cert == null) return;
		
		System.out.println("SerialNumber:" + cert.getSerialNumber().toString(16));
		System.out.println("NotBefore:" + cert.getNotBefore().toString());
		System.out.println("NotAfter:" + cert.getNotAfter().toString());
		System.out.println("SigAlg:" + cert.getSigAlgName());
		System.out.println("Algorithm:" + cert.getPublicKey().getAlgorithm());
		System.out.println("IssuerDN:" + cert.getIssuerDN().getName());
		System.out.println("SubjectDN:" + cert.getSubjectDN().toString());
	}
	
	private static void closeStream(final Closeable stream) {
		try {
			if (stream != null) stream.close();
		} catch(Exception e) {}
	}
	
}
