package cn.rdtimes.tls.security;

import java.security.PrivateKey;

import javax.crypto.Cipher;

import cn.rdtimes.tls.util.EapTLSDESUtil;
import cn.rdtimes.tls.util.EapTLSUtil;

/**
 * 压缩和加解密等工具类. 
 * 
 * @author BZ Date:2015-10-20
 */
public final class EapTLSAlgorithmUtil {

	/**
	 * 根据指定的压缩算法进行解压操作
	 * 
	 * @param sk
	 * @param data
	 * @return
	 */
	public static byte[] unzip(EapTLSSecurityKey sk, byte[] data) {
		return data;
	}

	/**
	 * 根据指定的压缩算法进行压缩操作
	 * 
	 * @param sk
	 * @param data
	 * @return
	 */
	public static byte[] zip(EapTLSSecurityKey sk, byte[] data) {
		return data;
	}

	/**
	 * 根据指定的对称算法加密数据(使用服务端写秘密加密)
	 * 
	 * @param sk
	 * @param data
	 * @return
	 */
	public static byte[] encrypt(EapTLSSecurityKey sk, byte[] data) {
		if (sk.serverWriteKey == null)
			return data;

		String alg = EapTLSDESUtil.ALG_DES;
		if (sk.cipherSpec != null
				&& sk.cipherSpec.getCipherAlgorithm() == EapTLSBulkCipherAlgorithm.RC4) {
			alg = EapTLSDESUtil.ALG_RC4;
		}

		return EapTLSDESUtil.encrypt(data, sk.serverWriteKey, alg);
	}

	/**
	 * 根据指定的对称算法解密数据(使用客户端写秘密进行解密)
	 * 
	 * @param sk
	 * @param data
	 * @return
	 */
	public static byte[] decrypt(EapTLSSecurityKey sk, byte[] data) {
		if (sk.clientWriteKey == null)
			return data;

		String alg = EapTLSDESUtil.ALG_DES;
		if (sk.cipherSpec != null
				&& sk.cipherSpec.getCipherAlgorithm() == EapTLSBulkCipherAlgorithm.RC4) {
			alg = EapTLSDESUtil.ALG_RC4;
		}

		return EapTLSDESUtil.decrypt(data, sk.clientWriteKey, alg);
	}

	/**
	 * 根据私钥进行解密
	 * 
	 * @param pk
	 * @param data
	 * @return
	 */
	public static byte[] decrypt(PrivateKey pk, byte[] data) {
		try {
			Cipher cipher1 = Cipher.getInstance("RSA");
			cipher1.init(Cipher.DECRYPT_MODE, pk);
			return cipher1.doFinal(data);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * 根据预主秘密生成主秘密
	 * 
	 * @param preMasterSecret
	 *            预主秘密
	 * @param clientRandom
	 *            客户端随机数
	 * @param serverRandom
	 *            服务端随机数
	 * @return 48个字节
	 */
	public static byte[] generateMasterSecret(byte[] preMasterSecret,
											  byte[] clientRandom, byte[] serverRandom) {
		byte[] buff = new byte[48];
		byte[] tmp;
		int j = 0;

		for (int i = 0; i < 48; i = i + 16) {
			tmp = generateMd5(j, preMasterSecret, clientRandom, serverRandom);
			EapTLSUtil.copyArray(tmp, 0, buff, i, tmp.length);
			++j;
		}

		return buff;
	}

	/**
	 * 根据主秘密生成各种类型key
	 * 
	 * @param sk
	 *            key存储的地方
	 * @param masterSecret
	 *            主秘密
	 * @param serverRandom
	 *            服务端随机数
	 * @param clientRandom
	 *            客户端随机数
	 */
	public static void generateKeys(EapTLSSecurityKey sk, byte[] masterSecret,
			byte[] serverRandom, byte[] clientRandom) {
		int len = 0;
		// 获取key块的长度
		len = (sk.cipherSpec.getHashSize() + sk.cipherSpec.getIvSize() + 
			   sk.cipherSpec.getKeyMaterial()) * 2;
		// 获取16的整数倍
		len = (len - len % 16) + 16;
		// 获取key块
		byte[] ret = generateKeyBlock(len, masterSecret, serverRandom,
				clientRandom);

		int i = 0;
		// 写mac
		if (sk.cipherSpec.getHashSize() > 0) {
			sk.clientWriteMac = new byte[sk.cipherSpec.getHashSize()];
			EapTLSUtil.copyArray(ret, i, sk.clientWriteMac, 0,
					sk.cipherSpec.getHashSize());
			i += sk.cipherSpec.getHashSize();
			sk.serverWriteMac = new byte[sk.cipherSpec.getHashSize()];
			EapTLSUtil.copyArray(ret, i, sk.serverWriteMac, 0,
					sk.cipherSpec.getHashSize());
			i += sk.cipherSpec.getHashSize();
		}
		// 写key
		if (sk.cipherSpec.getKeyMaterial() > 0) {
			sk.clientWriteKey = new byte[sk.cipherSpec.getKeyMaterial()];
			EapTLSUtil.copyArray(ret, i, sk.clientWriteKey, 0,
					sk.cipherSpec.getKeyMaterial());
			i += sk.cipherSpec.getKeyMaterial();
			sk.serverWriteKey = new byte[sk.cipherSpec.getKeyMaterial()];
			EapTLSUtil.copyArray(ret, i, sk.serverWriteKey, 0,
					sk.cipherSpec.getKeyMaterial());
			i += sk.cipherSpec.getKeyMaterial();
		}
		// 写iv
		if (sk.cipherSpec.getIvSize() > 0) {
			sk.clientWriteIV = new byte[sk.cipherSpec.getIvSize()];
			EapTLSUtil.copyArray(ret, i, sk.clientWriteIV, 0,
					sk.cipherSpec.getIvSize());
			i += sk.cipherSpec.getIvSize();
			sk.serverWriteIV = new byte[sk.cipherSpec.getIvSize()];
			EapTLSUtil.copyArray(ret, i, sk.serverWriteIV, 0,
					sk.cipherSpec.getIvSize());
		}
	}

	/**
	 * 根据主秘密生成key块
	 * 
	 * @param keyLength
	 *            key块长度
	 * @param masterSecret
	 *            主秘密
	 * @param serverRandom
	 *            服务端随机数
	 * @param clientRandom
	 *            客户端随机数
	 * @return keyLength个字节
	 */
	private static byte[] generateKeyBlock(int keyLength, byte[] masterSecret,
			byte[] serverRandom, byte[] clientRandom) {
		byte[] buff = new byte[keyLength];
		byte[] tmp;
		int j = 0;

		for (int i = 0; i < keyLength; i = i + 16) {
			tmp = generateMd5(j, masterSecret, serverRandom, clientRandom);
			EapTLSUtil.copyArray(tmp, 0, buff, i, tmp.length);
			++j;
		}

		return buff;
	}

	private static byte[] generateMd5(int ii, byte[] secret, byte[] random1,
			byte[] random2) {
		byte basic = 65;
		byte[] sn;
		if (ii > 0) {
			basic += ii;
			sn = new byte[(ii+1)];
			for (int j = 0; j < (ii + 1); j++) {
				sn[j] = basic;
			}
		} else {
			sn = new byte[1];
			sn[0] = basic;
		}
		

		int len = sn.length + secret.length + random1.length + random2.length;
		byte[] buff = new byte[len];
		int i = 0;

		// 1.先sha
		EapTLSUtil.copyArray(sn, 0, buff, i, sn.length);
		i += sn.length;
		EapTLSUtil.copyArray(secret, 0, buff, i, secret.length);
		i += secret.length;
		EapTLSUtil.copyArray(random1, 0, buff, i, random1.length);
		i += random1.length;
		EapTLSUtil.copyArray(random2, 0, buff, i, random2.length);
		byte[] sha = EapTLSHashMacUtil.hashMac(EapTLSHashMacUtil.HASH_SHA1,
				buff);
		// 2.再md5
		len = sha.length + secret.length;
		buff = new byte[len];
		i = 0;
		EapTLSUtil.copyArray(secret, 0, buff, i, secret.length);
		i += secret.length;
		EapTLSUtil.copyArray(sha, 0, buff, i, sha.length);

		return EapTLSHashMacUtil.hashMac(EapTLSHashMacUtil.HASH_MD5, buff);
	}

}