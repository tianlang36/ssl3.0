package cn.rdtimes.tls.security;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import cn.rdtimes.tls.msg.EapTLSRecordType;
import cn.rdtimes.tls.util.EapTLSUtil;

/**
 * 算法、MAC等工具类.
 * 
 * @author BZ
 * Date:2015-10-14
 */
public final class EapTLSHashMacUtil {
	
	public static String HASH_MD5 = "MD5";
	public static String HASH_SHA1 = "SHA-1";
	
	/**
	 * 进行hash算法操作
	 * @param hashType
	 * @param input
	 * @return
	 */
	public static byte[] hashMac(String hashType, byte[] input) {
		// 获得摘要算法的 MessageDigest 对象
        MessageDigest mdInst;
		try {
			mdInst = MessageDigest.getInstance(hashType);
			// 使用指定的字节更新摘要
	        mdInst.update(input);
	        // 获得密文
	        return mdInst.digest();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	/**
	 * 生成一个服务端的MAC
	 * @param writeMAC 服务端写MAC key
	 * @param seqnum 序列号
	 * @param length 消息总长度
	 * @param data 原始数据
	 * @return 
	 */
	public static byte[] serverWriteMAC(EapTLSMACAlgorithm hash, byte[] writeMAC,
										long seqnum,int length,byte[] data,EapTLSRecordType rt) {
		return generateClientServerMac(hash,writeMAC,seqnum,length,data,rt);
	}
	
	/**
	 * 验证客户端发送的MAC
	 * 此方法暂时不实现
	 * @param writeMAC 客户端写mac key
	 * @param seqnum 序列号
	 * @param length 消息总长度
	 * @param data 原始数据
	 * @param srcMAC 被验证的MAC
	 * @return true-成功，false-失败
	 */
	public static boolean verifyClientMAC(EapTLSMACAlgorithm hash, byte[] writeMAC,
										  long seqnum, int length, byte[] data, 
										  byte[] srcMAC,EapTLSRecordType rt) {
		byte[] tmp1 = generateClientServerMac(hash,writeMAC,seqnum,length,data,rt);
		
//		System.out.println(EapTLSUtil.formatByteHex(tmp1));
//		return true;
		
		return EapTLSUtil.compareBytes(tmp1, srcMAC);
	}
	///用于客户端和服务器端记录数据中mac生成
	private static byte[] generateClientServerMac(EapTLSMACAlgorithm hash, byte[] writeMAC,
			  									  long seqnum, int length, byte[] data,
			  									  EapTLSRecordType rt) {
		byte[] pad1 = EapTLSUtil.generatePad1(hash==EapTLSMACAlgorithm.MD5?48:40);
		byte[] pad2 = EapTLSUtil.generatePad2(hash==EapTLSMACAlgorithm.MD5?48:40);
		int len = writeMAC.length + pad1.length + 8 + 1 + 2 + data.length;
		byte[] tmp = new byte[len];
		int i = 0;
		EapTLSUtil.copyArray(writeMAC, 0, tmp, i, writeMAC.length);
		i += writeMAC.length;
		EapTLSUtil.copyArray(pad1, 0, tmp, i, pad1.length);
		i += pad1.length;
		EapTLSUtil.convertLongToByte(tmp, i, seqnum);
		i += 8;
		tmp[i++] = rt.getValue();
		EapTLSUtil.convertShortToByte(tmp, i, length);
		i += 2;
		EapTLSUtil.copyArray(data, 0, tmp, i, data.length);
		String strhash = (hash==EapTLSMACAlgorithm.MD5?EapTLSHashMacUtil.HASH_MD5:EapTLSHashMacUtil.HASH_SHA1);
		//第一次
		byte[] sh1 = EapTLSHashMacUtil.hashMac(strhash, tmp);
		
		len = writeMAC.length + pad2.length + sh1.length;
		tmp = new byte[len];
		i = 0;
		EapTLSUtil.copyArray(writeMAC, 0, tmp, i, writeMAC.length);
		i += writeMAC.length;
		EapTLSUtil.copyArray(pad2, 0, tmp, i, pad2.length);
		i += pad2.length;
		EapTLSUtil.copyArray(sh1, 0, tmp, i, sh1.length);
		
		return EapTLSHashMacUtil.hashMac(strhash, tmp);
	}
	
}