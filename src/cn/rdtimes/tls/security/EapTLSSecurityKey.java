package cn.rdtimes.tls.security;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import cn.rdtimes.tls.util.EapTLSUtil;

/**
 * 协商密钥等相关信息
 * 
 * @author BZ Date:2015-09-25
 */
public final class EapTLSSecurityKey {
	/**
	 * 支持的密码套接, 0x0009,0x0005 默认按0x0005解析
	 */
	public static String[] CIPHER_SUITE = { "SSL_RSA_WITH_RC4_128_SHA",
											"SSL_RSA_WITH_DES_CBC_SHA" };
	// 确认使用的密钥套件,用来加密和解密数据
	private byte[] cipherSuite = null;
	// 主秘密，用来加密和解密数据
	public byte[] masterKey = null;
	// 客户端加密数据时的秘密
	public byte[] clientWriteKey = null;
	// 服务端加密数据时的秘密
	public byte[] serverWriteKey = null;
	// 客户端写mac信息时的秘密
	public byte[] clientWriteMac = null;
	// 服务端写mac信息时的秘密
	public byte[] serverWriteMac = null;
	// 客户端初始化化向量
	public byte[] clientWriteIV = null;
	// 服务端初始化向量
	public byte[] serverWriteIV = null;
	// 会话id
	public byte[] sessionId = null;
	// 压缩算法
	public byte compressMethod = 0;
	// 客户端生成的随机数
	public byte[] clientRandom = null;
	// 服务端生成随机数
	public byte[] serverRandom = null;
	// 读序列号
	public long seq_number_read = 0;
	//写序列号
	public long seq_number_write = 0;
	// 只有设置密钥套件时才会创建和使用
	public EapTLSCipherSpec30 cipherSpec = null;

	// 消息总览
	private ByteArrayOutputStream msgTotalBuffer = new ByteArrayOutputStream();

	public EapTLSSecurityKey() {
	}

	public void addBytesToMsgTotalBuffer(byte[] b) {
		if (msgTotalBuffer == null)
			msgTotalBuffer = new ByteArrayOutputStream();
		try {
			msgTotalBuffer.write(b);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public byte[] msgTotalBufferToByte() {
		return msgTotalBuffer.toByteArray();
	}

	public void clearMsgTotalBuffer() {
		try {
			if (msgTotalBuffer != null) {
				msgTotalBuffer.close();
			}
		} catch (IOException e) {
			e.printStackTrace();
		}

		msgTotalBuffer = null;
	}

	public byte[] getCipherSuite() {
		return cipherSuite;
	}

	public void setCipherSuite(byte[] cipherSuite) {
		this.cipherSuite = cipherSuite;
		if (this.cipherSuite != null) {
			this.cipherSpec = new EapTLSCipherSpec30(
					(int) EapTLSUtil.convertShot(this.cipherSuite, 0));
		}
	}

}
