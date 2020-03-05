package cn.rdtimes.tls.msg;

import java.util.ArrayList;
import java.util.List;

import cn.rdtimes.tls.util.EapTLSUtil;

/**
 * ClientHello协议 我们是服务端，所以这里只做解析处理
 * 
 * @author BZ
 * Date:2015-10-08
 */

public class EapTLSClientHelloMsg extends EapTLSHandShakeMsg {
	//最大版本
	private byte maxClientVersion = 0x3;
	//最小版本
	private byte minClientVersion = 0x0;
	//随机数
	private byte[] randoms = new byte[32];
	//会话id
	private byte[] sessionId = null;
	//密码套件列表
	private List<byte[]> cipherSuite = new ArrayList<byte[]>();
	//压缩算法
	private List<Byte> compressionMethod = new ArrayList<Byte>();
	
	/**
	 * 将接收到的内容传入然后解析
	 * @param content
	 */
	public EapTLSClientHelloMsg(byte[] content) {
		this.hstype = EapTLSHandShakeType.CLIENT_HELLO;
		parseBody(content);
	}
	
	/**
	 * 分析数据中的具体内容
	 * @param content
	 */
	private void parseBody(byte[] content) {
		int i = 0; int len = 0;
		//0.获取版本和随机数
		this.maxClientVersion = content[i++];
		this.minClientVersion = content[i++];
		EapTLSUtil.copyArray(content, i, this.randoms, 0, this.randoms.length);
		i += 32;
		//1.先获取回话id的长度，在获取回话内容
		len = content[i++];
		if (len > 0) {
			this.sessionId = new byte[len];
			EapTLSUtil.copyArray(content, i, this.sessionId, 0, this.sessionId.length);
			i += len;
		}
		//2.获取密钥套件的长度和内容
		byte[] cipher = new byte[2];
		EapTLSUtil.copyArray(content, i, cipher, 0, 2);
		i += 2;
		len = EapTLSUtil.convertShot(cipher, 0);
		for (int j = 0; j < len; j=j+2) {
			byte[] tb = new byte[2];
			EapTLSUtil.copyArray(content, i, tb, 0, 2);
			this.cipherSuite.add(tb);
			i += 2;
		}
		//3.获取压缩算法
		len = content[i++];
		for (int j = 0; j < len; j++) {
			this.compressionMethod.add(content[i++]);
		}
	}

	public byte getMaxClientVersion() {
		return maxClientVersion;
	}

	public byte getMinClientVersion() {
		return minClientVersion;
	}

	public byte[] getRandoms() {
		return randoms;
	}

	public byte[] getSessionId() {
		return sessionId;
	}

	public List<byte[]> getCipherSuite() {
		return cipherSuite;
	}

	public List<Byte> getCompressionMethod() {
		return compressionMethod;
	}
	
	@Override
	public String toString() {
		return "EapTLSClientHelloMsg: \r\n" + 
			   "Version:" + this.maxClientVersion + "." + this.minClientVersion + "\r\n" +
			   "Random:" + EapTLSUtil.formatByteHex(this.randoms) + "\r\n" +
			   "SessionId:" + EapTLSUtil.formatByteHex(this.sessionId) + "\r\n" +
			   "CipherSuite Length:" + this.cipherSuite.size() + "\r\n" +
			   "CipherSuite:" + formatCipherSuit() + "\r\n" +
			   "CompressionMethod Length:" + this.compressionMethod.size() + "\r\n" +
			   "CompressionMethod:" + formatCompressMethod() + "\r\n"  ;
	}
	
	private String formatCipherSuit() {
		String ret = "";
		for(int i = 0; i < this.cipherSuite.size(); i++) {
			if (i > 0) ret += " ";
			ret += EapTLSUtil.formatByteHex(this.cipherSuite.get(i));
		}
		
		return ret;
	}
	
	private String formatCompressMethod() {
		String ret = "";
		for(int i = 0; i < this.compressionMethod.size(); i++) {
			if (i > 0) ret += " ";
			ret += EapTLSUtil.formatByteHex(this.compressionMethod.get(i));
		}
		return ret;
	}

}
