package cn.rdtimes.tls.msg;

import cn.rdtimes.tls.security.EapTLSHashMacUtil;
import cn.rdtimes.tls.security.EapTLSSecurityKey;
import cn.rdtimes.tls.util.EapTLSUtil;

/**
 * 应用数据消息
 * 
 * @author BZ
 *
 * Date: 2015-10-23
 */

public class EapTLSApplicationMsg extends EapTLSMessage {
	//内容将赋值给EapTLSRecordMsg.content统一处理
	private byte[] content = null;
	private byte[] mac = null;
	private EapTLSSecurityKey sk = null;
	
	public EapTLSApplicationMsg(EapTLSSecurityKey sk) {
		this.rtype = EapTLSRecordType.APPLICATION_DATA;
		this.sk = sk;
	}

	@Override
	public byte[] combine() {
		//写server MAC,应该是压缩的数据
		int len = this.content.length;
		this.mac = EapTLSHashMacUtil.serverWriteMAC(this.sk.cipherSpec.getMacAlgorithm(), 
													this.sk.serverWriteMac, 
													this.sk.seq_number_write,
													len, this.content,this.rtype);
		this.length = this.mac.length + this.content.length;
		byte[] buff = new byte[this.length];
		EapTLSUtil.copyArray(this.content, 0, buff, 0, this.content.length);
		EapTLSUtil.copyArray(this.mac, 0, buff, this.content.length, this.mac.length);
		
		return buff;
	}
	
	//分析内容
	public void parseContent(byte[] content) {
		///这里是按照流方式处理的，如果是块方式是错误的 !!!!!
		this.length = content.length - this.sk.cipherSpec.getHashSize();
		this.content = new byte[this.length];
		EapTLSUtil.copyArray(content, 0, this.content, 0, this.length);
		
		this.mac = new byte[this.sk.cipherSpec.getHashSize()];
		EapTLSUtil.copyArray(content, this.length, this.mac, 0, mac.length);
	}

	public byte[] getContent() {
		return content;
	}

	public void setContent(byte[] content) {
		this.content = content;
		if (this.content != null) this.length = this.content.length;
	}
	
	public byte[] getMac() {
		return mac;
	}
	
	@Override
	public String toString() {
		int len = this.content == null ? 0 : this.content.length;
		return "EapTLSApplicationMsg: \r\n" +
			   "Length:" + len + "\r\n" + 
			   "MAC:" + EapTLSUtil.formatByteHex(this.mac) + "\r\n" +
			   "Msg:" + new String(this.content);
	}
	
}
