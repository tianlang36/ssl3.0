package cn.rdtimes.tls.msg;

import cn.rdtimes.tls.util.EapTLSUtil;

/**
 * 修改密钥消息,这个内容只有一个字节，并且值是“1”
 * 
 * 它的消息内容将是是加密和压缩的
 * 
 * @author BZ
 *
 * Date: 2015-09-24
 */

public class EapTLSChangeCipherMsg extends EapTLSMessage {
	//内容将赋值给EapTLSRecordMsg.content统一处理
	private byte[] content = null;
	
	public EapTLSChangeCipherMsg() {
		this.rtype = EapTLSRecordType.CHANGE_CIPHER;
	}

	@Override
	public byte[] combine() {
		return content;
	}
	
	@Override
	public String toString() {
		return "EapTLSChangeCipherMsg: \r\n" + EapTLSUtil.formatByteHex(content) + "\r\n";
	}
	
	public byte[] getContent() {
		return content;
	}
	
	public void setContent(byte[] content) {
		this.content = content;
		if (this.content != null) this.length = this.content.length;
	}

}
