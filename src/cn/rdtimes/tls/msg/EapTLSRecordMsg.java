package cn.rdtimes.tls.msg;

import cn.rdtimes.tls.util.EapTLSUtil;

/**
 * 用来解析和封装记录协议
 * 
 * @author BZ
 * Date: 2015-09-15
 */

public class EapTLSRecordMsg extends EapTLSMessage {
	public static int FIX_HEAD_LEN = 5;
	
	//消息内容
	private byte[] content = null;
	
	public EapTLSRecordMsg() {
		this.rtype = EapTLSRecordType.RECORD_MSG;
	}
	
	public byte[] getContent() {
		return content;
	}
	
	public void setContent(byte[] content) {
		this.content = content;
		
		if (this.content != null) this.length = this.content.length;
	}

	@Override
	public byte[] combine() {
		byte[] buff = new byte[FIX_HEAD_LEN + this.length];
		
		int i = 0;
		buff[i++] = this.rtype.getValue();
		buff[i++] = this.maxVersion;
		buff[i++] = this.minVersion;
		EapTLSUtil.convertShortToByte(buff, i, this.length);
		i += 2;
		EapTLSUtil.copyArray(this.content, 0, buff, i, this.length);
		
		return buff;
	}
	
	@Override
	public String toString() {
		return "EapTLSRecordMsg: \r\n" + 
			   "RecType:" + this.rtype.toString() + "\r\n" +
			   "MaxVersion:" + this.maxVersion + "\r\n" +
			   "MinVersion:" + this.minVersion + "\r\n" +
			   "Length:" + this.length + "\r\n" + 
			   "Msg:" + EapTLSUtil.formatByteHex(this.content==null?new byte[0]:this.content) + "\r\n";
	}
	
}
