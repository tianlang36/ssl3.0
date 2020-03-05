package com.asiainfo.eap.tls.msg;

import com.asiainfo.eap.tls.util.EapTLSUtil;

/**
 * 握手消息
 * 
 * @author BZ
 *
 * Date: 2015-09-22
 */

public class EapTLSHandShakeMsg extends EapTLSMessage {
	/**
	 * 头长度
	 */
	public static int FIX_HEAD_LEN = 4;
	/**
	 * 握手各个协议整合的内容,将赋值给EapTLSRecordMsg.content统一处理
	 */
	protected byte[] content = null;
	/**
	 * 握手协议中的类型
	 */
	protected EapTLSHandShakeType hstype = EapTLSHandShakeType.HELLO_REQUEST;
	
	
	public EapTLSHandShakeMsg() {
		this.rtype = EapTLSRecordType.HAND_SHAKE;
	}

	/**
	 * 这个由子类来完成其协议的组成，尤其是server端发出的消息
	 */
	protected void combineBody() {
		///nothing. 
	}
	
	@Override
	public byte[] combine() {
		combineBody();
		
		if (this.length <= 0 && this.content != null) {
			this.length = this.content.length;
		}
		byte[] buff = new byte[FIX_HEAD_LEN + this.length];
		int i = 0;
		
		buff[i] = this.hstype.getValue();
		i += 1;
		EapTLSUtil.convertIntegerTo3Byte(buff, i, this.length);
		i += 3;
		if (this.length > 0) {
			EapTLSUtil.copyArray(this.content, 0, buff, i, this.length);
		}
		
		return buff;
	}
	
	@Override
	public String toString() {
		return "EapTLSHandShakeMsg: \r\n" + 
			   "HSType:" + this.hstype.toString() + "\r\n" +
			   "Length:" + this.length + "\r\n" + 
			   "Msg:" + EapTLSUtil.formatByteHex(this.content==null?new byte[0]:this.content) + "\r\n";
	}

	public byte[] getContent() {
		return content;
	}

	public void setContent(byte[] content) {
		this.content = content;
		if (this.content != null) this.length = (short)this.content.length;
	}

	public EapTLSHandShakeType getHstype() {
		return hstype;
	}

	public void setHstype(EapTLSHandShakeType hstype) {
		this.hstype = hstype;
	}
	
}
