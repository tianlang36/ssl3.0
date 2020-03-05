package com.asiainfo.eap.tls.msg;

/**
 * 握手消息的类型 
 * 
 * @author BZ
 * 
 * Date: 2015-10-12
 */

public enum EapTLSHandShakeType {
	HELLO_REQUEST(0),CLIENT_HELLO(1),SERVER_HELLO(2),
	CERTIFICATE(11),SERVER_KEY_EXCHANGE(12),CERTIFICATE_REQUEST(13),
	SERVER_DONE(14),CERTIFICATE_VERIFY(15),CLIENT_KEY_EXCHANGE(16),
	FINISHED(20), CHANGE_CIPER_SPEC(255) /*非握手协议，用来表示状态*/;
	
	private byte value = 1;
	
	public static EapTLSHandShakeType valueOf(byte value) {
		switch(value) {
			case 0:
				return HELLO_REQUEST;
			case 1:
				return CLIENT_HELLO;
			case 2:
				return SERVER_HELLO;
			case 11:
				return CERTIFICATE;
			case 12:
				return SERVER_KEY_EXCHANGE;
			case 13:
				return CERTIFICATE_REQUEST;
			case 14:
				return SERVER_DONE;
			case 15:
				return CERTIFICATE_VERIFY;
			case 16:
				return CLIENT_KEY_EXCHANGE;
			case 20:
				return FINISHED;
			case (byte)255:
				return CHANGE_CIPER_SPEC;
		}
		
		return null;
	}
	
	private EapTLSHandShakeType(int value) {
		this.value = (byte)value;
	}
	
	public byte getValue() {
		return this.value;
	}
	
	@Override
	public String toString() {
		return this.name() + "(" + Byte.toString(this.value) + ")";
	}
	
}
