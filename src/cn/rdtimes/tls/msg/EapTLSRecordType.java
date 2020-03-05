package cn.rdtimes.tls.msg;

/**
 * TLS记录协议中的类型
 * 
 * @author BZ
 *
 * Date: 2015-09-15
 */

public enum EapTLSRecordType {
	CHANGE_CIPHER(20), 		//改变密码格式协议
	ALERT(21),				//警告协议
	HAND_SHAKE(22),			//握手协议
	APPLICATION_DATA(23),	//应用数据协议
	RECORD_MSG(-1);			//自定义的记录协议消息类型,即本身
	
	private byte value = 22;
	
	public static EapTLSRecordType valueOf(byte value) {
		switch(value) {
			case 20:
				return CHANGE_CIPHER;
			case 21:
				return ALERT;
			case 22:
				return HAND_SHAKE;
			case 23:
				return APPLICATION_DATA;
		}
		
		return RECORD_MSG;
	}
	
	private EapTLSRecordType(int value) {
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
