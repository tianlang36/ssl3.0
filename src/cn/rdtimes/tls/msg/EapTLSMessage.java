package cn.rdtimes.tls.msg;

/**
 * 消息基类
 * 以记录消息协议为基础。
 * 
 * @author BZ
 * Date: 2015-09-15
 */

public abstract class EapTLSMessage {
	//消息类型，这里指的是记录协议中的类型
	protected EapTLSRecordType rtype = EapTLSRecordType.HAND_SHAKE;
	//主要版本 SSL3.0,TLS1.0=SSL3.1,TLS1.1=SSL3.2,TLS1.2=SSL3.3
	protected byte maxVersion = 0x03;
	//次要版本
	protected byte minVersion = 0x00;
	//消息长度,2个字节长
	protected int length = 0;

	public EapTLSRecordType getRType() {
		return rtype;
	}
	
	public void setRType(EapTLSRecordType rtype) {
		this.rtype = rtype;
	}

	public byte getMaxVersion() {
		return maxVersion;
	}
	
	public void setMaxVersion(byte maxVersion) {
		this.maxVersion = maxVersion;
	}

	public void setMinVersion(byte minVersion) {
		this.minVersion = minVersion;
	}

	public void setLength(int length) {
		this.length = length;
	}

	public byte getMinVersion() {
		return minVersion;
	}

	public int getLength() {
		return length;
	}
	
	/**
	 * 组合消息内容
	 */
	public abstract byte[] combine();
		
}
