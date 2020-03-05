package cn.rdtimes.tls.msg;

/**
 * 警告协议消息.
 * 
 * @author BZ
 *
 */

public class EapTLSAlertMsg extends EapTLSMessage {
	private EapTLSAlertLevel alertLevel = EapTLSAlertLevel.WARNING;
	private byte alertDesc = 0x0;
	
	//内容将赋值给EapTLSRecordMsg.content统一处理
	private byte[] content = new byte[2];
	
	public EapTLSAlertMsg() {
		this.rtype = EapTLSRecordType.ALERT;
		this.length = 2;
	}

	@Override
	public byte[] combine() {
		content[0] = (byte)this.alertLevel.ordinal();
		content[1] = this.alertDesc;
		
		return content;
	}
	
	@Override
	public String toString() {
		return "EapTLSAlertMsg: \r\n" +
			   "AlertLevel:" + this.alertLevel.ordinal() + "\r\n" +
			   "AlertDescription:" + this.alertDesc;
	}

	public EapTLSAlertLevel getAlertLevel() {
		return alertLevel;
	}

	public void setAlertLevel(EapTLSAlertLevel alertLevel) {
		this.alertLevel = alertLevel;
	}

	public byte getAlertDesc() {
		return alertDesc;
	}

	public void setAlertDesc(byte alertDesc) {
		this.alertDesc = alertDesc;
	}
	
	public byte[] getContent() {
		return content;
	}
	
}

