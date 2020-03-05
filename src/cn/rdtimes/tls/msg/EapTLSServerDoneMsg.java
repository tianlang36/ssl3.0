package cn.rdtimes.tls.msg;


/**
 * 完成消息
 * @author BZ
 * 
 */

public class EapTLSServerDoneMsg extends EapTLSHandShakeMsg {

	public EapTLSServerDoneMsg() {
		this.hstype = EapTLSHandShakeType.SERVER_DONE;
	}

	@Override
	public String toString() {
		return  "EapTLSServerDoneMsg: {}\r\n";
	}
	
}
