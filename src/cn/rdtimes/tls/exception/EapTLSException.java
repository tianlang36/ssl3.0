package cn.rdtimes.tls.exception;

/**
 * “Ï≥£ª˘¿‡
 * @author BZ
 * Date:2015-10-20
 */
@SuppressWarnings("serial")
public class EapTLSException extends Exception {
	public EapTLSException() {
		super();
	}
	
	public EapTLSException(String msg) {
		super(msg);
	}
	
	public EapTLSException(String msg, Exception ex) {
		super(msg,ex);
	}
	
}
