package cn.rdtimes.tls.handle;

import cn.rdtimes.tls.EapTLSHandlerAdapter;
import cn.rdtimes.tls.exception.EapTLSException;
import cn.rdtimes.tls.msg.EapTLSChangeCipherMsg;
import cn.rdtimes.tls.msg.EapTLSHandShakeType;
import cn.rdtimes.tls.msg.EapTLSRecordMsg;
import cn.rdtimes.tls.msg.EapTLSRecordType;

/**
 * 密钥交换消息处理器
 * @author BZ
 * Date: 2015-10-13
 */
public class EapTLSChangeCipherHandler extends EapTLSHandler {

	public EapTLSChangeCipherHandler() {}
	
	public EapTLSChangeCipherHandler(EapTLSHandlerAdapter adapter) {
		this.adapter = adapter;
	}

	/**
	 * 解析客户端消息
	 * @param msg
	 * @return
	 * @throws EapTLSException
	 */
	public EapTLSChangeCipherMsg processChangeCipher(byte[] msg) throws EapTLSException {
		//1.创建交换信息，通常内容是1
		EapTLSChangeCipherMsg cc = new EapTLSChangeCipherMsg();
		cc.setContent(msg);
		//2.改变握手协议中的状态
		adapter.getEapTLSHandShakeHandler().setCurrState(EapTLSHandShakeType.CHANGE_CIPER_SPEC);
		adapter.getSecurityKey().seq_number_read = 0;
		
		return cc;
	}
	
	/**
	 * 发送服务端消息
	 * @throws EapTLSException
	 */
	public void writeChangeCipherMsg() throws EapTLSException {
		EapTLSChangeCipherMsg cc = getEapTLSChangeCipherMsg();
		EapTLSRecordMsg rmsg = new EapTLSRecordMsg();
		rmsg.setRType(EapTLSRecordType.CHANGE_CIPHER);
		rmsg.setContent(cc.combine());
		
		adapter.writeRecordMsg(rmsg);
		adapter.getSecurityKey().seq_number_write = 0;
	}
	
	/**
	 * 获得一个交换消息
	 * @return
	 */
	public EapTLSChangeCipherMsg getEapTLSChangeCipherMsg() {
		EapTLSChangeCipherMsg cc = new EapTLSChangeCipherMsg();
		byte[] b = new byte[1];
		b[0] = 0x01;
		cc.setContent(b);
		return cc;
	}
	
}
