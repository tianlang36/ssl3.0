package cn.rdtimes.tls.handle;

/**
 * 警告消息处理器
 * Author: BZ
 * Date: 2015-10-23
 */
import cn.rdtimes.tls.EapTLSHandlerAdapter;
import cn.rdtimes.tls.exception.EapTLSException;
import cn.rdtimes.tls.msg.EapTLSAlertLevel;
import cn.rdtimes.tls.msg.EapTLSAlertMsg;
import cn.rdtimes.tls.msg.EapTLSRecordMsg;
import cn.rdtimes.tls.msg.EapTLSRecordType;
import cn.rdtimes.tls.security.EapTLSAlgorithmUtil;
import cn.rdtimes.tls.security.EapTLSHashMacUtil;
import cn.rdtimes.tls.util.EapTLSUtil;

public class EapTLSAlertHandler extends EapTLSHandler {

	public EapTLSAlertHandler() {}
	
	public EapTLSAlertHandler(EapTLSHandlerAdapter adapter) {
		this.adapter = adapter;
	}
	
	/**
	 * 解析客户端消息
	 * @param msg
	 * @return
	 * @throws EapTLSException
	 */
	public EapTLSAlertMsg processAlert(byte[] msg) throws EapTLSException {
		byte[] alg = null;
		byte[] unzip = null;
		if (adapter.getReadCipher() == null) {
			alg = unzip = msg;
		}
		else {
			alg = adapter.getReadCipher().decrypt(msg);
			if (alg == null) {
				throw new EapTLSException("EapTLSAlertHandler.processHandShake() decryption is null");
			}
			unzip = EapTLSAlgorithmUtil.unzip(adapter.getSecurityKey(), alg);
			if (unzip == null) {
				throw new EapTLSException("EapTLSAlertHandler.processHandShake() unzip is null");
			}
		}
		this.adapter.getSecurityKey().seq_number_read += 1;
		//2.创建警告信息
		EapTLSAlertMsg alert = new EapTLSAlertMsg();
		alert.setAlertLevel(EapTLSAlertLevel.valueOf(unzip[0]));
		alert.setAlertDesc(unzip[1]);
				
		return alert;
	}
	
	/**
	 * 写服务端消息
	 * @param level
	 * @param description
	 * @throws EapTLSException
	 */
	public void writeAlertMsg(byte level, byte description) throws EapTLSException {
		if (adapter.getWriteCipher() == null) {
			EapTLSAlertMsg alert = new EapTLSAlertMsg();
			alert.setAlertLevel(EapTLSAlertLevel.valueOf(level));
			alert.setAlertDesc(description);
			
			EapTLSRecordMsg rmsg = new EapTLSRecordMsg();
			rmsg.setRType(EapTLSRecordType.ALERT);
			rmsg.setContent(alert.combine());
			
			adapter.writeRecordMsg(rmsg);
		}
		else {
			EapTLSAlertMsg alert = new EapTLSAlertMsg();
			alert.setAlertLevel(EapTLSAlertLevel.valueOf(level));
			alert.setAlertDesc(description);
			byte[] abuff = alert.combine();
			byte[] compress = EapTLSAlgorithmUtil.zip(adapter.getSecurityKey(), abuff);
			if (compress == null) {
				throw new EapTLSException("EapTLSAlertHandler.writeAlertMsg() zip is null");
			}
			byte[] mac = EapTLSHashMacUtil.serverWriteMAC(adapter.getSecurityKey().cipherSpec.getMacAlgorithm(), 
														  adapter.getSecurityKey().serverWriteMac, 
														  adapter.getSecurityKey().seq_number_write,
														  abuff.length, abuff, alert.getRType());
			byte[] encrypt = new byte[abuff.length + mac.length];
			EapTLSUtil.copyArray(abuff, 0, encrypt, 0, abuff.length);
			EapTLSUtil.copyArray(mac, 0, encrypt, abuff.length, mac.length);
			byte[] alg = adapter.getWriteCipher().encrypt(compress);
			if (alg == null) {
				throw new EapTLSException("EapTLSAlertHandler.writeAlertMsg() encrypt is null");
			}
			//3.组成记录协议发送
			EapTLSRecordMsg rmsg = new EapTLSRecordMsg();
			rmsg.setRType(EapTLSRecordType.ALERT);
			rmsg.setContent(alg);
			
			adapter.writeRecordMsg(rmsg);
		}
		this.adapter.getSecurityKey().seq_number_write += 1;
	}
	
}
