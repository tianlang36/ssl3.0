package cn.rdtimes.tls;

import cn.rdtimes.tls.msg.EapTLSRecordMsg;
import cn.rdtimes.tls.msg.EapTLSRecordType;
import cn.rdtimes.tls.security.EapTLSCipherRC4;
import cn.rdtimes.tls.security.EapTLSSecurityKey;
import cn.rdtimes.tls.handle.EapTLSAlertHandler;
import cn.rdtimes.tls.handle.EapTLSApplicationHandler;
import cn.rdtimes.tls.handle.EapTLSChangeCipherHandler;
import cn.rdtimes.tls.handle.EapTLSHandShakeHandler;
import cn.rdtimes.tls.handle.EapTLSHandler;
import cn.rdtimes.tls.handle.EapTLSRecordHandler;

import java.util.HashMap;

/**
 * 用了对TLS协议解析和封装的管理，包括TLS握手协议和内容数据解密和加密。 此类不能以单件模式创建，每个连接需要单独创建实例。
 * 
 * @author BZ
 * 
 * Date：2015-10-20
 */

public class EapTLSHandlerAdapter {
	/**
	 * 握手是否完成，true-完成，false-未完成
	 */
	private boolean isHandShakeCompleted = false;
	/**
	 * 密钥等相关的信息
	 */
	private EapTLSSecurityKey securityKey = new EapTLSSecurityKey();
	/**
	 * 各种类型协议处理器
	 */
	private HashMap<Integer, EapTLSHandler> handlers = new HashMap<Integer, EapTLSHandler>();
	/**
	 * 本地java密钥库存放的路径及名称
	 */
	private String keystore = null;
	/**
	 * 密钥库的密码
	 */
	private String keystorePwd = "123456";
	/**
	 * 私钥获取时的密码
	 */
	private String privatekeyPwd = "123456";
	/**
	 * 在密钥库中获取私钥和证书的别名
	 */
	private String privatekeyAlias = "rdtimes";
	/**
	 * 解密客户端消息
	 */
	private EapTLSCipherRC4 readCipher = null;
	/**
	 * 加密服务端消息
	 */
	private EapTLSCipherRC4 writeCipher = null;
	

	public EapTLSHandlerAdapter() {
		init();
	}

	private void init() {
		handlers.put((int) EapTLSRecordType.RECORD_MSG.getValue(),
				new EapTLSRecordHandler(this));
		handlers.put((int) EapTLSRecordType.HAND_SHAKE.getValue(),
				new EapTLSHandShakeHandler(this));
		handlers.put((int) EapTLSRecordType.ALERT.getValue(),
				new EapTLSAlertHandler(this));
		handlers.put((int) EapTLSRecordType.CHANGE_CIPHER.getValue(),
				new EapTLSChangeCipherHandler(this));
		handlers.put((int) EapTLSRecordType.APPLICATION_DATA.getValue(),
				new EapTLSApplicationHandler(this));
	}

	public boolean isHandShakeCompleted() {
		return this.isHandShakeCompleted;
	}
	
	public void setHandShakeCompleted(boolean b) {
		this.isHandShakeCompleted = b;
	}

	public EapTLSSecurityKey getSecurityKey() {
		return securityKey;
	}

	public EapTLSCipherRC4 getReadCipher() {
		return this.readCipher;
	}
	
	public EapTLSCipherRC4 getWriteCipher() {
		return this.writeCipher;
	}
	
	public void generateReadCipher(byte[] key) {
		this.readCipher = new EapTLSCipherRC4(key, null, false);
	}
	
	public void generateWriteCipher(byte[] key) {
		this.writeCipher = new EapTLSCipherRC4(key, null, true);
	}
	
	public String getKeystore() {
		return keystore;
	}

	public void setKeystore(String keystore) {
		this.keystore = keystore;
	}

	public String getKeystorePwd() {
		return keystorePwd;
	}

	public void setKeystorePwd(String keystorePwd) {
		this.keystorePwd = keystorePwd;
	}

	public String getPrivatekeyPwd() {
		return privatekeyPwd;
	}

	public void setPrivatekeyPwd(String privatekeyPwd) {
		this.privatekeyPwd = privatekeyPwd;
	}

	public String getPrivatekeyAlias() {
		return privatekeyAlias;
	}

	public void setPrivatekeyAlias(String privatekeyAlias) {
		this.privatekeyAlias = privatekeyAlias;
	}

	public EapTLSHandler getEapTLSHandler(EapTLSRecordType rt) {
		return handlers.get((int) rt.getValue());
	}
	public EapTLSRecordHandler getEapTLSRecordHandler() {
		return (EapTLSRecordHandler) handlers
				.get((int) EapTLSRecordType.RECORD_MSG.getValue());
	}
	public EapTLSHandShakeHandler getEapTLSHandShakeHandler() {
		return (EapTLSHandShakeHandler) handlers
				.get((int) EapTLSRecordType.HAND_SHAKE.getValue());
	}
	public EapTLSAlertHandler getEapTLSAlertHandler() {
		return (EapTLSAlertHandler) handlers.get((int) EapTLSRecordType.ALERT
				.getValue());
	}
	public EapTLSChangeCipherHandler getEapTLSChangeCipherHandler() {
		return (EapTLSChangeCipherHandler) handlers
				.get((int) EapTLSRecordType.CHANGE_CIPHER.getValue());
	}
	public EapTLSApplicationHandler getEapTLSApplicationHandler() {
		return (EapTLSApplicationHandler) handlers
				.get((int) EapTLSRecordType.APPLICATION_DATA.getValue());
	}
	
	/**
	 * 写最终的记录消息
	 * @param msg
	 */
	public void writeRecordMsg(EapTLSRecordMsg msg) {
		getEapTLSRecordHandler().writeRecordMsg(msg);
	}
	
	public void writeRecordMsg(byte[] msg) {
		getEapTLSRecordHandler().writeRecordMsg(msg);
	}

}
