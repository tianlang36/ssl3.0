package cn.rdtimes.tls.msg;


import java.security.PrivateKey;

import cn.rdtimes.tls.EapTLSHandlerAdapter;
import cn.rdtimes.tls.security.EapTLSAlgorithmUtil;
import cn.rdtimes.tls.util.EapTLSCertUtil;
import cn.rdtimes.tls.util.EapTLSUtil;

/**
 * ClientKeyExchange协议 我们是服务端，所以这里只做解析处理
 * 
 * @author BZ
 * Date:2015-10-13
 */

public class EapTLSClientKeyExchangeMsg extends EapTLSHandShakeMsg {
	private EapTLSHandlerAdapter adapter = null;
	
	//预主秘密,整个消息都是
	private byte[] preMasterSecret = null;
	//最大版本
	private byte maxClientVersion = 0x03;
	//最小版本
	private byte minClientVersion = 0x00;
	
	/**
	 * 将接收到的内容传入然后解析
	 * @param content
	 */
	public EapTLSClientKeyExchangeMsg(byte[] content, EapTLSHandlerAdapter adapter) {
		this.hstype = EapTLSHandShakeType.CLIENT_KEY_EXCHANGE;
		this.adapter = adapter;
		parseBody(content);
	}
	
	/**
	 * 分析数据中的具体内容
	 * @param content
	 */
	private void parseBody(byte[] content) {
		//解密预主秘密
		decryptPreMasterSecret(content);
		//获取版本和随机数
		this.maxClientVersion = this.preMasterSecret[0];
		this.minClientVersion = this.preMasterSecret[1];
	}
	
	private void decryptPreMasterSecret(byte[] content) {
		PrivateKey pk = EapTLSCertUtil.getPriveKeyFromKeyStore(adapter.getKeystore(), 
				adapter.getKeystorePwd(), adapter.getPrivatekeyAlias(), 
				adapter.getPrivatekeyPwd());
		this.preMasterSecret = EapTLSAlgorithmUtil.decrypt(pk, content);
	}

	public byte getMaxClientVersion() {
		return maxClientVersion;
	}

	public byte getMinClientVersion() {
		return minClientVersion;
	}

	public byte[] getPreMasterSecret() {
		return preMasterSecret;
	}

	public void setPreMasterSecret(byte[] preMasterSecret) {
		this.preMasterSecret = preMasterSecret;
	}

	public void setMaxClientVersion(byte maxClientVersion) {
		this.maxClientVersion = maxClientVersion;
	}

	public void setMinClientVersion(byte minClientVersion) {
		this.minClientVersion = minClientVersion;
	}

	@Override
	public String toString() {
		return "EapTLSClientKeyExchangeMsg: \r\n" + 
			   "Version:" + this.maxClientVersion + "." + this.minClientVersion + "\r\n" +
			   "PreMasterSecret:" + EapTLSUtil.formatByteHex(this.preMasterSecret) + "\r\n";
	}
	
}
