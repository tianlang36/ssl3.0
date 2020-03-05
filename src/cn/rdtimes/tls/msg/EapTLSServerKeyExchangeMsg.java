package cn.rdtimes.tls.msg;


import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import cn.rdtimes.tls.EapTLSHandlerAdapter;
import cn.rdtimes.tls.security.EapTLSHashMacUtil;
import cn.rdtimes.tls.util.EapTLSCertUtil;
import cn.rdtimes.tls.util.EapTLSUtil;

/**
 * ServerKeyExchange协议 我们是服务端，所以这里只做消息构成处理
 * 
 * @author BZ
 * 
 * Date: 2015-10-08
 */

public class EapTLSServerKeyExchangeMsg extends EapTLSHandShakeMsg {
	private byte[] modulus = null;
	private byte[] exponent = null;
	private byte[] hashmd5 = null;
	private byte[] hashsha = null;
	
	private byte[] clientRandom = null;
	private byte[] serverRandom = null;
	
	private EapTLSHandlerAdapter adapter = null;
	
	public EapTLSServerKeyExchangeMsg(EapTLSHandlerAdapter adapter) {
		this.hstype = EapTLSHandShakeType.SERVER_KEY_EXCHANGE;
		this.clientRandom = adapter.getSecurityKey().clientRandom;
		this.serverRandom = adapter.getSecurityKey().serverRandom;
		this.adapter = adapter;
		
		generate();
	}
	
	@Override
	protected void combineBody() {
		int len = 2 + this.modulus.length + 2 + this.exponent.length + 16 + 20;
		this.content = new byte[len];
		int i = 0;
		EapTLSUtil.convertShortToByte(this.content, i, this.modulus.length);
		i += 2;
		EapTLSUtil.copyArray(this.modulus, 0, this.content, i, this.modulus.length);
		i += this.modulus.length;
		EapTLSUtil.convertShortToByte(this.content, i, this.exponent.length);
		i += 2;
		EapTLSUtil.copyArray(this.exponent, 0, this.content, i, this.exponent.length);
		i += this.exponent.length;
		EapTLSUtil.copyArray(this.hashmd5, 0, this.content, i, 16);
		i += 16;
		EapTLSUtil.copyArray(this.hashsha, 0, this.content, i, 20);
	}
	
	private void generate() {
		//1.读取共钥
		X509Certificate x509 = EapTLSCertUtil.getX509CertificateFromKeyStore(adapter.getKeystore(), 
																			 adapter.getKeystorePwd(), 
																			 adapter.getPrivatekeyAlias());
		RSAPublicKey pk = (RSAPublicKey)x509.getPublicKey();
		this.modulus = pk.getModulus().toByteArray();
		this.exponent = pk.getPublicExponent().toByteArray();
		//2.开始mac
		int len = this.clientRandom.length + this.serverRandom.length + this.modulus.length +
				  this.exponent.length;
		byte[] tmp = new byte[len];
		
		int i = 0;
		EapTLSUtil.copyArray(this.clientRandom, 0, tmp, i, this.clientRandom.length);
		i += this.clientRandom.length;
		EapTLSUtil.copyArray(this.serverRandom, 0, tmp, i, this.serverRandom.length);
		i += this.serverRandom.length;
		EapTLSUtil.copyArray(this.modulus, 0, tmp, i, this.modulus.length);
		i += this.modulus.length;
		EapTLSUtil.copyArray(this.exponent, 0, tmp, i, this.exponent.length);
		
		this.hashmd5 = EapTLSHashMacUtil.hashMac(EapTLSHashMacUtil.HASH_MD5, tmp);
		this.hashsha = EapTLSHashMacUtil.hashMac(EapTLSHashMacUtil.HASH_SHA1, tmp);
	}

	public byte[] getModulus() {
		return modulus;
	}

	public void setModulus(byte[] modulus) {
		this.modulus = modulus;
	}

	public byte[] getExponent() {
		return exponent;
	}

	public void setExponent(byte[] exponent) {
		this.exponent = exponent;
	}

	@Override
	public String toString() {
		return  "EapTLSServerKeyExchangeMsg: \r\n" +
				"Modulus:" + EapTLSUtil.formatByteHex(this.modulus) + "\r\n" +
				"Exponent:" + EapTLSUtil.formatByteHex(this.exponent) + "\r\n" +
				"MD5:" + EapTLSUtil.formatByteHex(this.hashmd5) + "\r\n" +
				"SHA1:" + EapTLSUtil.formatByteHex(this.hashsha) + "\r\n" ;
	}

}
