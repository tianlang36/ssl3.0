package cn.rdtimes.tls.msg;


import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import cn.rdtimes.tls.EapTLSHandlerAdapter;
import cn.rdtimes.tls.util.EapTLSCertUtil;
import cn.rdtimes.tls.util.EapTLSUtil;

/**
 * ServerCertificate协议 我们是服务端，所以这里只做消息构成处理
 * 
 * @author BZ
 * 
 * Date: 2015-09-24
 */

public class EapTLSServerCertificateMsg extends EapTLSHandShakeMsg {
	private EapTLSHandlerAdapter adapter = null;
	
	
	public EapTLSServerCertificateMsg(EapTLSHandlerAdapter adapter) {
		this.hstype = EapTLSHandShakeType.CERTIFICATE;
		this.adapter = adapter;
	}
	
	@Override
	protected void combineBody() {
		int len = 3 + 3; 
		X509Certificate cert = EapTLSCertUtil.getX509CertificateFromKeyStore(adapter.getKeystore(), 
								adapter.getKeystorePwd(), adapter.getPrivatekeyAlias());
		byte[] buff = null;
		try {
			buff = cert.getEncoded();
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
			buff = null;
		}
		
		if (buff == null) return;
		len += buff.length;
		this.content = new byte[len];
		
		int i = 0;
		EapTLSUtil.convertIntegerTo3Byte(this.content, i, (buff.length + 3));
		i += 3;
		EapTLSUtil.convertIntegerTo3Byte(this.content, i, buff.length);
		i += 3;
		EapTLSUtil.copyArray(buff, 0, this.content, i, buff.length);
	}

	@Override
	public String toString() {
		return  "EapTLSServerCertificateMsg: \r\n" +
				"Length:" + (this.content==null?0:this.content.length) + "\r\n";
	}

}
