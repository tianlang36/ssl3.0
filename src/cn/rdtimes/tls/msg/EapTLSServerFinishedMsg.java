package cn.rdtimes.tls.msg;

import cn.rdtimes.tls.EapTLSHandlerAdapter;
import cn.rdtimes.tls.security.EapTLSHashMacUtil;
import cn.rdtimes.tls.util.EapTLSUtil;

/**
 * ServerFinished协议 我们是服务端，所以这里只做消息构成处理
 * 
 * @author BZ
 * Date:2015-10-23
 */

public class EapTLSServerFinishedMsg extends EapTLSHandShakeMsg {
	private EapTLSHandlerAdapter adapter = null;
	
	private byte[] md5 = null;
	private byte[] sha = null;
	private static long server = 0x53525652;
	
	public EapTLSServerFinishedMsg(EapTLSHandlerAdapter adapter) {
		this.hstype = EapTLSHandShakeType.FINISHED;
		this.adapter = adapter;
		
		generateHash();
	}
	
	/**
	 * 生成md5概要，外部可调用
	 * @param adapter
	 * @param cs
	 * @return
	 */
	public static byte[] generateHashMD5(EapTLSHandlerAdapter adapter, long cs) {
		byte[] sender = new byte[4];
		EapTLSUtil.convertIntegerToByte(sender, 0, cs);
		byte[] totalMsg = adapter.getSecurityKey().msgTotalBufferToByte();
		byte[] pad1 = EapTLSUtil.generatePad1(48);
		byte[] pad2 = EapTLSUtil.generatePad2(48);
		int len = totalMsg.length + sender.length + 
				  adapter.getSecurityKey().masterKey.length + pad1.length;
		byte[] tmp = new byte[len];
		int i = 0;
		EapTLSUtil.copyArray(totalMsg, 0, tmp, i, totalMsg.length);
		i += totalMsg.length;
		EapTLSUtil.copyArray(sender, 0, tmp, i, sender.length);
		i += sender.length;
		EapTLSUtil.copyArray(adapter.getSecurityKey().masterKey, 0, tmp, i, adapter.getSecurityKey().masterKey.length);
		i += adapter.getSecurityKey().masterKey.length;
		EapTLSUtil.copyArray(pad1, 0, tmp, i, pad1.length);
		byte[] hash = EapTLSHashMacUtil.hashMac(EapTLSHashMacUtil.HASH_MD5, tmp);
		//md5
		len = adapter.getSecurityKey().masterKey.length + pad2.length + hash.length;
		tmp = new byte[len];
		i = 0;
		EapTLSUtil.copyArray(adapter.getSecurityKey().masterKey, 0, tmp, i, adapter.getSecurityKey().masterKey.length);
		i += adapter.getSecurityKey().masterKey.length;
		EapTLSUtil.copyArray(pad2, 0, tmp, i, pad2.length);
		i += pad2.length;
		EapTLSUtil.copyArray(hash, 0, tmp, i, hash.length);
		return EapTLSHashMacUtil.hashMac(EapTLSHashMacUtil.HASH_MD5, tmp);
	}
	
	/**
	 * 生成sha概要，外部可调用
	 * @param adapter
	 * @param cs
	 * @return
	 */
	public static byte[] generateHashSHA(EapTLSHandlerAdapter adapter, long cs) {
		byte[] sender = new byte[4];
		EapTLSUtil.convertIntegerToByte(sender, 0, cs);
		byte[] totalMsg = adapter.getSecurityKey().msgTotalBufferToByte();
		byte[] pad1 = EapTLSUtil.generatePad1(40);
		byte[] pad2 = EapTLSUtil.generatePad2(40);
		int len = totalMsg.length + sender.length + 
				  adapter.getSecurityKey().masterKey.length + pad1.length;
		byte[] tmp = new byte[len];
		int i = 0;
		EapTLSUtil.copyArray(totalMsg, 0, tmp, i, totalMsg.length);
		i += totalMsg.length;
		EapTLSUtil.copyArray(sender, 0, tmp, i, sender.length);
		i += sender.length;
		EapTLSUtil.copyArray(adapter.getSecurityKey().masterKey, 0, tmp, i, adapter.getSecurityKey().masterKey.length);
		i += adapter.getSecurityKey().masterKey.length;
		EapTLSUtil.copyArray(pad1, 0, tmp, i, pad1.length);
		byte[] hash = EapTLSHashMacUtil.hashMac(EapTLSHashMacUtil.HASH_SHA1, tmp);
		//sha
		len =adapter.getSecurityKey().masterKey.length + pad2.length + hash.length;
		tmp = new byte[len];
		i = 0;
		EapTLSUtil.copyArray(adapter.getSecurityKey().masterKey, 0, tmp, i, adapter.getSecurityKey().masterKey.length);
		i += adapter.getSecurityKey().masterKey.length;
		EapTLSUtil.copyArray(pad2, 0, tmp, i, pad2.length);
		i += pad2.length;
		EapTLSUtil.copyArray(hash, 0, tmp, i, hash.length);
		return EapTLSHashMacUtil.hashMac(EapTLSHashMacUtil.HASH_SHA1, tmp);
	}

	private void generateHash() {
		this.md5 = generateHashMD5(this.adapter,server);
		this.sha = generateHashSHA(this.adapter,server);
	}

	/**
	 * 将数据组成协议格式
	 * 
	 * @param content
	 */
	@Override
	protected void combineBody() {
		this.content = new byte[36];
		EapTLSUtil.copyArray(this.md5, 0, this.content, 0,
				this.md5.length);
		EapTLSUtil.copyArray(this.sha, 0, this.content, 16,
				this.sha.length);
	}
	

	@Override
	public String toString() {
		return  "EapTLSServerFinishedMsg: \r\n" +
				"Version:" + this.maxVersion + "." + this.minVersion + "\r\n"
				+ "MD5:" + EapTLSUtil.formatByteHex(this.md5) + "\r\n"
				+ "SHA:" + EapTLSUtil.formatByteHex(this.sha) + "\r\n";
	}
	
}
