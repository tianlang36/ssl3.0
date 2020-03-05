package cn.rdtimes.tls.handle;

import cn.rdtimes.tls.EapTLSHandlerAdapter;
import cn.rdtimes.tls.exception.EapTLSException;
import cn.rdtimes.tls.msg.EapTLSChangeCipherMsg;
import cn.rdtimes.tls.msg.EapTLSClientFinishedMsg;
import cn.rdtimes.tls.msg.EapTLSClientHelloMsg;
import cn.rdtimes.tls.msg.EapTLSClientKeyExchangeMsg;
import cn.rdtimes.tls.msg.EapTLSHandShakeMsg;
import cn.rdtimes.tls.msg.EapTLSHandShakeType;
import cn.rdtimes.tls.msg.EapTLSRecordMsg;
import cn.rdtimes.tls.msg.EapTLSRecordType;
import cn.rdtimes.tls.msg.EapTLSServerCertificateMsg;
import cn.rdtimes.tls.msg.EapTLSServerDoneMsg;
import cn.rdtimes.tls.msg.EapTLSServerFinishedMsg;
import cn.rdtimes.tls.msg.EapTLSServerHelloMsg;
import cn.rdtimes.tls.security.EapTLSAlgorithmUtil;
import cn.rdtimes.tls.security.EapTLSHashMacUtil;
import cn.rdtimes.tls.security.EapTLSSecurityKey;
import cn.rdtimes.tls.util.EapTLSUtil;

/**
 * 握手协议处理器
 * 
 * @author BZ
 * Date:2015-10-23
 */
public class EapTLSHandShakeHandler extends EapTLSHandler {
	//当前握手到达的协议类型
	private EapTLSHandShakeType currState = EapTLSHandShakeType.HELLO_REQUEST;
	private EapTLSSecurityKey securityKey = null;

	public EapTLSHandShakeHandler() {}
	
	public EapTLSHandShakeHandler(EapTLSHandlerAdapter adapter) {
		this.adapter = adapter;
		this.securityKey = adapter.getSecurityKey();
	}
	
	public void setCurrState(EapTLSHandShakeType currState) {
		this.currState = currState;
	}
	
	/**
	 * 处理握手协议消息
	 * @param content
	 * @throws EapTLSException
	 */
	public void processHandShake(byte[] content) throws EapTLSException {
		//1.先分析握手协议
		EapTLSHandShakeMsg hsmsg = parseMsg(content);
		if (hsmsg.getHstype() == EapTLSHandShakeType.FINISHED) {
			processClientFinished(hsmsg);
		}
		//2.获取具体握手协议进行处理
		else {
			this.securityKey.addBytesToMsgTotalBuffer(content);
			processDetail(hsmsg);
		}
		//3.到达最后表示握手成功
		if (currState == EapTLSHandShakeType.FINISHED) {
			adapter.setHandShakeCompleted(true);
		}
	}
	
	/**
	 * 分析握手协议
	 * @param content
	 * @return
	 * @throws EapTLSException
	 */
	private EapTLSHandShakeMsg parseMsg(byte[] content) throws EapTLSException {
		EapTLSHandShakeMsg hsmsg = new EapTLSHandShakeMsg();
		//1.是否为客户端的完成消息
		if (currState == EapTLSHandShakeType.CHANGE_CIPER_SPEC) {
			hsmsg.setHstype(EapTLSHandShakeType.FINISHED);
			hsmsg.setContent(content);
			
			return hsmsg;
		}
		//2.其他握手消息
		else {
			int i = 0;
			hsmsg.setHstype(EapTLSHandShakeType.valueOf(content[i++]));
			hsmsg.setLength(EapTLSUtil.convert3Integer(content, i));
			i += 3;
			if (hsmsg.getLength() > 0) {
				byte[] buff = new byte[hsmsg.getLength()];
				EapTLSUtil.copyArray(content, i, buff, 0, buff.length);
				hsmsg.setContent(buff);
				return hsmsg;
			}
			else {
				throw new EapTLSException("EapTLSHandShakeHandler.parseMsg() HandShake content is null");
			}
		}
	}
	
	/**
	 * 处理具体的握手协议类型，主要是针对客户端类型的处理
	 * @param hsmsg
	 */
	private void processDetail(EapTLSHandShakeMsg hsmsg) throws EapTLSException {
		EapTLSHandShakeType hst = hsmsg.getHstype();
		if (hst == EapTLSHandShakeType.CLIENT_HELLO) {
			processClientHello(hsmsg);
		}else if (hst == EapTLSHandShakeType.CERTIFICATE_VERIFY) {
			///nothing.
		}else if (hst == EapTLSHandShakeType.CLIENT_KEY_EXCHANGE) {
			processClientKeyExchang(hsmsg);
		}
	}
	
	private void processClientHello(EapTLSHandShakeMsg hsmsg)  throws EapTLSException {
		//0.获取信息
		byte[] tmpbuff = hsmsg.getContent();
		//1.解析消息内容clienthello
		EapTLSClientHelloMsg msg = new EapTLSClientHelloMsg(tmpbuff);
		this.securityKey.clientRandom = msg.getRandoms();
		
//		System.out.print(msg);
		
		//2.发送serverhello消息
		EapTLSServerHelloMsg shmsg = new EapTLSServerHelloMsg();
		byte[] tmp1 = shmsg.combine();
		//2.1服务端会话id赋值等
		this.securityKey.sessionId = shmsg.getSessionId();
		this.securityKey.serverRandom = shmsg.getRandoms();
		this.securityKey.compressMethod = shmsg.getCompressionMethod();
		this.securityKey.setCipherSuite(shmsg.getCipherSuite());
		//3.发送server端证书或者发送服务器密钥交换，选择其一即可
		EapTLSServerCertificateMsg cmsg = new EapTLSServerCertificateMsg(adapter);
		byte[] tmp2 = cmsg.combine();
		//4.发一个serverdone消息
		EapTLSServerDoneMsg sdmsg = new EapTLSServerDoneMsg();
		byte[] tmp3 = sdmsg.combine();
		//5.组合消息并发送
		byte[] buff = new byte[tmp1.length + tmp2.length + tmp3.length];
		int i = 0;
		EapTLSUtil.copyArray(tmp1, 0, buff, i, tmp1.length);
		i += tmp1.length;
		EapTLSUtil.copyArray(tmp2, 0, buff, i, tmp2.length);
		i += tmp2.length;
		EapTLSUtil.copyArray(tmp3, 0, buff, i, tmp3.length);
		//5.1发送
		EapTLSRecordMsg rmsg = new EapTLSRecordMsg();
		rmsg.setRType(EapTLSRecordType.HAND_SHAKE);
		rmsg.setContent(buff);
		adapter.writeRecordMsg(rmsg);
		
		this.securityKey.addBytesToMsgTotalBuffer(buff);
		//6.设置当前状态
		this.currState = EapTLSHandShakeType.SERVER_DONE;
	}
	
	private void processClientKeyExchang(EapTLSHandShakeMsg hsmsg) throws EapTLSException {
		byte[] tmpbuff = hsmsg.getContent();
		EapTLSClientKeyExchangeMsg ckemsg = new EapTLSClientKeyExchangeMsg(tmpbuff,this.adapter);
		//1.生成主秘密
		this.securityKey.masterKey = EapTLSAlgorithmUtil.generateMasterSecret(ckemsg.getPreMasterSecret(),
																this.securityKey.clientRandom,
																this.securityKey.serverRandom);
		//2.设置状态
		this.currState = EapTLSHandShakeType.CLIENT_KEY_EXCHANGE;
		
//		System.out.println("PreMasterSecret:\r\n" + EapTLSUtil.formatByteHex(ckemsg.getPreMasterSecret()));
	}
	
	private void processClientFinished(EapTLSHandShakeMsg hsmsg) throws EapTLSException {
		//0.生成key
		EapTLSAlgorithmUtil.generateKeys(this.securityKey, this.securityKey.masterKey, 
										 this.securityKey.serverRandom, 
										 this.securityKey.clientRandom);
		this.adapter.generateReadCipher(this.securityKey.clientWriteKey);
		this.adapter.generateWriteCipher(this.securityKey.serverWriteKey);
		
//		System.out.println("clientRandom:\r\n" + EapTLSUtil.formatByteHex(this.securityKey.clientRandom));
//		System.out.println("serverRandom:\r\n" + EapTLSUtil.formatByteHex(this.securityKey.serverRandom));
//		System.out.println("masterKey:\r\n" + EapTLSUtil.formatByteHex(this.securityKey.masterKey));
//		System.out.println("clientWriteMac:\r\n" + EapTLSUtil.formatByteHex(this.securityKey.clientWriteMac));
//		System.out.println("serverWriteMac:\r\n" + EapTLSUtil.formatByteHex(this.securityKey.serverWriteMac));
//		System.out.println("clientWriteKey:\r\n" + EapTLSUtil.formatByteHex(this.securityKey.clientWriteKey));
//		System.out.println("serverWriteKey:\r\n" + EapTLSUtil.formatByteHex(this.securityKey.serverWriteKey));
		
		//1.解密数据client finished
		byte[] alg = this.adapter.getReadCipher().decrypt(hsmsg.getContent());
		if (alg == null) {
			throw new EapTLSException("EapTLSHandShakeHandler.processClientFinished() decryption is null");
		}
		byte[] head = new byte[4];
		EapTLSUtil.copyArray(alg, 0, head, 0, head.length);
		byte[] alg1 = new byte[alg.length - 4];
		EapTLSUtil.copyArray(alg, 4, alg1, 0, alg1.length);
		EapTLSClientFinishedMsg cfmsg = new EapTLSClientFinishedMsg(adapter);
		//2.分析内容
		cfmsg.parseDecryption(alg1);
		//组合验证信息
		byte[] verifyInfo = new byte[head.length + cfmsg.getContent().length];
		EapTLSUtil.copyArray(head, 0, verifyInfo, 0, head.length);
		EapTLSUtil.copyArray(cfmsg.getContent(), 0, verifyInfo, head.length, cfmsg.getContent().length);
		//验证MAC,不正确说明消息错误
		boolean b = EapTLSHashMacUtil.verifyClientMAC(this.adapter.getSecurityKey().cipherSpec.getMacAlgorithm(),
												      this.adapter.getSecurityKey().clientWriteMac,
												      this.adapter.getSecurityKey().seq_number_read,
												      verifyInfo.length, verifyInfo,
												      cfmsg.getClientHash(),cfmsg.getRType());
		if (!b) {
			throw new EapTLSException("EapTLSHandShakeHandler.processClientFinished() client finished msg verify mac error");
		}
		
		//3.解压缩
		byte[] unzip = EapTLSAlgorithmUtil.unzip(adapter.getSecurityKey(), cfmsg.getContent());
		if (unzip == null) {
			throw new EapTLSException("EapTLSHandShakeHandler.processClientFinished() unzip is null");
		}
		cfmsg.setContent(unzip);
		cfmsg.parseUnzip();
		//3.1mac验证
		if (!cfmsg.verifyClientFinished())
			throw new EapTLSException("EapTLSHandShakeHandler.processClientFinished() client finished msg verify error");
		this.adapter.getSecurityKey().seq_number_read += 1;
		
		//4.发送服务端交换密钥消息
		EapTLSChangeCipherHandler handler = this.adapter.getEapTLSChangeCipherHandler();
		EapTLSChangeCipherMsg ccmsg = handler.getEapTLSChangeCipherMsg();
		this.securityKey.seq_number_write = 0;
		//4.1构建消息
		EapTLSRecordMsg rmsg = new EapTLSRecordMsg();
		rmsg.setRType(EapTLSRecordType.CHANGE_CIPHER);
		rmsg.setContent(ccmsg.combine());
		byte[] tmp1 = rmsg.combine();
		
		//5.发送服务端完成消息
		this.adapter.getSecurityKey().addBytesToMsgTotalBuffer(verifyInfo);
		EapTLSServerFinishedMsg sfmsg = new EapTLSServerFinishedMsg(this.adapter);
		byte[] tmp2 = sfmsg.combine();
		byte[] compress = EapTLSAlgorithmUtil.zip(adapter.getSecurityKey(), tmp2);
		int len = compress.length;
		//5.1写mac信息
		byte[] mac = EapTLSHashMacUtil.serverWriteMAC(adapter.getSecurityKey().cipherSpec.getMacAlgorithm(), 
													  adapter.getSecurityKey().serverWriteMac, 
													  adapter.getSecurityKey().seq_number_write,
													  len, compress,sfmsg.getRType());
		len += mac.length;
		tmp2 = new byte[len];
		EapTLSUtil.copyArray(compress, 0, tmp2, 0, compress.length);
		EapTLSUtil.copyArray(mac, 0, tmp2, compress.length, mac.length);
		tmp2 = this.adapter.getWriteCipher().encrypt(tmp2);
		if (tmp2 == null) {
			throw new EapTLSException("EapTLSHandShakeHandler.processClientFinished() encrypt finished is null");
		}
		//5.2组合记录协议
		rmsg.setRType(EapTLSRecordType.HAND_SHAKE);
		rmsg.setContent(tmp2);
		tmp2 = rmsg.combine();
		
		//6.组合消息和发送消息
		byte[] buff = new byte[tmp1.length + tmp2.length];
		int i = 0;
		EapTLSUtil.copyArray(tmp1, 0, buff, i, tmp1.length);
		i += tmp1.length;
		EapTLSUtil.copyArray(tmp2, 0, buff, i, tmp2.length);
		//6.1发送
		adapter.writeRecordMsg(buff);
		this.securityKey.seq_number_write += 1;
		
//		System.out.println("=========Finished=========");
		
		//7.设置状态和清零
		this.currState = EapTLSHandShakeType.FINISHED;
		this.securityKey.clearMsgTotalBuffer();
	}
	
}
