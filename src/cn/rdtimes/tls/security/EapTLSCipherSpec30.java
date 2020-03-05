package cn.rdtimes.tls.security;


/**
 * 密钥说明(SSL3.0)
 * 
 * 只支持0x0005和0x0009这两种协议，0x0005做为默认协议。
 * 
 * @author BZ
 * Date:2015-09-29
 */
public final class EapTLSCipherSpec30 {
	//这里的设置默认为0x0005套件
	//算法是否有exported
	private boolean isExportable = false;
	//加密类型
	private EapTLSCipherType cipherType = EapTLSCipherType.STREAM;
	//加密算法
	private EapTLSBulkCipherAlgorithm cipherAlgorithm = EapTLSBulkCipherAlgorithm.RC4;
	//概要算法
	private EapTLSMACAlgorithm macAlgorithm = EapTLSMACAlgorithm.SHA;
	//概要算法的输出长度
	private int hashSize = 20;
	//加密密码的长度
	private int keyMaterial = 16;
	//初始化向量的长度
	private int ivSize = 0;
	
	
	public EapTLSCipherSpec30() {
		parseSuite(0);
	}
	
	public EapTLSCipherSpec30(int cipherSuite) {
		parseSuite(cipherSuite);
	}
	
	private void parseSuite(int cipherSuite) {
		if (cipherSuite <= 0) return;
		if (cipherSuite == 0x0005) {
			this.cipherType = EapTLSCipherType.STREAM;
			this.cipherAlgorithm = EapTLSBulkCipherAlgorithm.RC4;
			this.macAlgorithm = EapTLSMACAlgorithm.SHA;
			this.keyMaterial = 16;
			this.ivSize = 0;
		}else if (cipherSuite == 0x0009) {
			this.cipherType = EapTLSCipherType.BLOCK;
			this.cipherAlgorithm = EapTLSBulkCipherAlgorithm.DES;
			this.macAlgorithm = EapTLSMACAlgorithm.SHA;
			this.keyMaterial = 8;
			this.ivSize = 8;
		}
	}

	public boolean isExportable() {
		return isExportable;
	}

	public EapTLSCipherType getCipherType() {
		return cipherType;
	}

	public EapTLSBulkCipherAlgorithm getCipherAlgorithm() {
		return cipherAlgorithm;
	}

	public EapTLSMACAlgorithm getMacAlgorithm() {
		return macAlgorithm;
	}

	public int getHashSize() {
		return hashSize;
	}

	public int getKeyMaterial() {
		return keyMaterial;
	}

	public int getIvSize() {
		return ivSize;
	}
	
	@Override
	public String toString() {
		return "EapTLSCipherSpec30: \r\n" + 
			   "IsExportable:" + this.isExportable + "\r\n" +
			   "CipherType:" + this.cipherType.toString() + "\r\n" + 
			   "CipherAlgorithm:" + this.cipherAlgorithm.toString() + "\r\n" +
			   "MacAlgorithm:" + this.macAlgorithm.toString() + "\r\n" +
			   "HashSize:" + this.hashSize + "\r\n" +
			   "KeyMaterial:" + this.keyMaterial + "\r\n" +
			   "IVSize:" + this.ivSize + "\r\n" ;
	}
	
}
