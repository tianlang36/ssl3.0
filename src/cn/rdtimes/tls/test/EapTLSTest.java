package cn.rdtimes.tls.test;


import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.junit.Test;

import cn.rdtimes.tls.msg.*;
import cn.rdtimes.tls.security.*;
import cn.rdtimes.tls.util.*;

//import javax.crypto.Mac;

/**
 * 功能测试类
 * 
 * @author BZ
 *
 */

public class EapTLSTest {

	@Test
	public void test() {
		EapTLSRecordType rt = EapTLSRecordType.APPLICATION_DATA;
		
		System.out.println(rt);
		rt = EapTLSRecordType.valueOf((byte)20);
		System.out.println(rt);
		
		EapTLSRecordMsg msg = new EapTLSRecordMsg();
		System.out.println(msg);
	}
	
	@Test
	public void testCertificate() {
		String keystore = "C:/Users/Administrator/.keystore";
		String certFileName = "D:/rdtimescert.crt";
		
		X509Certificate cert = EapTLSCertUtil.getX509CertificateFromFile(certFileName);
		EapTLSCertUtil.printX509Certificate(cert);
		
		X509Certificate cert1 = EapTLSCertUtil.getX509CertificateFromKeyStore(keystore, "123456", "rdtimes");
		EapTLSCertUtil.printX509Certificate(cert1);
		
		byte[] b = EapTLSCertUtil.getX509CertificateBytes(certFileName);
		System.out.println("Length:" + b!=null?b.length:0);
		
		PrivateKey pk = EapTLSCertUtil.getPriveKeyFromKeyStore(keystore, "123456", "rdtimes", "123456");
		if (pk != null) {
			System.out.println("Alg:" + pk.getAlgorithm());
			System.out.println("Format:" + pk.getFormat());
			System.out.println("Encode:" + pk.getEncoded());
		}
		
		byte[] msg = "1234567".getBytes();
		byte[] sig = EapTLSCertUtil.getSignatureByPrivateKey(EapTLSCertUtil.SIGNATURE_ALG_SHA1RSA, pk, msg);
		boolean f = EapTLSCertUtil.verifySignature(EapTLSCertUtil.SIGNATURE_ALG_SHA1RSA, cert1, msg, sig);
		if (f) System.out.println("Sig Success");
		else System.out.println("Sig failure");
	}
	
	@Test
	public void testDES() {
		String msg = "123456789";
		String key = "123456781234567812345678"; //密钥长度必须是8的倍数
		byte[] enc = EapTLSDESUtil.encrypt(msg.getBytes(), key.getBytes(),EapTLSDESUtil.ALG_DESEDE);
		System.out.println(new String(enc));
		byte[] dec = EapTLSDESUtil.decrypt(enc, key.getBytes(),EapTLSDESUtil.ALG_DESEDE);
		System.out.println(new String(dec));
		
		String key1 = "1234567812345678";
		byte[] enc1 = EapTLSDESUtil.encrypt(msg.getBytes(), key1.getBytes(),EapTLSDESUtil.ALG_RC4);
		System.out.println(new String(enc1));
		byte[] dec1 = EapTLSDESUtil.decrypt(enc1, key1.getBytes(),EapTLSDESUtil.ALG_RC4);
		System.out.println(new String(dec1));
		
		System.out.println(EapTLSUtil.formatByteHex(EapTLSHashMacUtil.hashMac(EapTLSHashMacUtil.HASH_MD5, msg.getBytes())));
		System.out.println(EapTLSUtil.formatByteHex(EapTLSHashMacUtil.hashMac(EapTLSHashMacUtil.HASH_SHA1, msg.getBytes())));
	}
	
	@Test
	public void testDigest() throws NoSuchAlgorithmException {
		//SHA1:20个概要字节
		//SHA-256:32个概要字节
		//MD5:16个概要字节
		MessageDigest md = MessageDigest.getInstance("MD5");
        
        byte[] dataBytes = "12345678".getBytes();
     
        md.update(dataBytes, 0, dataBytes.length);
        
        byte[] mdbytes = md.digest();
        
        System.out.println(mdbytes.length);
     
        //convert the byte to hex format method 1
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < mdbytes.length; i++) {
          sb.append(Integer.toString((mdbytes[i] & 0xff) + 0x100, 16).substring(1));
        }

        System.out.println("Hex format : " + sb.toString());
        
       //convert the byte to hex format method 2
        StringBuffer hexString = new StringBuffer();
    	for (int i=0;i<mdbytes.length;i++) {
    	  hexString.append(Integer.toHexString(0xFF & mdbytes[i]));
    	}

    	System.out.println("Hex format : " + hexString.toString());
    	
	}
	
	@Test
	public void testConvert() {
		byte[] b = new byte[3];
		b[0] = 0;b[1] = 0;b[2] = -77;
		int l = EapTLSUtil.convert3Integer(b, 0);
		System.out.println(l);
	}
	
	@Test
	public void testClientMac() {
//		EapTLSHashMacUtil.verifyClientMAC(EapTLSMACAlgorithm.SHA, 
//			new byte[] {0x02,(byte)0xdb,(byte)0xe2,(byte)0xf8,0x76,(byte)0xb8,0x3a,0x3f,0x5e,(byte)0x93,0x68,
//						(byte)0xcf,(byte)0x93,0x3d,(byte)0xd5,(byte)0xf0,(byte)0x80,0x14,0x21,0x13},
//			1,7,
//			new byte[] {0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x0D, 0x0A},
//			      null,EapTLSRecordType.APPLICATION_DATA);
		byte[] buff = new byte[]{0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x0D, 0x0A, (byte)0xcd, 0x40, (byte)0xa3, 0x57, (byte)0xd8, 
		                       (byte)0xe5, (byte)0xaf,(byte)0xf4, (byte)0xee, 0x1f, (byte)0xfb, 0x51, 0x2b, (byte)0xdf, 
		                       0x44, 0x21, (byte)0xcf, 0x30, 0x45, (byte)0xd6};
		byte[] clientKey = new byte[] {0x44, (byte)0x91, 0x43, 0x1D, 0x09, (byte)0x84, (byte)0x8E, 0x6A, 0x56, 
									(byte)0xF8, (byte)0xE6, (byte)0xDC, (byte)0x71, (byte)0xD8, (byte)0xB2, (byte)0x94};
//		byte[] serverKey = new byte[] {0x71, (byte)0xEB, 0x1C, (byte)0x96, (byte)0xBF, (byte)0xDD, 0x39, 0x0F, 0x20, 
//								(byte)0xEF, (byte)0x90, (byte)0xD8, 0x6E, 0x01,(byte) 0x94, (byte)0xE5};
							
//		byte[] clientRandom = new byte[] {0x56, 0x1E, 0x45, (byte)0x8C, 0x1C, 0x03, (byte)0xFB, 0x40,
//										  (byte)0xBA, 0x3F, 0x77, 0x76, 0x41, (byte)0xE9, (byte)0x84,
//										  0x58, (byte)0xDC, (byte)0xAD, (byte)0xC6, 0x6A, (byte)0xB9, 
//										  0x0E, 0x10, (byte)0xBE, (byte)0xB2, (byte)0xA0, 0x35, (byte)0xD5,
//										  0x55, (byte)0xBC, (byte)0xF3, (byte)0xF7};
		
		byte[] tmp = EapTLSDESUtil.encrypt(buff, clientKey, EapTLSDESUtil.ALG_RC4);
		System.out.println(EapTLSUtil.formatByteHex(tmp));
		
		//17 03 00 00 1B 8E 87 E0   9D 14 C0 6E 7A 89 46 38
		//B3 70 7A 22 71 08 D4 BB   CE C8 C5 55 52 C6 01 0D
		
	}
	
}
