package cn.rdtimes.tls.security;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;


/**
 * RC4º”√‹∫ÕΩ‚√‹.
 * 
 * @author BZ
 * Date:2015-10-20
 */
public final class EapTLSCipherRC4 {
	private final static String ALG_RC4 = "RC4";			//key=16
	
    private Cipher cipher ;
    private SecureRandom random = null;
    
    public EapTLSCipherRC4(byte[] key, SecureRandom random, boolean encrypt) {
    	try {
    		SecretKey securekey = new SecretKeySpec(key, ALG_RC4);
    		
            this.cipher = Cipher.getInstance(ALG_RC4);;
            int mode = encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
            if (random == null) {
                random = new SecureRandom();
            }
            this.random = random;

            cipher.init(mode, securekey, this.random);
        } catch (Exception e) {
            e.printStackTrace();
        } 
    }
    
    public byte[] decrypt(byte[] data) {
    	if (this.cipher == null) return null;
    	
    	byte[] output = new byte[data.length];
    	try {
			this.cipher.update(data, 0, data.length, output, 0);
			return output;
		} catch (ShortBufferException e) {
			e.printStackTrace();
			return null;
		}
    }
    
    public byte[] encrypt(byte[] data) {
    	if (this.cipher == null) return null;
    	
    	byte[] output = new byte[data.length];
    	try {
			this.cipher.update(data, 0, data.length, output, 0);
			return output;
		} catch (ShortBufferException e) {
			e.printStackTrace();
			return null;
		}
    	
    }
    
}
