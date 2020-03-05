package cn.rdtimes.tls.util;

/**
 * 工具类
 * 
 * @author BZ
 * Date:2015-10-13
 */

public final class EapTLSUtil {
	
	/**
	 * 拷贝数组
	 * @param src  源数组
	 * @param start	源数组开始位置
	 * @param dest	目标数组
	 * @param dstart 目标数组开始位置
	 * @param length 拷贝的长度
	 */
	public static void copyArray(byte[] src, int start, byte[] dest,
			int dstart, int length) {
		int j = start;
		for (int i = dstart; i < dstart + length; i++, j++)
			dest[i] = src[j];
	}

	/**
	 * 将网络字节序转换成短整形
	 * @param buf 字节序数组
	 * @param start 开始位置
	 */
	public static int convertShot(byte[] buf, int start) {
		int ret = 0;
		int temp =  (buf[start] & 0xff);
		ret = temp;
		temp = (buf[start + 1] & 0xff);
		ret = (ret << 8);
		ret = (ret | temp);
		return ret;
	}

	/**
	 * 将网络字节序转换成整形
	 * @param buf 字节序数组
	 * @param start 开始位置
	 */
	public static long convertInteger(byte[] buf, int start) {
		long ret = 0;
		long temp = buf[start] & 0xff;
		ret = temp;
		temp = buf[start + 1] & 0xff;
		ret = ret << 8;
		ret = ret | temp;
		temp = buf[start + 2] & 0xff;
		ret = ret << 8;
		ret = ret | temp;
		temp = buf[start + 3] & 0xff;
		ret = ret << 8;
		ret = ret | temp;
		return ret;
	}
	public static int convert3Integer(byte[] buf, int start) {
		int ret = 0;
		int temp = buf[start] & 0xff;
		ret = temp;
		temp = buf[start + 1] & 0xff;
		ret = ret << 8;
		ret = ret | temp;
		temp = buf[start + 2] & 0xff;
		ret = ret << 8;
		ret = ret | temp;
		
		return ret;
	}
	
	/**
	 * 将整形转换成网络字节流序
	 * @param b 转换后的字节数组
	 * @param value 被转换的整形
	 */
	public static void convertIntegerToByte(byte b[], int start, long value) {
		b[start + 3] = (byte) (value & 0xff);
		b[start + 2] = (byte) ((value & 0xff00) >>> 8);
		b[start + 1] = (byte) ((value & 0xff0000) >>> 16);
		b[start + 0] = (byte) ((value & 0xff000000) >>> 24);
	}
	public static void convertIntegerTo3Byte(byte b[], int start, int value) {
		b[start + 2] = (byte) (value & 0xff);
		b[start + 1] = (byte) ((value & 0xff00) >>> 8);
		b[start + 0] = (byte) ((value & 0xff0000) >>> 16);
	}
	public static void convertLongToByte(byte b[], int start, long value) {
		b[start + 7] = (byte) (value & 0xff);
		b[start + 6] = (byte) ((value & 0xff00) >>> 8);
		b[start + 5] = (byte) ((value & 0xff0000) >>> 16);
		b[start + 4] = (byte) ((value & 0xff000000) >>> 24);
		b[start + 3] = (byte) ((value & 0xff00000000L) >>> 32);
		b[start + 2] = (byte) ((value & 0xff000000000L) >>> 40);
		b[start + 1] = (byte) ((value & 0xff0000000000L) >>> 48);
		b[start + 0] = (byte) ((value & 0xff000000000000L) >>> 56);
	}

	/**
	 * 将短整形转换成网络字节流序
	 * @param b 转换后的字节数组
	 * @param value 被转换的短整形
	 */
	public static void convertShortToByte(byte b[], int start, int value) {
		b[start + 1] = (byte) (value & 0xff);
		b[start + 0] = (byte) ((value & 0xff00) >>> 8);
	}
	
	/**
	 * 将byte转换成无符号整形
	 * @param value
	 * @return
	 */
	public static int convertByteToInteger(byte value) {
		return (value & 0xFF);
	}
	
	/**
	 * 将字节数组转换成十六进制
	 * @param value
	 * @return
	 */
	public static StringBuffer formatByteHex(byte[] value) {
		StringBuffer sb = new StringBuffer();
		if (value == null || value.length == 0) return sb;
		
        for (int i = 0; i < value.length; i++) {
        	if (i > 0) sb.append(" ");
        	sb.append(Integer.toString((value[i] & 0xff) + 0x100, 16).substring(1));
        }
        
        return sb;
	}
	
	public static String formatByteHex(byte value) {
		return Integer.toString((value & 0xff) + 0x100, 16).substring(1);
	}
	
	/**
	 * 生成指定长度（40或48）的pad1数据
	 * @param length
	 * @return
	 */
	public static byte[] generatePad1(int length) {
		byte[] b = new byte[length];
		for(int i = 0; i < length; i++) {
			b[i] = 0x36;
		}
		
		return b;
	}

	/**
	 * 生成指定长度（40或48）的pad2数据
	 * @param length
	 * @return
	 */
	public static byte[] generatePad2(int length) {
		byte[] b = new byte[length];
		for(int i = 0; i < length; i++) {
			b[i] = 0x5c;
		}
		
		return b;
	}
	
	/**
	 * 比较两个数组是否相等
	 * @param src  源数组
	 * @param dest 目标数组
	 * @return true-相同
	 */
	public static boolean compareBytes(byte[] src, byte[] dest) {
		if (src == null && dest == null) return true;
		if (src == null || dest == null) return false;
		if (src.length != dest.length) return false;
		
		boolean eq = true;
		for(int i = 0; i < src.length; i++) {
			if (src[i] != dest[i]) {
				eq = false;
				break;
			}
		}
		if (eq) return true;
		else return false;
	}
	
}
