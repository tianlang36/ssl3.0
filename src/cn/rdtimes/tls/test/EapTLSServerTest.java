package cn.rdtimes.tls.test;

import org.junit.Test;

import cn.rdtimes.tls.EapTLSHandlerAdapter;
import cn.rdtimes.tls.exception.EapTLSException;
import cn.rdtimes.tls.handle.EapTLSAlertHandler;
import cn.rdtimes.tls.handle.EapTLSHandShakeHandler;
import cn.rdtimes.tls.handle.EapTLSRecordHandler;
import cn.rdtimes.tls.handle.EapTLSChangeCipherHandler;
import cn.rdtimes.tls.handle.EapTLSApplicationHandler;
import cn.rdtimes.tls.msg.EapTLSAlertLevel;
import cn.rdtimes.tls.msg.EapTLSRecordMsg;
import cn.rdtimes.tls.msg.EapTLSRecordType;
import cn.rdtimes.tls.msg.EapTLSAlertMsg;
import cn.rdtimes.tls.msg.EapTLSApplicationMsg;
import cn.rdtimes.tls.msg.EapTLSChangeCipherMsg;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * 测试程序
 * @author PC-BZ
 * 
 * Date:2015-10-23
 */
public class EapTLSServerTest {

	@Test
	public void test() {
		ServerSocket ssocket = null;
		
		try {
			ssocket = new ServerSocket(9090);
			System.out.println("server listen on port 9090...");
			
			while (true) {
				Socket socket = ssocket.accept();

				System.out.println("\r\naccept a client socket...\r\n");

				processClient(socket);
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			if (ssocket != null)
				try {
					ssocket.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
		}
	}

	private void processClient(Socket socket) {
		EapTLSHandlerAdapter adapter = new EapTLSHandlerAdapter();
		//初始化相关参数
//		adapter.setKeystore("C:/Users/PC-BZ/.keystore");
		adapter.setKeystore("C:/Users/Administrator/.keystore");
		adapter.setKeystorePwd("123456");
		adapter.setPrivatekeyPwd("123456");
		adapter.setPrivatekeyAlias("rdtimes");
		
		InputStream input = null;
		OutputStream output = null;
		try {
			input = socket.getInputStream();
			output = socket.getOutputStream();

			EapTLSRecordHandler handler = adapter.getEapTLSRecordHandler();
			handler.setInputStream(input);
			handler.setOutputStream(output);

			while (true) {
				// 1.开始分析协议内容
				EapTLSRecordMsg recordMsg = handler.parseRecordMsg();
				if (recordMsg == null) {
					System.out.println("accept record msg is null");
					break;
				}
				
//				System.out.println(recordMsg);
				
				// 2.根据类型处理
				EapTLSRecordType rt = recordMsg.getRType();
				if (rt == EapTLSRecordType.HAND_SHAKE) {
					processHandShake(adapter, recordMsg);
				} else if (rt == EapTLSRecordType.ALERT) {
					processAlter(adapter, recordMsg);
				} else if (rt == EapTLSRecordType.CHANGE_CIPHER) {
					processChagneCipher(adapter, recordMsg);
				} else if (rt == EapTLSRecordType.APPLICATION_DATA) {
					if (processApplication(adapter, recordMsg)) break;
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				if (input != null)
					input.close();
				if (output != null)
					output.close();
				socket.close();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	private void processHandShake(EapTLSHandlerAdapter adapter,
			EapTLSRecordMsg msg) throws EapTLSException {
		EapTLSHandShakeHandler handler = adapter.getEapTLSHandShakeHandler();
		handler.processHandShake(msg.getContent());
	}

	private void processAlter(EapTLSHandlerAdapter adapter, EapTLSRecordMsg msg)
			throws EapTLSException {
		EapTLSAlertHandler handler = adapter.getEapTLSAlertHandler();
		EapTLSAlertMsg alert = handler.processAlert(msg.getContent());
		
		System.out.println(alert==null?"":alert);
		
		if (alert != null && alert.getAlertLevel() == EapTLSAlertLevel.FATA) {
			fataAlert();
		}
	}

	private void processChagneCipher(EapTLSHandlerAdapter adapter,
			EapTLSRecordMsg msg) throws EapTLSException {
		EapTLSChangeCipherHandler handler = adapter
				.getEapTLSChangeCipherHandler();
		EapTLSChangeCipherMsg ccc = handler.processChangeCipher(msg
				.getContent());
		if (ccc == null) {
			fataAlert();
		}
	}

	private boolean processApplication(EapTLSHandlerAdapter adapter,
									EapTLSRecordMsg msg) throws EapTLSException {
		EapTLSApplicationHandler handler = adapter.getEapTLSApplicationHandler();
		EapTLSApplicationMsg app = handler.processApplication(msg.getContent());
		if (app == null) {
			fataAlert();
			return false;
		}
		try {
			System.out.println(new String(app.getContent(),"UTF8"));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			return false;
		}
		
		//写数据
		String test = "HTTP/1.1 200 OK\r\n";
		handler.writeAppliationMsg(test.getBytes());
		
		return true;
	}

	private void fataAlert() {
		System.out.println("*** Occur fata error,system will be exit ***");
		System.exit(1);
	}

}
