package cn.rdtimes.tls.handle;

import java.io.InputStream;
import java.io.OutputStream;

import cn.rdtimes.tls.EapTLSHandlerAdapter;
import cn.rdtimes.tls.msg.EapTLSRecordMsg;
import cn.rdtimes.tls.msg.EapTLSRecordType;
import cn.rdtimes.tls.util.EapTLSUtil;

/**
 * 记录消息处理器
 * 
 * @author BZ
 * Date:2015-10-20
 */
public class EapTLSRecordHandler extends EapTLSHandler {
	
	private InputStream input;
	private OutputStream output;

	public EapTLSRecordHandler() {
	}

	public EapTLSRecordHandler(EapTLSHandlerAdapter adapter) {
		this.adapter = adapter;
	}
	
	/**
	 * 解析记录协议
	 * 
	 * @return 记录类型数据
	 */
	public EapTLSRecordMsg parseRecordMsg() {
		try {
			EapTLSRecordMsg msg = new EapTLSRecordMsg();
			//先读取头信息
			byte[] head = new byte[EapTLSRecordMsg.FIX_HEAD_LEN];
			int readLen = input.read(head, 0, EapTLSRecordMsg.FIX_HEAD_LEN);
			if (readLen < 0) {
				return null;
			}
			int i = 0;
			msg.setRType(EapTLSRecordType.valueOf(head[i++]));
			msg.setMaxVersion(head[i++]);
			msg.setMinVersion(head[i++]);
			msg.setLength(EapTLSUtil.convertShot(head, i));
			i += 2;
			if (msg.getLength() > 0) {
				byte[] content = new byte[msg.getLength()];
				//读取数据
				if (input.read(content,0,msg.getLength()) < 0) 
					return null;
				//设置数据
				msg.setContent(content);
			}
			return msg;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	/**
	 * 写消息
	 * @param msg
	 */
	public void writeRecordMsg(EapTLSRecordMsg msg) {
		if (msg == null || msg.getContent() == null) return;
		try {
			byte[] b = msg.combine();
			output.write(b);
		} catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	public void writeRecordMsg(byte[] msg) {
		if (msg == null) return;
		try {
			output.write(msg);
		} catch(Exception e) {
			e.printStackTrace();
		}
	}

	public InputStream getInputStream() {
		return input;
	}

	public void setInputStream(InputStream input) {
		this.input = input;
	}

	public OutputStream getOutputStream() {
		return output;
	}

	public void setOutputStream(OutputStream output) {
		this.output = output;
	}

}
