package cn.rdtimes.tls.handle;

import cn.rdtimes.tls.EapTLSHandlerAdapter;

/**
 * handler处理器基类
 * 用来解析和发送各类型消息
 * 
 * @author BZ
 * Date:2015-10-20
 */
public abstract class EapTLSHandler {
	
	protected EapTLSHandlerAdapter adapter = null;

	public EapTLSHandlerAdapter getAdapter() {
		return adapter;
	}

	public void setAdapter(EapTLSHandlerAdapter adapter) {
		this.adapter = adapter;
	}
	
	
}
