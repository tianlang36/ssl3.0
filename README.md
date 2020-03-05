# cache-mq

#### 介绍
本工程将缓存和消息队列统一定义了接口，并与接口的实现进行分离。其中实现了memcached和redis等缓存，实现了activemq、rabbitmq和kafka等消息队列。
可以在每个项目中直接引用缓存或消息队列接口即可进行开发，无需关心具体实现。如果对现有的实现不合适，可自定义重新实现，已开发的代码不会因此而修改。

#### 软件架构
cn.rdtimes.cache/mq包定义了缓存和消息队列的接口及抽象实现，可以将其独立打包供开发时使用。cn.rdtimes.imp.cache/mq包实现了缓存和消息队列各种开源项目支持的系统，可以根据使用的类型进行重新打包，以减少不必要的类。都使用工厂模式来创建、获取和销毁实例。


#### 安装教程

1.  接口定义和实现最好独立打包

#### 使用说明

1.  缓存使用：
    1）创建redis缓存实例 new RedisCache(configure)，自动注册到工厂中
    2）使用redis实例 BCacheFactory.getCacheBase("id").get("key")
    3）释放资源 BCacheFactory.shutdown()
    4）所有创建的实例都是单例模式，每个实现的name必须唯一
2.  消息队列使用：（同上）
    1）创建发送器实例 new KafkaSender(configure)，自动注册到工厂中
    2）创建接收器实例  new KafkaReceiver(configure)，自动注册到工厂中
    3）使用实例 BMQFactory.getMQSender("xxx").sendMessage()
    4）接收器需要实现ProcessNotify业务处理相关的接口
    5）释放资源 BCacheFactory.shutdown()
    6）所有创建的实例都是单例模式，每个实现的name必须唯一

#### 参与贡献

1.  天狼-BZ
2.  biz0petter@126.com
