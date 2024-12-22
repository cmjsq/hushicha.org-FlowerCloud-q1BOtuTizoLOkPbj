[合集 \- 高级前端加解密与验签实战(7\)](https://github.com)[1\.渗透测试\-前端验签绕过之SHA25612\-14](https://github.com/CVE-Lemon/p/18606207)[2\.渗透测试\-前端验签绕过之SHA256\+RSA12\-14](https://github.com/CVE-Lemon/p/18606915)[3\.渗透测试\-前端加密分析之AES12\-15](https://github.com/CVE-Lemon/p/18607483)[4\.渗透测试\-前端加密之AES加密下的SQL注入12\-15](https://github.com/CVE-Lemon/p/18608265)[5\.渗透测试\-前端加密分析之RSA加密登录（密钥来源本地）12\-21](https://github.com/CVE-Lemon/p/18620177)6\.渗透测试\-前端加密分析之RSA加密登录（密钥来源服务器）12\-21[7\.渗透测试\-前端加密分析之RSA响应加密12\-22](https://github.com/CVE-Lemon/p/18621613):[veee加速器](https://youhaochi.com)收起
本文是高级前端加解密与验签实战的第6篇文章，本系列文章实验靶场为Yakit里自带的Vulinbox靶场，本文讲述的是绕过RSA加密来爆破登录。


## 分析


这里的代码跟上文的类似，但是加密的公钥是通过请求服务端获取的


![](https://img2024.cnblogs.com/blog/2855436/202412/2855436-20241221010258053-109528556.png)


[http://127\.0\.0\.1:8787/crypto/js/rsa/generator](https://github.com)


![](https://img2024.cnblogs.com/blog/2855436/202412/2855436-20241221010259747-2012372105.png)


由于密钥是服务端生产的，服务端有公私钥信息，所以自然不需要传递公私钥了。


请求格式如下，只有被加密的内容：


![](https://img2024.cnblogs.com/blog/2855436/202412/2855436-20241221010302779-1560805770.png)


## 序列\+热加载


### 序列


打开Yakit的Web Fuzzer，点击左侧的序列
![](https://img2024.cnblogs.com/blog/2855436/202412/2855436-20241221010305869-1197929681.png)


选择从服务端获取密钥的那个数据包


![](https://img2024.cnblogs.com/blog/2855436/202412/2855436-20241221010311350-2063766194.png)


使用数据提取器提取公钥


![](https://img2024.cnblogs.com/blog/2855436/202412/2855436-20241221010313496-2019350956.png)


提取结果正常：


![](https://img2024.cnblogs.com/blog/2855436/202412/2855436-20241221010316874-1542100205.png)


再添加序列：


![](https://img2024.cnblogs.com/blog/2855436/202412/2855436-20241221010322386-96102009.png)


先把请求体置空，编写热加载代码


![](https://img2024.cnblogs.com/blog/2855436/202412/2855436-20241221010324143-1704373230.png)


### 热加载


本来之前写的是请求体格式跟上文一样，然后在热加载里请求来获取密钥，缺点也显而易见，每次登录请求都会多出了一个请求公钥的数据包，所以最后选择用Yakit的序列配合热加载标签传参来加密。


由于Yakit热加载标签只能传一个参数，这里感谢Yakit群群友**Gun**的帮助，给了我一个手动分割参数的函数。


把序列第一个请求提取到的`publicKey`变量和需要加密的数据传过去，由`splitParams`分割，然后传参给`encrypt`进行RSA加密。


序列格式：



```
{{yak(splitParams|{{p(publicKey)}}|{"username":"admin","password":"admin123","age":"20"})}}

```

热加载代码：



```
encrypt = (pemPublic, data) => {
    data = codec.RSAEncryptWithOAEP(pemPublic /*type: []byte*/, data)~
    data = codec.EncodeBase64(data)
    body = f`{"data":"${data}"}`
    return body
}

//分割传过来的参数，每个参数中间以|分隔
splitParams = (params) => {
    pairs := params.SplitN("|", 2)
    return encrypt(pairs[0], pairs[1])
}

```

执行序列，爆破成功，使用序列的好处就是只获取一次公钥即可。


![](https://img2024.cnblogs.com/blog/2855436/202412/2855436-20241221010331508-873300056.png)


### 之前的代码：


弃用代码，就不做解释了。



```
getPubkey = func(host) {
    //通过请求动态获取公钥
    rsp, req = poc.HTTP(f`GET /crypto/js/rsa/generator HTTP/1.1
Host: ${host}

    `)~
    body = poc.GetHTTPPacketBody(rsp) // 响应体
    params = json.loads(body)
    publicKey = str.ReplaceAll(params.publicKey, r"\n", "\n")
    println(publicKey)
    return publicKey
}

encryptData = (packet) => {
    body = poc.GetHTTPPacketBody(packet)
    host = poc.GetHTTPPacketHeader(packet, "Host")
    pemBytes = getPubkey(host) // 获取公钥
    println(pemBytes)

    data = codec.RSAEncryptWithOAEP(pemBytes /*type: []byte*/, body)~
    data = codec.EncodeBase64(data)

    body = f`{"data":"${data}"}`
    return string(poc.ReplaceBody(packet, body, false))
}


//发送到服务端修改数据包
// beforeRequest = func(req){
//     return encryptData(req)
// }

//调试用
packet = <<
```

 \_\_EOF\_\_

       - **本文作者：** [柠檬i](https://github.com)
 - **本文链接：** [https://github.com/CVE\-Lemon/p/18620180](https://github.com)
 - **关于博主：** 评论和私信会在第一时间回复。或者[直接私信](https://github.com)我。
 - **版权声明：** 本博客所有文章除特别声明外，均采用 [BY\-NC\-SA](https://github.com "BY-NC-SA") 许可协议。转载请注明出处！
 - **声援博主：** 如果您觉得文章对您有帮助，可以点击文章右下角**【[推荐](javascript:void(0);)】**一下。
     
