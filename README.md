中国移动通行证开放平台Python SDK
========

本项目是基于[httplib2][HTTPLIB2]开发的移动通行证平台Python SDK开发包；支持所有官方提供的API，可用于网站接入型应用和普通应用开发。

## 运行环境

* Python 2.6 / 2.7
* httplib2 [链接][HTTPLIB2]
* Flask(example) [链接][FLASK]

## 使用示例

### 引入SDK
```python
from cmcc import ChinaMobile
```

### 以Falsk为例子
```python
oauth_config = {  \
    'oauth_consumer_key' : 'your oauth consumer key', \
    'oauth_app_secret'   : 'your oauth app secret' \
}
# 初始化
conn = ChinaMobile(oauth_config)
```


### 第一步: 获取Request token
```python
# 参数为oauth_callback url,可选
result = conn.get_request_token('http://127.0.0.1:5000/auth') 

# 将得到的未授权的Request Token以及对应的Request Token Secret存到session
session['oauth_token_secret'] = result['oauth_token_secret'][0]
session['oauth_token'] = result['oauth_token'][0]

# 设置使用得到的Request Token
conn.set_token(session['oauth_token'])
```


### 第二步: 请求用户授权Request Token
```python
return redirect(conn.get_authorize_url()) # 跳转授权
```


### 第三步: 使用授权后的Request Token换取Access Token
```python
# 设置token secret为第一步得到的oauth_token_secret
conn.set_token_secret(session['oauth_token_secret']) 
# 参数为第二步跳转回来的GET参数oauth_verifier
result = conn.get_access_token(request.args.get('oauth_verifier')) 

# 将得到的Access Token以及Access Token Secret存到session
session['oauth_access_token_secret'] = result['oauth_token_secret'][0]
session['oauth_access_token'] = result['oauth_token'][0]
```


### 第四步: 使用Access Token访问或修改受保护资源
```python
# 设置使用得到的Access Token
conn.set_token(session['oauth_access_token']) 
# 设置使用得到的Access Token Secret
conn.set_token_secret(session['oauth_access_token_secret']) 

# 查询个人信息api
user = conn.api_get('user/profile')
# 所有方法 api_get() api_post() api_put() api_delete()
```




[HTTPLIB2]: http://code.google.com/p/httplib2/
[FlASK]: http://flask.pocoo.org/