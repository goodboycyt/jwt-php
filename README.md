## jwt php lib

### composer install  
`composer require linwanfeng/jwt-php`

不使用composer请参考src/JwtTest.php

### composer update
`composer update linwanfeng/jwt-php`

### 生成token
```php
<?php
use \JwtPhp\Jwt;
$jwt = new Jwt();
//生成签名
$jwt->setSecret("xDE}o4L1dVW+'@;P#=9]SFvVzPs'~Z");//设置密钥
$jwt->setExp(time()-1);
$jwt->setIat(time()-2);
try {
    $jwt->setPublicPd(['username' => 'linwanfeng', 'luserid' => 'Ahkjhkgusd']);//设置公共信息
    $b = $jwt->genSignature();//生成jwt字符串
} catch (Exception $e) {
    echo "必须传数组";
}
```
### 验证jwt字符串的真实性
```php
try {
    $a = $jwt->vailDecSign("sdhlshadhsaidhhhhhhhhhhhhhhhhhhhhhhhhhhhhhsaidh.sadsadsad.saddssssssssssssssssssssss");
} catch (Exception $e) {
}
if ($a===true) {
    echo "验证通过";
}
```
### 验证签名是否过期
```php
$exp = $jwt->isExp();//调用此方法之前必须验证token真实性,return true or false
if ($exp) {
    echo "token未过期";
} else {
    echo "token已过期";
}
```

### 获取payload信息
```php
$jwt->getRecPd();//获取全部信息
$jwt->getRecPd('username');//获取某个字段信息
```