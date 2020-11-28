<?php
require "Jwt.php";
$jwt = new \JwtPhp\Jwt();
//生成签名
$jwt->setSecret("xDE}o4L1dVW+'@;P#=9]SFvVzPs'~Z");//设置密钥
//$jwt->setExp(time()-1);
//$jwt->setIat(time()-2);
//try {
//    $jwt->setPublicPd(['username' => 'linwanfeng', 'luserid' => 66666]);
//    $b = $jwt->genSignature();
//} catch (Exception $e) {
//    echo "必须传数组";
//}

//验证签名是否正确
try {
    $a = $jwt->vailDecSign("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiIiLCJleHAiOjE3MDAwMDAwMDAsImlhdCI6MCwiaXNzIjoiIiwianRpIjoiIiwibmJmIjowLCJzdWIiOiIiLCJ1c2VyaWQiOjEyMTIxLCJ1c2VybmFtZSI6InNkc2FkIn0=.1afed7f3b297f5a3d51a3ea56883e2b479fb661516d1f0289f28d2a90c174fb8");
} catch (Exception $e) {
    echo $e->getMessage();
}
if ($a===true) {
    echo "验证通过";
}else{
    echo "验证未通过";
}
//验证签名是否过期
$exp = $jwt->getRecPd('exp');//调用此方法之前必须验证token真实性
if ($exp < time()) {
    echo "token过期";
} else {
    echo "token未过期";
}
//获取用户信息
var_dump($jwt->getRecPd());
