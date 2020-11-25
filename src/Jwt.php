<?php
namespace JwtPhp;

/**
 * Class Jwt
 *
 * Jwt php lib to do jwt job.
 * @author linwanfeng
 * @package JwtPhp
 */
class Jwt
{
    //************************************************************加密信息所需方法
    /**
     * generate jwt string
     * @throws \Exception 请捕获
     */
    public function genSignature()
    {
        if (empty($this->secret) || empty($this->exp) || empty($this->iat) || $this->exp<$this->iat) {//not empty var
            throw new \Exception('secret and exp and iat must not be empty. exp>iat');
        }
        $sign['header'] = base64_encode($this->header);
        $payload['iss'] = $this->iss;
        $payload['sub'] = $this->sub;
        $payload['aud'] = $this->aud;
        $payload['exp'] = $this->exp;
        $payload['nbf'] = $this->nbf;
        $payload['iat'] = $this->iat;
        $payload['jti'] = $this->jti;
        $payload = array_merge($payload, $this->publicPayload);
        $sign['payload'] = base64_encode(\json_encode($payload));
        $sign['sign'] = hash_hmac('sha256', $sign['header'].md5($sign['payload']).$sign['payload'], $this->secret);//不采用jwt算法
        return \implode('.', $sign);
    }
    /**
     * @param string $secret hmac密钥
     */
    public function setSecret($secret)
    {
        $this->secret = $secret;
    }
    /**
     * @param string $iss jwt签发者
     */
    public function setIss($iss)
    {
        $this->iss = $iss;
    }
    /**
     * @param string $sub jwt所面向的用户
     */
    public function setSub($sub)
    {
        $this->sub = $sub;
    }
    /**
     * @param string $aud 接收jwt的一方
     */
    public function setAud($aud)
    {
        $this->aud = $aud;
    }
    /**
     * @param string $exp jwt的过期时间，这个过期时间必须要大于签发时间
     */
    public function setExp($exp)
    {
        $this->exp = $exp;
    }
    /**
     * @param int $nbf 定义在什么时间之前，该jwt都是不可用的.
     */
    public function setNbf($nbf)
    {
        $this->nbf = $nbf;
    }
    /**
     * @param int $iat jwt的签发时间
     */
    public function setIat($iat)
    {
        $this->iat = $iat;
    }
    /**
     * @param string $jti jwt的唯一身份标识，主要用来作为一次性token,从而回避重放攻击。
     */
    public function setJti($jti)
    {
        $this->jti = $jti;
    }

    /**
     * @param array $publicPayload 公共信息
     * @throws \Exception 请捕获
     */
    public function setPublicPd($publicPayload)
    {
        if (!is_array($publicPayload)) {
            throw new \Exception('publicPayload must be array');
        }

        $this->publicPayload = $publicPayload;
    }
    //*************************************************************解密信息所需方法

    /**
     * 验证并解密jwt信息
     * @param string $sign 签名信息
     * @return string
     * @throws \Exception
     */
    public function vailDecSign($sign)
    {
        if (empty($this->secret)) {//not empty var
            throw new \Exception('secret must not be empty');
        }
        $data = explode('.', $sign);
        if (hash_hmac('sha256', $data[0].md5($data[1]).$data[1], $this->secret) === $data[2]) {
            $this->recPayload = \json_decode(base64_decode($data[1]), true);
            return true;
        } else {
            return false;
        }
    }
    /**
     * @return string  jwt签发者
     */
    public function getIss()
    {
        return $this->iss;
    }
    /**
     * @return string  jwt所面向的用户
     */
    public function getSub()
    {
        return $this->sub;
    }
    /**
     * @return string 接收jwt的一方
     */
    public function getAud()
    {
        return $this->aud;
    }
    /**
     * @return string  jwt的过期时间，这个过期时间必须要大于签发时间
     */
    public function getExp()
    {
        return $this->exp;
    }
    /**
     * @return int  定义在什么时间之前，该jwt都是不可用的.
     */
    public function getNbf()
    {
        return $this->nbf;
    }
    /**
     * @return int  jwt的签发时间
     */
    public function getIat()
    {
        return $this->iat;
    }
    /**
     * @return string  jwt的唯一身份标识，主要用来作为一次性token,从而回避重放攻击。
     */
    public function getJti()
    {
        return $this->jti;
    }
    /**
     * @param string $key 公共信息key
     * @return  mixed  公共信息
     */
    public function getRecPd($key = null)
    {
        if ($key==null) {
            return $this->recPayload;
        } else {
            return isset($this->recPayload[$key])?$this->recPayload[$key]:false;
        }
    }
    //**************************************************私有变量
    private $secret;//hmac密钥

    private $iss = '';//jwt签发者
    private $sub = '';//jwt所面向的用户
    private $aud = '';//接收jwt的一方
    private $exp = '';//jwt的过期时间，这个过期时间必须要大于签发时间
    private $nbf = '';//定义在什么时间之前，该jwt都是不可用的.
    private $iat = '';//jwt的签发时间
    private $jti = '';//jwt的唯一身份标识，主要用来作为一次性token,从而回避重放攻击。

    private $publicPayload = [];//公共信息
    private $recPayload;//接收到的信息
    private $header = '{"typ":"JWT","alg":"HS256"}';//头部信息


}