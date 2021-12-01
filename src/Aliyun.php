<?php

namespace laocc\cloudos;

class Aliyun
{

    public function callback()
    {
        // 1.获取OSS的签名header和公钥url header
        $authorizationBase64 = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        $pubKeyUrlBase64 = $_SERVER['HTTP_X_OSS_PUB_KEY_URL'] ?? '';
        if ($authorizationBase64 == '' || $pubKeyUrlBase64 == '') return 'Forbidden';

        // 2.获取OSS的签名
        $authorization = base64_decode($authorizationBase64);

        // 3.获取公钥
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, base64_decode($pubKeyUrlBase64));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
        $pubKey = curl_exec($ch);
        if (empty($pubKey)) return 'fail pubKey';

        // 4.获取回调body
        $body = file_get_contents('php://input');

        // 5.拼接待签名字符串
        $authStr = '';
        $path = $_SERVER['REQUEST_URI'];
        $pos = strpos($path, '?');
        if ($pos === false) {
            $authStr = urldecode($path) . "\n" . $body;
        } else {
            $authStr = urldecode(substr($path, 0, $pos)) . substr($path, $pos, strlen($path) - $pos) . "\n" . $body;
        }

        // 6.验证签名
        $ok = openssl_verify($authStr, $authorization, $pubKey, OPENSSL_ALGO_MD5);
        if ($ok == 1) {
            return json_decode($body, true);
        }

        return 'sign error';
    }


    /**
     * @param array $config
     * @return array
     */
    public function signature(array $config): array
    {
        $cBody = [
            'bucket' => '${bucket}',
            'etag' => '${etag}',
            'url' => '${url}',
            'filename' => '${object}',
            'size' => '${size}',
            'mimeType' => '${mimeType}',
            'width' => '${imageInfo.width}',
            'height' => '${imageInfo.height}',
        ];
        $callback_param = array(
            'callbackUrl' => $config['callback'],
            'callbackBody' => urldecode(http_build_query($cBody)),
            'callbackBodyType' => "application/x-www-form-urlencoded"
        );
        $base64_callback_body = base64_encode(json_encode($callback_param, 320));
        $expire = time() + ($config['ttl'] ?? 60);

        $config['dir'] = '/' . trim($config['dir'], '/') . '/';


        $conditions = [];
        //最大文件大小.用户可以自己设置，2个1024=1M
        $conditions[] = ['content-length-range', 0, 1024 * 1024 * 10];

        // 表示用户上传的数据，必须是以$dir开始，不然上传会失败，这一步不是必须项，
        //只是为了安全起见，防止用户通过policy上传到别人的目录。
        $conditions[] = ['starts-with', '$key', $config['dir']];

        $arr = array(
            'expiration' => str_replace('+00:00', '.000Z', gmdate('c', $expire)),
            'conditions' => $conditions
        );
        $base64_policy = base64_encode(json_encode($arr, 320));
        $signature = base64_encode(hash_hmac('sha1', $base64_policy, $config['secret'], true));

        $response = array();
        $response['accessid'] = $config['id'];
        $response['host'] = $config['host'];
        $response['policy'] = $base64_policy;
        $response['signature'] = $signature;
        $response['expire'] = $expire;
        $response['callback'] = $base64_callback_body;
        $response['dir'] = $config['dir'];  // 这个参数是设置用户上传文件时指定的前缀。
        return $response;
    }


}