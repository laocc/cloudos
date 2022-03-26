<?php

namespace laocc\cloudos;

use OSS\Core\OssException;
use OSS\OssClient;

class Aliyun
{
    private $conf;

    public function __construct(array $conf = null)
    {
        $this->conf = $conf;
    }

    /**
     * 文档：
     * https://help.aliyun.com/document_detail/91771.htm?spm=a2c4g.11186623.2.12.79477d9cF4fx2C#concept-nhs-ldt-2fb
     *
     */
    public function callback()
    {
        $conf = $this->conf;
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
//            parse_str($body, $post);
            $post = json_decode($body, true);

            if (isset($conf['host'])) {
                $host = $conf['host'] . '/' . $post['filename'];
            } else {
                $host = str_replace('https://', "https://{$conf['bucket']}.", $conf['endpoint']);
            }
            $post['url'] = rtrim($host, '/') . '/' . $post['filename'];
            return $post;
        }

        return 'sign error';
    }
    /**
     * 回调参数说明：
     * https://help.aliyun.com/document_detail/31927.htm?spm=a2c4g.11186623.0.0.26882214SfEebC#concept-qp2-g4y-5db
     *
     * https://help.aliyun.com/document_detail/31989.htm?spm=a2c4g.11186623.0.0.1c945b78YJROhK#section-btz-phx-wdb
     *
     * filename=test%2F1638370894896auxdun2y0e.jpg&size=54883&mimeType=image%2Fjpeg&height=750&width=750
     *
     * (
     * [bucket] => laocctest
     * [etag] => BB3064B59606ECBDEF7E67BCE75D3A1E
     * [url] =>
     * [filename] => test/16383740968241ogjuxvm4i.jpg
     * [size] => 63029
     * [mimeType] => image/jpeg
     * [width] => 750
     * [height] => 750
     * )
     *
     * https://laocctest.oss-cn-shanghai.aliyuncs.com/test/1638374704544k3s6xjovjq.jpg
     */

    /**
     * web页面中直传OSS时，先请求签名，见demo中示例
     *
     * @param array $append
     * @return array
     */
    public function signature(array $append = []): array
    {
        $conf = $this->conf;

        $cBody = [
            'bucket' => '${bucket}',
            'etag' => '${etag}',
            'filename' => '${object}',
            'size' => '${size}',
            'mimeType' => '${mimeType}',
            'width' => '${imageInfo.width}',
            'height' => '${imageInfo.height}',
            'params' => $append,
        ];
        $callback_param = array(
            'callbackUrl' => $conf['callback'],
            'callbackBody' => preg_replace('/\"(\$\{\w+\})\"/', '\1', json_encode($cBody, 320)),
            'callbackBodyType' => "application/json"
        );
        //支持application/x-www-form-urlencoded和application/json
        $base64_callback_body = base64_encode(json_encode($callback_param, 320));
        $expire = time() + ($conf['ttl'] ?? 60);

        $conf['dir'] = trim($conf['dir'], '/') . '/';

        $conditions = [];
        //最大文件大小.用户可以自己设置，2个1024=1M
        $conditions[] = ['content-length-range', 0, 1024 * 1024 * 10];

        // 表示用户上传的数据，必须是以$dir开始，不然上传会失败，这一步不是必须项，
        //只是为了安全起见，防止用户通过policy上传到别人的目录。
        if ($conf['force'] ?? 0) {
            $conditions[] = ['starts-with', '$key', $conf['dir']];
        }

        $arr = array(
            'expiration' => str_replace('+00:00', '.000Z', gmdate('c', $expire)),
            'conditions' => $conditions
        );
        $base64_policy = base64_encode(json_encode($arr));
        $signature = base64_encode(hash_hmac('sha1', $base64_policy, $conf['secret'], true));

        $response = array();
        $response['accessid'] = $conf['id'];
        if (isset($conf['host'])) {
            $response['host'] = $conf['host'];
        } else {
            $response['host'] = str_replace('https://', "https://{$conf['bucket']}.", $conf['endpoint']);
        }
        $response['policy'] = $base64_policy;
        $response['signature'] = $signature;
        $response['expire'] = $expire;
        $response['callback'] = $base64_callback_body;
        $response['dir'] = $conf['dir'];  // 这个参数是设置用户上传文件时指定的前缀。
        return $response;
    }

    /**
     * 上传文件
     *
     * @param string $savePathName 含要保存的name文件名
     * @param string $tempFile 本地文件path路径
     * @return string|null
     */
    public function upload(string $savePathName, string $tempFile)
    {
        try {
            $ossClient = new OssClient($this->conf['id'], $this->conf['secret'], $this->conf['endpoint']);
            return $ossClient->uploadFile($this->conf['bucket'], ltrim($savePathName, '/'), $tempFile);

        } catch (OssException $e) {
            return $e->getMessage();
        }
    }

    /**
     * 保存文本为文件
     *
     * https://help.aliyun.com/document_detail/88473.html
     *
     * @param string $savePathName
     * @param string $content
     * @param array|null $option
     * @return string|null
     */
    public function save(string $savePathName, string $content, array $option = null)
    {
        try {
            $ossClient = new OssClient($this->conf['id'], $this->conf['secret'], $this->conf['endpoint']);
            return $ossClient->putObject($this->conf['bucket'], ltrim($savePathName, '/'), $content, $option);

        } catch (OssException $e) {
            return $e->getMessage();
        }
    }


    /**
     * 删除文件
     *
     * @param string $filePathName
     * @return string|null
     */
    public function delete(string $filePathName)
    {
        try {
            $ossClient = new OssClient($this->conf['id'], $this->conf['secret'], $this->conf['endpoint']);
            return $ossClient->deleteObject($this->conf['bucket'], ltrim($filePathName, '/'));

        } catch (OssException $e) {
            return $e->getMessage();
        }
    }

    /**
     * 读取文件
     *
     * @param string $filePathName
     * @return string
     */
    public function read(string $filePathName)
    {
        try {
            $ossClient = new OssClient($this->conf['id'], $this->conf['secret'], $this->conf['endpoint']);
            return $ossClient->getObject($this->conf['bucket'], ltrim($filePathName, '/'));

        } catch (OssException $e) {
            return $e->getMessage();
        }
    }

}