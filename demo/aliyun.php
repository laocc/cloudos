<?php

use laocc\cloudos\Aliyun;

function aliyunPost()
{
    $config = [
        'id' => '****',
        'secret' => '****',
        'endpoint' => '****',
    ];
    $config['callback'] = 'https://api.domain.cn/oss/aliyun/';
    $config['ttl'] = 60;
    $config['dir'] = 'face';
    $config['bucket'] = 'bucket';

    $aliyun = new Aliyun();
    $response = $aliyun->signature($config, $_POST);
    $info = pathinfo($_POST['file']['path']);

    $response['filename'] = $response['dir'] . "123456789." . $info['extension'];

    $ossData = [
        'key' => $response['filename'],
        'policy' => $response['policy'],
        'OSSAccessKeyId' => $response['accessid'],
        'signature' => $response['signature'],
        'callback' => $response['callback'],
        'success_action_status' => '200',
    ];

    return ['host' => $response['host'], 'data' => $ossData];
}

/**
 * 系统内直传，删除
 *
 * @param $action
 */
function ossCli($action)
{
    $conf = [
        'id' => '****',
        'secret' => '****',
        'endpoint' => '****',
    ];
    $conf['bucket'] = 'bucket';

    $aliyun = new Aliyun();

    switch ($action) {
        case 'upload':
            $file = [];
            $file['name'] = 'exampledir/exampleobject.txt';
            $file['path'] = _RUNTIME . '/sess0.txt';
            $up = $aliyun->upload($conf, $file);
            print_r($up);
            break;
        case 'delete':
            $file = 'exampledir/exampleobject.txt';
            $up = $aliyun->delete($conf, $file);
            print_r($up);
            break;
    }

    var_dump($action);
}