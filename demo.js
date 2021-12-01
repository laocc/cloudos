uni.uploadFile({
    url: oss.host,
    filePath: res.tempFiles[0].path,
    fileType: res.tempFiles[0].ext,
    name: 'file',
    formData: {
        key: getFileName(res.tempFiles[0].path), //文件名
        policy: oss.policy, //后台获取超时时间
        OSSAccessKeyId: oss.accessid, //后台获取临时ID
        signature: oss.signature, //后台获取签名
        callback: oss.callback, //后台获取签名
        success_action_status: '200', //让服务端返回200,不然，默认会返回204
    },
    success: resu => {
        console.log(resu);
    },
    fail: erru => {
        console.log(erru);
    }
});
