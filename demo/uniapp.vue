<script>

new Vue({
    methods: {

        upload() {

            uni.chooseImage({
                count: 1, //默认9
                sourceType: ['camera'], //从相册选择
                crop: {width: 800, height: 800, resize: false},
                success: (res) => {
                    let data = {used: 1, type: 1, mode: 1, file: res.tempFiles[0]};
                    this.$api.post('/upload/aliyun', data).then(
                        oss => {

                            uni.uploadFile({
                                url: oss.data.api,
                                formData: oss.data.data,

                                filePath: res.tempFiles[0].path,
                                name: 'file',

                                success: resu => {
                                    let data = JSON.parse(resu.data);
                                    console.log(data);
                                },
                                fail: erru => {
                                    console.log(erru);
                                }
                            });


                        },
                        err => {
                            console.log(err)
                        },
                    );
                }
            })

        }

    }
})

</script>