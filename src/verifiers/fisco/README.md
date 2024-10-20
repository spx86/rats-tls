# Rats-TLS中FISCO BCOS链使用

1. 参照[Fisco Bcos C SDK](https://fisco-bcos-doc.readthedocs.io/zh-cn/latest/docs/sdk/c_sdk/dylibs.html)下载`libbcos-c-sdk.so`并安装到`/usr/local/lib`
  
2. 编译rats-tls
  

```shell
export CFLAGS="${CFLAGS} -fPIC"
export CXXFLAGS="${CXXFLAGS} -fPIC"

cd rats-tls

cmake -DBUILD_SAMPLES=on -DBUILD_FISCO=on -H. -Bbuild
make -C build install
```

3. 运行测试
  

```shell
cd rats-tls/build/samples/rats-tls-server
./rats-tls-server

cd rats-tls/build/samples/rats-tls-client
#替换为自己的配置路径./rats-tls-client -b <Your Fisco Bcos Config File>
./rats-tls-client -b /home/admin/inclavare-containers/rats-tls/rats-tls-fisco/rats-tls-fisco/src/verifiers/fisco/config/config.json
```

其中FISCO-BCOS相关配置请参考[Fisco-BCOS](https://fisco-bcos-doc.readthedocs.io/zh-cn/latest/index.html)官网，配置文件示例可参考`rats-tls/src/verifiers/fisco/config`

```shell
.
├── conf #Fisco Bcos配置文件，包括证书等文件
├── config.ini #Fisco Bcos配置信息
├── config.json #具体的运行配置，包括Fisco Bcos配置文件、合约配置、公私钥以及签名等路径信息
├── contract  #合约文件，用于放置合约源文件以及ABI文件
├── private #私钥存储路径
├── public #公钥存储路径
└── signature #签名文件存储路径
```
