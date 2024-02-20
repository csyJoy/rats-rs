# rats-rs

rats-rs是一个纯Rust的CPU-TEE SPDM远程证明和安全传输实现，它建立在[spdm-rs](https://github.com/ccc-spdm-tools/spdm-rs)之上。

**注意，这个项目目前还未达到生产可用状态，其安全性也未得到正式评估。**

在设计上，该项目尽量模块化，并通过cargo的features来进行条件编译，（现在或者未来）包含如下模块：
- `attester` / `verifier`：不同CPU TEE的证明和验证逻辑的实现
    - 现在包含了SGX-DCAP（ECDSA）的支持，由`build-mode-occlum`和`verifier-sgx-ecdsa`控制
- `crypto`：提供密码学原语的抽象接口，例如hash、非对称加密（签名）
    - 目前的提供了一个基于[RustCrypto](https://github.com/RustCrypto)的实现（通过`crypto-rustcrypto`控制），未来可以考虑提供基于[ring](https://github.com/briansmith/ring)或者[rust-openssl](https://github.com/sfackler/rust-openssl)的实现
- `cert`：提供证书的生成和签名验证实现。
    - 现在我们拥有一个符合[Interoperable RA-TLS](https://github.com/CCC-Attestation/interoperable-ra-tls)的实现（我们将其简称为dice证书），需要注意的是dice证书与[DSP0274](https://www.dmtf.org/dsp/DSP0274)中对SPDM证书的规定描述存在一定距离，例如：
        - dice证书是单一的自签名证书，而SPDM证书包含了多级证书，且包含Device/Alias/Generic三种证书模型
        - 对于代表设备的证书，SPDM对其中的一些字段有强制要求
        
        尽管如此，由于dice证书和SPDM证书的用途和目的是一致的，在目前阶段本项目中仍然使用dice证书作为SPDM协商过程中的证书格式，未来将考虑设计一种更符合SPDM证书要求的证书格式。
- `transport`：提供建立在远程证明之上的任意安全传输层（例如SPDM和TLS、DTLS）的实现。
    - 目前包含了一个基于SPDM协议的实现，能够完成握手和数据传输。    
        SPDM协议的部分基于[spdm-rs](https://github.com/ccc-spdm-tools/spdm-rs)项目，我们提供了对Requester和Responder的简易封装

        此外，spdm-rs中提供了SPDM传输层（`trait SpdmTransportEncap`）的PCIDOE和MCTP两种不同的实现。对此，我们提供了一个类似的`struct SimpleTransportEncap`实现，使用一个`u8`的tag来区分SPDM消息、受保护的SPDM消息和APP消息这三种消息。
        
        为了让SPDM协议在现有通信链路如TCP等基于上运行，我们提供了一个`struct FramedStream`实现。

        由于spdm-rs的原始实现与本项目的设计目标之间存在一些差距，我们对spdm-rs项目进行了fork和修改，主要有：
        - 调整spdm-rs的`ResponderContext::process_message()`在处理app_message时的逻辑，剔除`SpdmAppMessageHandler`。
        - 调整`max_cert_chain_data_size`，以容纳我们的dice证书（该变更不改变SPDM协议）
        - 剔除将一些全局的、类似于c的函数指针的callback实现，抽象成trait接口，例如：
            - `SecretAsymSigner`：SPDM通信方的私钥和签名逻辑，在SPDM协商阶段会使用该接口完成对给定数据的签名
            - `CertValidationStrategy`：对SPDM通信对方的证书验证的逻辑
            - `MeasurementProvider`：提供SPDM通信方的measurements

## 测试

出于时间原因，本项目目前只对部分组件提供了单元测试。

对SPDM通信的测试可以在`src/transport/spdm/responder.rs`的`test_spdm_over_tcp()`里找到。其中，`test_dummy=true`模式下通信双方使用的是spdm-rs项目中提供的虚假的x509证书；`test_dummy=false`模式下模拟的是基于远程证明的单边验证，SPDM通信双方使用的是dice证书。

> [!Note]
> `test_dummy=false`模式暂时还未在occlum SGX环境中得到测试。


## 下一目标

当前的实现仍然也存在一些缺陷需要解决：

- [ ] 增加更完备的测试，包括对更多组件的单元测试与集成测试
- [ ] 实现dice证书中的endorsements extension
- [ ] 设计适用于CPU TEE的SPDM measurements映射
- [ ] 改善当前的证书设计，提供一种更符合SPDM证书要求的证书
