本项目基于相关规范实现了sm2算法以及der编解码，具备sm2密钥生成、加密、解密、签名、验签等功能；
包含sm2算法实现、sm2算法测试、sm2der编解码（基于国密sm2相关结构的asn定义）、sm2算法jni封装、大数库等；
算法实现中调用了libtommath大数库、goldbar的sm3算法，以及asn1c等；
本项目可以在Mac/Linux/Windows/Android/iOS等平台编译；
本项目作者simonpang/steven.psm@gmail.com；感谢libtommath作者及goldbar :)
