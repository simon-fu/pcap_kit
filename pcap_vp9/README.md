# 播放sdp
```
ffplay -protocol_whitelist file,udp,rtp test.sdp
```

# 样例文件
1. 文件 [h264.pcap](https://github.com/saghul/sipp-scenarios/blob/master/h264.pcap)  
    过滤条件
    ```rust
    src: "192.168.0.101:5018".parse()?,
    dst: "85.17.186.6:53134".parse()?,
    ```  

    SDP for ffplay  
    ```
    v=0
    o=ms 1 1 IN IP4 ms
    s=-
    t=0 0
    c=IN IP4 127.0.0.1
    m=video 1234 RTP/AVP 96
    a=rtpmap:96 H264/90000
    a=fmtp:96 packetization-mode=1
    ```

2. 文件名： vp9-28.pcap 或 vp9-28.zip
vp9编码问题，客户过来的格式比较复杂，我们能解包； 我们发给客户的，不能解包。  
125.211.130.237 是客户的ip，172.27.92.150是我们的ip。  

    查看SDP  
    ```
    sip.Call-ID contains 7827a5273290603b14279b2750734
    ```  

    过滤条件
    ```rust
    src: "125.211.130.237:54744".parse()?,
    dst: "172.27.92.150:16062".parse()?,
    is_reverse: true,
    ```  

    SDP for ffplay  
    ```
    v=0
    o=- 1698309908 1698309909 IN IP4 cc1
    s=-
    b=AS:1096
    t=0 0
    c=IN IP4 127.0.0.1
    m=video 1234 RTP/AVP 103
    a=rtpmap:103 VP9/90000
    ```

