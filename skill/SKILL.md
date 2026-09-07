---
name: proto-diag
description: 工业协议 (Modbus TCP/RTU、FINS、MELSEC、S7comm、IEC 60870-5-104、
  EtherNet/IP) 报文诊断。当用户给出 hex 报文、抓包片段、PLC 通信异常日志、pcap
  文件，或要求排查上位机/网关/PLC 通信故障时触发。日常读写数据不触发 (用 plc_read)。
---

诊断流程 (严格按序):
1. 判断协议: 只知道 IP 不知道协议时先 detect_device (并发扫标准端口→协议指纹→
   验证读, 给出可执行的 plc_read 建议); 有 pcap 时直接 parse_pcap 自动判别;
   仍无法判断时问用户 (设备型号/通信端口) 或用 parse_frame 各试一次
2. parse_frame → 读结构化字段 (先看 errors, 再对照字段值)
3. validate_frame → 逐项看 fail 项 (长度/功能码/地址边界/异常码/序号)
4. 结合上下文 (设备型号/网络拓扑/日志) 读 diagnose 报告
5. 给出修复建议后, 提醒用户复测并回报新报文, 进入闭环

报文证据三种来源, 按可用性取:
- frame_hex: 单帧, 粘贴即测
- log_snippet: 通信日志全文 (自动提取 hex 帧, 含 TX/RX 配对交叉校验)
- pcap 文件: parse_pcap → 逐流逐帧, 大批量场景首选
- 无抓包条件的在线联调: start_proxy 透明代理 (上位机→代理→真 PLC), 双向录帧后分析

钓鱼模式 (设备只能当 client 时):
- start_listener(protocol, port, mode) 起假 server → 让用户把设备指向该端口
- 优先 record_only: 收满样本后 get_listener_frames + parse_frame/diagnose 逐帧分析
- 需要观察设备容错时才用 respond_normal, 一次只改一个变量;
  inject_errors 是故障注入 (回归/语料生成用), 不要对生产设备使用
- 结束必须 stop_listener 并提醒用户恢复设备原配置

注意事项:
- 字节序陷阱: Modbus/FINS/S7 大端, MELSEC 二进制小端; 半包要先重组完整帧再解析
- 地址语义按协议而异: S7 的 count 是字节数, enip 用 tag 名字符串 (如 "alpha[0]"),
  iec104 是总召收集式读 (options.ca 公共地址)
- 不要跳过 validate 直接下结论; 异常响应帧按"设备在线但应用层拒绝"理解,
  probe 的 reachable 语义是传输层可达
- 涉及写操作 (plc_write/send_frame) 时先跟用户确认目标设备与影响面
