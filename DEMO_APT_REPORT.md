# APT 攻击模拟报告

## 1. 执行摘要
- 目标数量：3 个（a-university.edu.cn -> b-tech.com.cn -> c-vocational.edu.cn）
- 已控目标：3 个
- 攻击阶段完成：11/11
- 蓝队感知度：100/100
- 模拟开始时间：2026-05-24 14:19:22

## 2. 攻击链拓扑
[hop 0] internet --[firewall_breach]--> A
  [hop 1] A --[cross_access]--> B
    [hop 2] B --[phishing]--> C

## 3. 目标概况
  [hop 0] [已控] a-university.edu.cn — 互联网暴露（A） [firewall_breach] 权限: user
  [hop 1] [已控] b-tech.com.cn — 供应链跳板（B） (via A) [cross_access] 权限: user
  [hop 2] [已控] c-vocational.edu.cn — 社工钓鱼目标（C） (via B) [phishing] 权限: user

## 5. 蓝队对抗分析
- 最终感知度：100/100
[!] 攻击链因蓝队感知度过高而终止

## 6. 完整攻击链
[hop 0] internet --[firewall_breach]--> A
  [hop 1] A --[cross_access]--> B
    [hop 2] B --[phishing]--> C

## 7. 关键脆弱性总结
[!] [!] A 目标: 华为 USG 防火墙使用默认口令 admin/Huawei@123
[!] [!] A 目标: 信息中心跳板机明文存储了 B 单位的 VPN 配置和预共享密钥
[!] [!] B 目标: 深信服 AF 防火墙从 VPN 隧道内可访问，共用 A 的运维口令
[!] [!] C 目标: 3 名教职工点击钓鱼链接，1 人提交 OA 凭证

## 8. 加固建议
- [hop0-A] 立即修改华为 USG 防火墙默认口令，关闭管理口公网可达
- [hop0-A] 部署堡垒机替代明文 VPN 配置文件存储
- [hop1-B] 取消供应商与客户之间的 VPN 直接互通，改为按需审批
- [hop1-B] 为每个接入单位使用独立的 VPN 账号和 ACL 策略
- [hop2-C] 部署 AI 反钓鱼邮件网关，重点检测冒充领导的钓鱼邮件
- [hop2-C] 全员安全意识培训 + 钓鱼演练（每季度一次）
- [全局] 建立 SIEM 集中日志审计，A/B/C 三方互通异常告警