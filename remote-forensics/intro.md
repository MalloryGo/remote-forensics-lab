# Remote Forensics Lab

本页面仅提供远程勘验靶机环境，正式题目及答案提交以比赛系统为准。

- `controlplane`：参赛队远程勘验工作站
- 目标服务器：`172.30.2.2`
- 请仅对目标服务器开展题目要求范围内的远程勘验操作

环境启动后会自动初始化，通常需要约 20～60 秒。可执行：

```bash
cat /tmp/remote-forensics-setup-status.txt
```

看到 `web=ok`、`tcp_services=ok` 后即可开始。

需要使用图形化浏览器访问目标站点时，可在 Killercoda 的 **Traffic / Ports** 中打开 **8080** 端口；该端口会转发至目标服务器的 Web 服务。
