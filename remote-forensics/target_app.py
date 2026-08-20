#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
import hashlib, html, os, sqlite3

HOST='0.0.0.0'; PORT=8080
BASE='/srv/remote-forensics'; ASSETS=os.path.join(BASE,'assets'); DB=os.path.join(BASE,'customer_relation.db')
ADMIN_USER='admin'; ADMIN_PASS='Aa123456'; SESSION='wh838-admin-session-2026'
PROFILE_FLAG='flag{991c4becc9a979aa096b23d0065f3f02}'
CARD_HASH='2f784423cb78cc6c70144c36cb9e25c49fa6eb62192a7f543422a4c25046c3fb'
PHONE_HASH='02052ee507e920ffcac1187f4b32dfbf664f558849b6821e2e42b4cf17afbba2'
IMPORT_HASH='0066ac9361cfe37c0cc7e42b61f34edd632fe93857f6b83fa26ab0b476b2dd14'
IMPORT_AUDIT=[
('260418客户资料.xlsx','861da7fc4e7f08b71802c5ab677a9dd79aa5f0f30a1c3e3019736ecf092d131a','kf01',72,70,2,'2026-04-18 21:18:06'),
('260420客户资料.xlsx',IMPORT_HASH,'kf03',80,76,4,'2026-04-20 15:12:44'),
('260420客户资料(1).xlsx','cb07b003354a9990ca978e26576b71d35a14d5ca5a739303ef36ea40d585c2b8','kf09',80,80,0,'2026-04-20 18:47:31'),
('260421客户资料.xlsx','38c9f63b0c37c3a760548bed851f211514b18effb3d3a721ad5ce22bacb3798b','kf06',93,89,4,'2026-04-21 16:26:10')]
def h(s): return hashlib.sha256(s.encode()).hexdigest()
def init_db():
 os.makedirs(ASSETS,exist_ok=True)
 if os.path.exists(DB): os.remove(DB)
 c=sqlite3.connect(DB); q=c.cursor(); q.execute('CREATE TABLE customer_relation(customer_id TEXT PRIMARY KEY,phone_last4 TEXT,phone_sha256 TEXT,card_last4 TEXT,card_sha256 TEXT,event_date TEXT,operator TEXT,status TEXT,batch_no TEXT,amount INTEGER,note TEXT)')
 rows=[
 ('C260331018','0785',h('13900000785'),'6758',h('6217000000006758'),'2026-03-31','liu03','invalid','B260331-01',6800,'号码重复'),
 ('C260401018','0785',PHONE_HASH,'6758',CARD_HASH,'2026-04-01','test01','test','B260401-T1',100,'接口联调测试'),
 ('C260408109','0785',PHONE_HASH,'6758',h('6233000000006758'),'2026-04-08','liu05','following','B260408-04',36000,'同手机号干扰'),
 ('C260409137','0785',PHONE_HASH,'6758',CARD_HASH,'2026-04-09','liu07','completed','B260409-03',72800,'已完成'),
 ('C260409166','0785',PHONE_HASH,'1936',h('6200000000001936'),'2026-04-09','liu17','completed','B260409-04',42000,'同手机号其他卡'),
 ('C260409188','1785',h('13808881785'),'6758',h('6244000000006758'),'2026-04-09','liu11','completed','B260409-05',51000,'尾号相近'),
 ('C260412227','0785',h('13700000785'),'6758',h('6255000000006758'),'2026-04-12','liu02','invalid','B260412-06',9000,'无效数据'),
 ('C260409031','1936',h('13600001936'),'1936',h('6200000000001936'),'2026-04-09','liu17','completed','B260409-01',42000,''),
 ('C260409044','7586',h('13700007586'),'7586',h('6200000000007586'),'2026-04-09','liu70','following','B260409-02',26000,''),
 ('C260410201','0786',h('13808880786'),'6759',h('6200000000006759'),'2026-04-10','liu09','closed','B260410-01',15000,'')]
 q.executemany('INSERT INTO customer_relation VALUES (?,?,?,?,?,?,?,?,?,?,?)',rows)
 for x in ('phone_last4','phone_sha256','card_last4','card_sha256'): q.execute(f'CREATE INDEX idx_{x} ON customer_relation({x})')
 c.commit(); c.close()
STYLE='<style>body{font-family:Arial,"Microsoft YaHei",sans-serif;background:#f3f5f7;margin:0;color:#25313c}header{background:#203a59;color:white;padding:18px 28px}main{max-width:1100px;margin:25px auto;background:white;padding:25px;border-radius:8px}a{color:#1769aa;text-decoration:none}nav a{margin-right:18px}.card{border:1px solid #dce3e9;padding:15px;margin:12px 0}.muted{color:#6d7782}table{border-collapse:collapse;width:100%;font-size:13px}th,td{border:1px solid #d9e0e7;padding:8px}th{background:#eef3f7}input{padding:9px;margin:5px;width:300px}button{padding:9px 18px}.bad{color:#b42318}code{word-break:break-all;background:#eef2f5;padding:2px 4px}</style>'
def page(t,b,nav=False):
 n='<nav><a href="/admin/dashboard.php">首页</a><a href="/admin/profile.php">个人资料</a><a href="/admin/import-audit.php">数据导入审计</a><a href="/admin/backup.php">备份中心</a><a href="/admin/files.php">文件中心</a></nav><hr>' if nav else ''
 return f'<!doctype html><html><head><meta charset="utf-8"><title>{html.escape(t)}</title>{STYLE}</head><body><header><b>WH838 业务管理平台</b></header><main>{n}{b}</main></body></html>'.encode()
class H(BaseHTTPRequestHandler):
 server_version='nginx/1.24.0'
 def log_message(self,f,*a):
  with open('/var/log/wh838-access.log','a') as z:z.write(f'{self.client_address[0]} {self.log_date_time_string()} {f%a}\n')
 def out(self,b,s=200,c='text/html; charset=utf-8',hdr=None):
  self.send_response(s);self.send_header('Content-Type',c);self.send_header('Content-Length',str(len(b)))
  if hdr:
   for k,v in hdr.items():self.send_header(k,v)
  self.end_headers();self.wfile.write(b)
 def redir(self,p):self.send_response(302);self.send_header('Location',p);self.end_headers()
 def auth(self):return f'session={SESSION}' in self.headers.get('Cookie','')
 def need(self):
  if not self.auth():self.redir('/admin/login.php');return False
  return True
 def dl(self,p,n,c='application/octet-stream'):
  if not self.need():return
  if not os.path.exists(p):self.out(page('404','<h2>文件不存在</h2>'),404);return
  b=open(p,'rb').read();self.out(b,c=c,hdr={'Content-Disposition':f'attachment; filename="{n}"'})
 def do_GET(self):
  p=urlparse(self.path).path
  if p=='/':self.out(page('WH838 H5','<h2>WH838 H5 业务系统</h2><div class="card">系统运行正常。客户服务、数据同步及商家接口已连接。</div><script src="/static/app.js"></script>'));return
  if p=='/robots.txt':self.out(b'User-agent: *\nDisallow: /admin/\nDisallow: /internal/\n',c='text/plain');return
  if p=='/static/app.js':self.out(b'window.WH838={apiBase:"/api/v2/",adminBase:"/admin/",adminEntry:"login.php",build:"2026.04.3"};',c='application/javascript');return
  if p in ('/admin','/admin/'):self.redir('/admin/login.php');return
  if p=='/admin/login.php':
   if self.auth():self.redir('/admin/dashboard.php');return
   self.out(page('后台登录','<h2>测试服后台登录</h2><form method="post"><input name="username" placeholder="用户名"><br><input name="password" type="password" placeholder="密码"><br><button>登录</button></form>'));return
  if p=='/admin/dashboard.php':
   if not self.need():return
   self.out(page('后台首页','<h2>后台首页</h2><div class="card">数据中心：客户导入、业务资料与系统备份。</div>',True));return
  if p=='/admin/profile.php':
   if not self.need():return
   self.out(page('个人资料',f'<h2>个人资料</h2><table><tr><th>用户名</th><td>admin</td></tr><tr><th>个人签名</th><td><code>{PROFILE_FLAG}</code></td></tr></table>',True));return
  if p=='/admin/import-audit.php':
   if not self.need():return
   rs=''.join(f'<tr><td>{r[0]}</td><td><code>{r[1]}</code></td><td>{r[2]}</td><td>{r[3]}</td><td>{r[4]}</td><td>{r[5]}</td><td>{r[6]}</td></tr>' for r in IMPORT_AUDIT)
   self.out(page('导入审计',f'<h2>数据导入审计</h2><p class="muted">按原始文件 SHA-256 记录。</p><table><tr><th>文件</th><th>SHA-256</th><th>操作账号</th><th>总数</th><th>成功</th><th>失败</th><th>时间</th></tr>{rs}</table>',True));return
  if p=='/admin/backup.php':
   if not self.need():return
   self.out(page('备份中心','<h2>备份中心</h2><div class="card"><b>customer_relation.db</b><p>客户关联库，手机号和银行卡仅保留后四位及 SHA-256 摘要。</p><a href="/download/customer_relation.db">下载</a></div>',True));return
  if p=='/admin/files.php':
   if not self.need():return
   self.out(page('文件中心','<h2>文件中心</h2><table><tr><th>目录</th><th>文件</th></tr><tr><td>话术库</td><td><a href="/download/script.txt">1-打招呼话术.txt</a></td></tr><tr><td>客户资料</td><td>260420客户资料.xlsx（已导入，原件离线归档）</td></tr><tr><td>业绩归档</td><td><a href="/download/performance.csv">4.20业绩归档.csv</a></td></tr></table>',True));return
  if p=='/download/customer_relation.db':self.dl(DB,'customer_relation.db');return
  if p=='/download/performance.csv':self.dl(os.path.join(ASSETS,'performance_0420.csv'),'performance_0420.csv','text/csv; charset=utf-8');return
  if p=='/download/script.txt':self.dl(os.path.join(ASSETS,'1-打招呼话术.txt'),'script.txt','text/plain; charset=utf-8');return
  self.out(page('404','<h2>404</h2>'),404)
 def do_POST(self):
  if urlparse(self.path).path!='/admin/login.php':self.out(b'404',404,'text/plain');return
  n=int(self.headers.get('Content-Length','0') or 0);d=parse_qs(self.rfile.read(n).decode(errors='ignore'));u=d.get('username',[''])[0];pw=d.get('password',[''])[0]
  if u==ADMIN_USER and pw==ADMIN_PASS:
   self.send_response(302);self.send_header('Location','/admin/dashboard.php');self.send_header('Set-Cookie',f'session={SESSION}; Path=/; HttpOnly');self.end_headers();return
  self.out(page('登录失败','<h2>测试服后台登录</h2><p class="bad">用户名或密码错误</p>'),401)
if __name__=='__main__':init_db();ThreadingHTTPServer((HOST,PORT),H).serve_forever()
