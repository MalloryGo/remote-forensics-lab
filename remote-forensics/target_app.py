#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
import hashlib
import html
import json
import os
import sqlite3

HOST = '0.0.0.0'
PORT = 8080
BASE = '/srv/remote-forensics'
ASSETS = os.path.join(BASE, 'assets')
CUSTOMER_DB = os.path.join(BASE, 'customer_relation.db')
AUDIT_DB = os.path.join(BASE, 'import_audit.db')
ADMIN_USER = 'admin'
ADMIN_PASS = 'Aa123456'
SESSION = 'wh838-admin-session-2026'
LOGIN_PATH = '/administrator/login.php'
ADMIN_BASE = '/administrator/'
PROFILE_FLAG = 'flag{991c4becc9c4cb304ebc54f136051}'
CARD_HASH = '2f784423cb78cc6c70144c36cb9e25c49fa6eb62192a7f543422a4c25046c3fb'
PHONE_HASH = '02052ee507e920ffcac1187f4b32dfbf664f558849b6821e2e42b4cf17afbba2'
IMPORT_HASH = '0066ac9361cfe37c0cc7e42b61f34edd632fe93857f6b83fa26ab0b476b2dd14'


def h(value):
    return hashlib.sha256(value.encode()).hexdigest()


def init_customer_db():
    if os.path.exists(CUSTOMER_DB):
        os.remove(CUSTOMER_DB)
    con = sqlite3.connect(CUSTOMER_DB)
    cur = con.cursor()
    cur.execute('''CREATE TABLE customer_relation(
        customer_id TEXT PRIMARY KEY,
        phone_last4 TEXT,
        phone_sha256 TEXT,
        card_last4 TEXT,
        card_sha256 TEXT,
        event_date TEXT,
        operator TEXT,
        status TEXT,
        batch_no TEXT,
        amount INTEGER,
        note TEXT
    )''')
    rows = [
        ('C260331018','0785',h('13900000785'),'6758',h('6217000000006758'),'2026-03-31','liu03','invalid','B260331-01',6800,'号码重复'),
        ('C260401018','0785',PHONE_HASH,'6758',CARD_HASH,'2026-04-01','test01','test','B260401-T1',100,'接口联调测试'),
        ('C260408109','0785',PHONE_HASH,'6758',h('6233000000006758'),'2026-04-08','liu05','following','B260408-04',36000,'同手机号干扰'),
        ('C260409137','0785',PHONE_HASH,'6758',CARD_HASH,'2026-04-09','liu07','completed','B260409-03',72800,'已完成'),
        ('C260409166','0785',PHONE_HASH,'1936',h('6200000000001936'),'2026-04-09','liu17','completed','B260409-04',42000,'同手机号其他卡'),
        ('C260409188','1785',h('13808881785'),'6758',h('6244000000006758'),'2026-04-09','liu11','completed','B260409-05',51000,'尾号相近'),
        ('C260412227','0785',h('13700000785'),'6758',h('6255000000006758'),'2026-04-12','liu02','invalid','B260412-06',9000,'无效数据'),
        ('C260409031','1936',h('13600001936'),'1936',h('6200000000001936'),'2026-04-09','liu17','completed','B260409-01',42000,''),
        ('C260409044','7586',h('13700007586'),'7586',h('6200000000007586'),'2026-04-09','liu70','following','B260409-02',26000,''),
        ('C260410201','0786',h('13808880786'),'6759',h('6200000000006759'),'2026-04-10','liu09','closed','B260410-01',15000,'')
    ]
    cur.executemany('INSERT INTO customer_relation VALUES (?,?,?,?,?,?,?,?,?,?,?)', rows)
    for col in ('phone_last4','phone_sha256','card_last4','card_sha256'):
        cur.execute(f'CREATE INDEX idx_{col} ON customer_relation({col})')
    con.commit()
    con.close()


def init_audit_db():
    if os.path.exists(AUDIT_DB):
        os.remove(AUDIT_DB)
    con = sqlite3.connect(AUDIT_DB)
    cur = con.cursor()
    cur.execute('''CREATE TABLE import_jobs(
        job_id TEXT PRIMARY KEY,
        archive_name TEXT,
        file_sha256 TEXT,
        upload_sid TEXT,
        total_count INTEGER,
        success_count INTEGER,
        failed_count INTEGER,
        state TEXT,
        finished_at TEXT
    )''')
    cur.execute('''CREATE TABLE operator_sessions(
        session_id TEXT PRIMARY KEY,
        username TEXT,
        source_ip TEXT,
        login_at TEXT,
        logout_at TEXT
    )''')
    cur.execute('''CREATE TABLE queue_events(
        event_id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id TEXT,
        stage TEXT,
        worker TEXT,
        logged_at TEXT
    )''')
    cur.execute('''CREATE TABLE archive_index(
        archive_id TEXT PRIMARY KEY,
        display_name TEXT,
        crc32 TEXT,
        storage_key TEXT,
        note TEXT
    )''')
    sessions = [
        ('S-228A10','kf01','10.8.4.21','2026-04-18 20:54:12','2026-04-18 22:03:45'),
        ('S-9F31A8','kf03','10.8.4.37','2026-04-20 14:58:07','2026-04-20 16:01:22'),
        ('S-7B8821','kf09','10.8.4.45','2026-04-20 18:21:36','2026-04-20 19:02:41'),
        ('S-13D00C','kf06','10.8.4.19','2026-04-21 15:46:02','2026-04-21 17:11:09'),
        ('S-SVC002','svc_import','127.0.0.1','2026-04-20 19:03:11','2026-04-20 19:05:20'),
        ('S-552C9E','kf12','10.8.4.28','2026-04-24 21:42:50','2026-04-24 22:29:13')
    ]
    cur.executemany('INSERT INTO operator_sessions VALUES (?,?,?,?,?)', sessions)
    jobs = [
        ('J260418-211806','260418客户资料.xlsx','861da7fc4e7f08b71802c5ab677a9dd79aa5f0f30a1c3e3019736ecf092d131a','S-228A10',72,70,2,'DONE','2026-04-18 21:18:06'),
        ('J260420-151244','260420客户资料.xlsx',IMPORT_HASH,'S-9F31A8',80,76,4,'DONE','2026-04-20 15:12:44'),
        ('J260420-184731','260420客户资料.xlsx','cb07b003354a9990ca978e26576b71d35a14d5ca5a739303ef36ea40d585c2b8','S-7B8821',80,80,0,'DONE','2026-04-20 18:47:31'),
        ('J260420-190421','260420客户资料.xlsx','cf85d8b909e65f1b1e663d5a09a091b95c63c14d98ce649a7b2864f8f6ecae42','S-SVC002',80,0,80,'REJECTED','2026-04-20 19:04:21'),
        ('J260421-162610','260421客户资料.xlsx','38c9f63b0c37c3a760548bed851f211514b18effb3d3a721ad5ce22bacb3798b','S-13D00C',93,89,4,'DONE','2026-04-21 16:26:10'),
        ('J260424-220549','260424客户资料.xlsx','9ef781d1e07f35ec8a98f275343c9bd4837dfc6cc81e0eb3bb6245fb33d9e506','S-552C9E',65,61,4,'DONE','2026-04-24 22:05:49')
    ]
    cur.executemany('INSERT INTO import_jobs VALUES (?,?,?,?,?,?,?,?,?)', jobs)
    events = [
        ('J260420-151244','UPLOAD','import-worker-02','2026-04-20 15:10:09'),
        ('J260420-151244','CHECKSUM','import-worker-02','2026-04-20 15:10:10'),
        ('J260420-151244','VALIDATE','import-worker-05','2026-04-20 15:11:37'),
        ('J260420-151244','COMMIT','import-worker-05','2026-04-20 15:12:44'),
        ('J260420-184731','UPLOAD','import-worker-04','2026-04-20 18:44:55'),
        ('J260420-184731','COMMIT','import-worker-04','2026-04-20 18:47:31'),
        ('J260420-190421','VALIDATE','import-worker-01','2026-04-20 19:04:13'),
        ('J260420-190421','REJECT','import-worker-01','2026-04-20 19:04:21')
    ]
    cur.executemany('INSERT INTO queue_events(job_id,stage,worker,logged_at) VALUES (?,?,?,?)', events)
    archives = [
        ('A-0420-01','260420客户资料.xlsx','7C2F9A1D','obj/2026/04/20/a1','首次上传'),
        ('A-0420-02','260420客户资料.xlsx','18B1DF21','obj/2026/04/20/b7','修订版本'),
        ('A-0420-03','260420客户资料.xlsx','4D11802A','quarantine/2026/04/20/c3','格式校验失败'),
        ('A-0421-01','260421客户资料.xlsx','E1AA7002','obj/2026/04/21/e4','正常')
    ]
    cur.executemany('INSERT INTO archive_index VALUES (?,?,?,?,?)', archives)
    con.commit()
    con.close()


def init_data():
    os.makedirs(ASSETS, exist_ok=True)
    init_customer_db()
    init_audit_db()


STYLE = '''<style>
*{box-sizing:border-box}body{font-family:Arial,"Microsoft YaHei",sans-serif;background:#f1f4f8;margin:0;color:#243444}
header{background:linear-gradient(120deg,#162d46,#285b78);color:#fff;padding:18px 28px}header .sub{font-size:12px;opacity:.72;margin-left:12px}
main{max-width:1180px;margin:24px auto;background:#fff;padding:24px;border-radius:10px;box-shadow:0 3px 12px #20304018}
a{color:#1769aa;text-decoration:none}nav{display:flex;flex-wrap:wrap;gap:14px;margin-bottom:14px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:13px}
.card{border:1px solid #dce4eb;border-radius:8px;padding:15px;margin:10px 0;background:#fff}.metric b{font-size:24px;display:block;margin-top:5px}.muted{color:#73808c}
.tag{display:inline-block;padding:2px 7px;border-radius:12px;background:#edf3f7;font-size:12px;margin-right:5px}.warn{background:#fff4e5;color:#9a5b00}.ok{background:#eaf7ef;color:#157347}.bad{color:#b42318}
.hero{padding:30px;border-radius:10px;background:linear-gradient(135deg,#edf7ff,#f8fbff);border:1px solid #dceaf5;margin-bottom:16px}.hero h1{margin:0 0 10px;font-size:30px}
.btn{display:inline-block;padding:9px 15px;border-radius:5px;background:#1f6fa8;color:#fff;margin:4px 6px 4px 0}.btn.alt{background:#455a64}
table{border-collapse:collapse;width:100%;font-size:13px;margin:10px 0}th,td{border:1px solid #d9e0e7;padding:8px 9px;text-align:left}th{background:#eef3f7}
input{padding:9px 10px;margin:6px 0;width:310px;max-width:90%;border:1px solid #cbd5df;border-radius:4px}button{padding:9px 18px;background:#1f5f99;color:#fff;border:0;border-radius:4px}
code{word-break:break-all;background:#eef2f5;padding:2px 4px;border-radius:3px}.notice{border-left:4px solid #e4a11b;background:#fff9ec;padding:10px 12px;margin:10px 0}.footer{font-size:12px;color:#89939d;margin-top:28px;border-top:1px solid #e5e9ed;padding-top:12px}
</style>'''


def public_nav():
    return '<nav><a href="/">首页</a><a href="/wallet/">资产中心</a><a href="/task/">任务中心</a><a href="/market/">行情资讯</a><a href="/merchant/">商家合作</a><a href="/support/">在线客服</a><a href="/download/">APP下载</a></nav>'


def admin_nav():
    items = [('dashboard.php','概览'),('customers.php','客户'),('recharge.php','充值订单'),('withdraw.php','提现审核'),('merchant.php','商户通道'),('chat.php','客服会话'),('import-audit.php','导入审计'),('system-log.php','系统日志'),('backup.php','备份中心'),('files.php','文件中心'),('profile.php','个人资料')]
    return '<nav>' + ''.join(f'<a href="{ADMIN_BASE}{path}">{label}</a>' for path, label in items) + '</nav>'


def page(title, body, nav='public'):
    n = admin_nav() + '<hr>' if nav == 'admin' else public_nav() + '<hr>' if nav == 'public' else ''
    footer = '<div class="footer">WH838 Service Platform · build 2026.04.3 · Asia Gateway</div>'
    return f'<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{html.escape(title)}</title>{STYLE}</head><body><header><b>WH838 服务平台</b><span class="sub">Business / Wallet / Merchant / Support</span></header><main>{n}{body}{footer}</main></body></html>'.encode('utf-8')


class Handler(BaseHTTPRequestHandler):
    server_version = 'nginx/1.24.0'

    def log_message(self, fmt, *args):
        with open('/var/log/wh838-access.log', 'a', encoding='utf-8') as f:
            f.write(f'{self.client_address[0]} {self.log_date_time_string()} {fmt % args}\n')

    def out(self, body, status=200, ctype='text/html; charset=utf-8', headers=None):
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, loc):
        self.send_response(302)
        self.send_header('Location', loc)
        self.end_headers()

    def authed(self):
        return f'session={SESSION}' in self.headers.get('Cookie', '')

    def need_auth(self):
        if not self.authed():
            self.redirect(LOGIN_PATH)
            return False
        return True

    def download(self, path, filename, ctype='application/octet-stream'):
        if not self.need_auth():
            return
        if not os.path.exists(path):
            self.out(page('404', '<h2>文件不存在</h2>', 'admin'), 404)
            return
        with open(path, 'rb') as f:
            body = f.read()
        self.out(body, ctype=ctype, headers={'Content-Disposition': f'attachment; filename="{filename}"'})

    def do_GET(self):
        p = urlparse(self.path).path

        public_pages = {
            '/': ('WH838 H5', '''<div class="hero"><span class="tag ok">线路正常</span><span class="tag">节点 AS-03</span><h1>一站式数字服务中心</h1><p>资产管理、商家结算、任务协作与专属客服已接入统一网关。</p><a class="btn" href="/wallet/">进入资产中心</a><a class="btn alt" href="/task/">查看任务大厅</a></div><div class="grid"><div class="card metric"><span class="muted">今日结算笔数</span><b>1,286</b></div><div class="card metric"><span class="muted">活动任务</span><b>36</b></div><div class="card metric"><span class="muted">在线客服</span><b>12</b></div><div class="card metric"><span class="muted">通道维护</span><b>2</b></div></div><div class="notice">系统公告：近期部分出款通道进行例行维护，审核中订单可能延迟。</div><script src="/static/app-config.js"></script>'''),
            '/wallet/': ('资产中心', '<h2>资产中心</h2><div class="grid"><div class="card metric"><span class="muted">可用余额</span><b>¥ 18,640.20</b></div><div class="card metric"><span class="muted">待结算</span><b>¥ 2,380.00</b></div><div class="card metric"><span class="muted">累计收益</span><b>¥ 6,927.60</b></div></div><div class="notice">提现订单进入风控审核后，状态可能短暂显示“复核中”。</div>'),
            '/task/': ('任务中心', '<h2>任务中心</h2><div class="grid"><div class="card"><b>新客体验任务</b><p>进度 2/3 · 奖励 18.8</p></div><div class="card"><b>商家协作任务</b><p>进度 1/5 · 奖励 68</p></div><div class="card"><b>VIP专属任务</b><p>今日剩余 6 个名额</p></div></div>'),
            '/market/': ('行情资讯', '<h2>行情资讯</h2><table><tr><th>频道</th><th>标题</th><th>更新时间</th></tr><tr><td>市场</td><td>亚太市场晨间简报</td><td>09:10</td></tr><tr><td>活动</td><td>会员周活动规则调整</td><td>08:45</td></tr><tr><td>系统</td><td>部分结算线路维护通知</td><td>昨日 23:40</td></tr></table>'),
            '/merchant/': ('商家合作', '<h2>商家合作</h2><div class="card"><b>聚合结算</b><p>订单同步、对账、分账、通道健康度监测。</p></div><div class="card"><b>接口状态</b><p><span class="tag ok">API v2 正常</span><span class="tag warn">备用通道维护</span></p></div>'),
            '/support/': ('在线客服', '<h2>在线客服</h2><div class="card"><b>智能客服</b><p>充值未到账、提现审核、账户异常、任务状态、商家结算。</p></div><div class="card"><b>人工坐席</b><p>当前排队人数：3</p></div>'),
            '/download/': ('客户端下载', '<h2>客户端下载</h2><div class="grid"><div class="card"><b>Android</b><p>版本 4.6.2</p></div><div class="card"><b>iOS</b><p>版本 4.6.1</p></div><div class="card"><b>PC助手</b><p>版本 2.3.0</p></div></div><p class="muted">下载按钮在靶场中已禁用。</p>')
        }
        if p in public_pages:
            title, body = public_pages[p]
            self.out(page(title, body))
            return

        if p == '/robots.txt':
            self.out(b'User-agent: *\nDisallow: /admin/\nDisallow: /manage/\nDisallow: /merchant-console/\nDisallow: /internal/\n', ctype='text/plain; charset=utf-8')
            return
        if p == '/static/app-config.js':
            js = b'''window.APP_CONFIG = {\n  apiBase: "/api/v2/",\n  consoleBase: "/administrator/",\n  consoleEntry: "login.php",\n  version: "2026.04.3"\n};\n'''
            self.out(js, ctype='application/javascript; charset=utf-8')
            return
        if p == '/api/v2/status':
            self.out(json.dumps({'status':'ok','region':'asia-03','build':'2026.04.3'}).encode(), ctype='application/json')
            return
        if p in ('/admin/', '/admin/login.php', '/manage/', '/manage/login.php'):
            self.out(page('旧版后台', '<h2>Legacy Console</h2><div class="notice">旧版管理端已停用。</div>', None), status=410)
            return
        if p == '/internal/' or p.startswith('/merchant-console/'):
            self.out(page('403', '<h2>403 Forbidden</h2>', None), status=403)
            return

        if p == LOGIN_PATH:
            if self.authed():
                self.redirect(ADMIN_BASE + 'dashboard.php')
                return
            body = '''<h2>统一运营控制台</h2><p class="muted">WH838 Operations Console / Asia-03</p><form method="post"><div><input name="username" placeholder="账号"></div><div><input name="password" type="password" placeholder="密码"></div><button type="submit">登录</button></form>'''
            self.out(page('运营控制台登录', body, None))
            return

        if p.startswith(ADMIN_BASE) and not self.need_auth():
            return

        if p == ADMIN_BASE + 'dashboard.php':
            body = '<h2>运营概览</h2><div class="grid"><div class="card metric"><span class="muted">今日充值</span><b>¥ 286,420</b></div><div class="card metric"><span class="muted">待审核提现</span><b>27</b></div><div class="card metric"><span class="muted">在线客服</span><b>18</b></div><div class="card metric"><span class="muted">活跃商户</span><b>42</b></div></div>'
            self.out(page('运营概览', body, 'admin')); return
        if p == ADMIN_BASE + 'customers.php':
            body = '<h2>客户管理</h2><table><tr><th>客户ID</th><th>分组</th><th>状态</th><th>负责人</th></tr><tr><td>C260409137</td><td>A3</td><td>已完成</td><td>liu07</td></tr><tr><td>C260409166</td><td>A3</td><td>已完成</td><td>liu17</td></tr><tr><td>C260409188</td><td>B1</td><td>已完成</td><td>liu11</td></tr></table><p class="muted">敏感字段在前端脱敏显示，完整关联数据仅保存在离线备份。</p>'
            self.out(page('客户管理', body, 'admin')); return
        if p == ADMIN_BASE + 'recharge.php':
            body = '<h2>充值订单</h2><table><tr><th>订单号</th><th>金额</th><th>状态</th></tr><tr><td>R260420184201</td><td>5,000</td><td>到账</td></tr><tr><td>R260420183544</td><td>12,000</td><td>到账</td></tr></table>'
            self.out(page('充值订单', body, 'admin')); return
        if p == ADMIN_BASE + 'withdraw.php':
            body = '<h2>提现审核</h2><table><tr><th>单号</th><th>金额</th><th>状态</th></tr><tr><td>W2604200721</td><td>18,000</td><td>待审</td></tr><tr><td>W2604200716</td><td>32,000</td><td>冻结</td></tr></table>'
            self.out(page('提现审核', body, 'admin')); return
        if p == ADMIN_BASE + 'merchant.php':
            body = '<h2>商户通道</h2><table><tr><th>商户</th><th>通道</th><th>状态</th></tr><tr><td>M13510216</td><td>PAY-A2</td><td>正常</td></tr><tr><td>M13510977</td><td>PAY-C4</td><td>降级</td></tr></table>'
            self.out(page('商户通道', body, 'admin')); return
        if p == ADMIN_BASE + 'chat.php':
            body = '<h2>客服会话</h2><table><tr><th>会话ID</th><th>坐席</th><th>状态</th></tr><tr><td>CH-884021</td><td>kf03</td><td>结束</td></tr><tr><td>CH-884055</td><td>kf09</td><td>进行中</td></tr></table>'
            self.out(page('客服会话', body, 'admin')); return
        if p == ADMIN_BASE + 'import-audit.php':
            con = sqlite3.connect(AUDIT_DB)
            rows = con.execute('''SELECT j.job_id,j.archive_name,j.file_sha256,s.username,j.total_count,j.success_count,j.failed_count,j.state,j.finished_at FROM import_jobs j LEFT JOIN operator_sessions s ON j.upload_sid=s.session_id ORDER BY j.finished_at DESC''').fetchall()
            con.close()
            tr = ''.join(f'<tr><td>{html.escape(r[0])}</td><td>{html.escape(r[1])}</td><td><code>{html.escape(r[2])}</code></td><td>{html.escape(r[3] or "-")}</td><td>{r[4]}</td><td>{r[5]}</td><td>{r[6]}</td><td>{html.escape(r[7])}</td><td>{html.escape(r[8])}</td></tr>' for r in rows)
            body = f'<h2>客户资料导入审计</h2><p class="muted">同名文件可能存在多个版本，请以原始文件 SHA-256 核对对应导入记录。</p><table><tr><th>任务ID</th><th>文件名</th><th>SHA-256</th><th>操作账号</th><th>总数</th><th>成功</th><th>失败</th><th>状态</th><th>完成时间</th></tr>{tr}</table><p><a href="/download/import_audit.db">下载 import_audit.db</a></p>'
            self.out(page('导入审计', body, 'admin')); return
        if p == ADMIN_BASE + 'system-log.php':
            body = '<h2>系统日志</h2><table><tr><th>时间</th><th>组件</th><th>摘要</th></tr><tr><td>19:04:21</td><td>import-worker-01</td><td>validation rejected</td></tr><tr><td>15:12:44</td><td>import-worker-05</td><td>import job committed</td></tr></table><p><a href="/download/legacy-import.log">下载 legacy-import.log</a></p>'
            self.out(page('系统日志', body, 'admin')); return
        if p == ADMIN_BASE + 'backup.php':
            body = f'<h2>备份中心</h2><div class="grid"><div class="card"><b>customer_relation.db</b><p>客户关联库；手机号和银行卡仅保留后四位及 SHA-256 摘要。</p><a href="/download/customer_relation.db">下载</a></div><div class="card"><b>import_audit.db</b><p>导入任务、文件 SHA-256 与操作会话。</p><a href="/download/import_audit.db">下载</a></div><div class="card"><b>业务归档</b><p><a href="{ADMIN_BASE}files.php">进入文件中心</a></p></div></div>'
            self.out(page('备份中心', body, 'admin')); return
        if p == ADMIN_BASE + 'files.php':
            body = '<h2>文件中心</h2><table><tr><th>目录</th><th>文件</th></tr><tr><td>话术库</td><td><a href="/download/script.txt">1-打招呼话术.txt</a></td></tr><tr><td>客户资料</td><td>260420客户资料.xlsx</td></tr><tr><td>业绩归档</td><td><a href="/download/performance.csv">4.20业绩归档.csv</a></td></tr><tr><td>系统日志</td><td><a href="/download/legacy-import.log">legacy-import.log</a></td></tr></table>'
            self.out(page('文件中心', body, 'admin')); return
        if p == ADMIN_BASE + 'profile.php':
            body = f'<h2>个人资料</h2><table><tr><th>用户名</th><td>admin</td></tr><tr><th>角色</th><td>系统管理员</td></tr><tr><th>区域</th><td>Asia-03</td></tr><tr><th>个人签名</th><td><code>{PROFILE_FLAG}</code></td></tr><tr><th>最后登录</th><td>2026-04-20 18:12:41</td></tr></table>'
            self.out(page('个人资料', body, 'admin')); return

        if p == '/download/customer_relation.db': self.download(CUSTOMER_DB, 'customer_relation.db'); return
        if p == '/download/import_audit.db': self.download(AUDIT_DB, 'import_audit.db'); return
        if p == '/download/performance.csv': self.download(os.path.join(ASSETS, 'performance_0420.csv'), 'performance_0420.csv', 'text/csv; charset=utf-8'); return
        if p == '/download/script.txt': self.download(os.path.join(ASSETS, '1-打招呼话术.txt'), 'script.txt', 'text/plain; charset=utf-8'); return
        if p == '/download/legacy-import.log':
            if not self.need_auth(): return
            body = b'2026-04-01 10:22:07 INFO legacy-import file=260420\xe5\xae\xa2\xe6\x88\xb7\xe8\xb5\x84\xe6\x96\x99.xlsx operator=test01 state=TEST_ONLY\n2026-04-20 19:04:21 WARN rejected job=J260420-190421 reason=column_mismatch\n'
            self.out(body, ctype='text/plain; charset=utf-8', headers={'Content-Disposition':'attachment; filename="legacy-import.log"'}); return

        self.out(page('404', '<h2>404 Not Found</h2>', None), status=404)

    def do_POST(self):
        if urlparse(self.path).path != LOGIN_PATH:
            self.out(b'not found', status=404, ctype='text/plain; charset=utf-8')
            return
        length = int(self.headers.get('Content-Length', '0') or 0)
        data = parse_qs(self.rfile.read(length).decode('utf-8', errors='ignore'))
        user = data.get('username', [''])[0]
        password = data.get('password', [''])[0]
        if user == ADMIN_USER and password == ADMIN_PASS:
            self.send_response(302)
            self.send_header('Location', ADMIN_BASE + 'dashboard.php')
            self.send_header('Set-Cookie', f'session={SESSION}; Path=/; HttpOnly')
            self.end_headers()
            return
        self.out(page('登录失败', '<h2>统一运营控制台</h2><p class="bad">账号或密码错误</p>', None), status=401)


if __name__ == '__main__':
    init_data()
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
