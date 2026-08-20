#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
import hashlib
import html
import os
import sqlite3

HOST = '0.0.0.0'
PORT = 8080
BASE = '/srv/remote-forensics'
DB_PATH = os.path.join(BASE, 'customer_relation.db')
ADMIN_USER = 'admin'
ADMIN_PASS = 'Aa123456'
SESSION_TOKEN = 'wh838-admin-session-2026'
PROFILE_FLAG = 'flag{51f34232339c9c4cb304ebc54f136051}'
CORRECT_CARD_HASH = '2f784423cb78cc6c70144c36cb9e25c49fa6eb62192a7f543422a4c25046c3fb'
IMPORT_FILE_HASH = '0066ac9361cfe37c0cc7e42b61f34edd632fe93857f6b83fa26ab0b476b2dd14'

IMPORT_AUDIT = [
    ('260418客户资料.xlsx', '861da7fc4e7f08b71802c5ab677a9dd79aa5f0f30a1c3e3019736ecf092d131a', 'kf01', 72, 70, 2, '2026-04-18 21:18:06'),
    ('260420客户资料.xlsx', IMPORT_FILE_HASH, 'kf03', 80, 76, 4, '2026-04-20 15:12:44'),
    ('260420客户资料(1).xlsx', 'cb07b003354a9990ca978e26576b71d35a14d5ca5a739303ef36ea40d585c2b8', 'kf09', 80, 80, 0, '2026-04-20 18:47:31'),
    ('260421客户资料.xlsx', '38c9f63b0c37c3a760548bed851f211514b18effb3d3a721ad5ce22bacb3798b', 'kf06', 93, 89, 4, '2026-04-21 16:26:10'),
    ('260424客户资料.xlsx', '9ef781d1e07f35ec8a98f275343c9bd4837dfc6cc81e0eb3bb6245fb33d9e506', 'kf12', 65, 61, 4, '2026-04-24 22:05:49'),
]


def fake_hash(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def init_db():
    os.makedirs(BASE, exist_ok=True)
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute('''CREATE TABLE customer_relation (
        customer_id TEXT PRIMARY KEY,
        card_last4 TEXT NOT NULL,
        card_sha256 TEXT NOT NULL,
        event_date TEXT NOT NULL,
        operator TEXT NOT NULL,
        status TEXT NOT NULL,
        batch_no TEXT NOT NULL,
        amount INTEGER NOT NULL,
        note TEXT
    )''')
    rows = [
        ('C260331018', '6758', fake_hash('6217000000006758'), '2026-03-31', 'liu03', 'invalid', 'B260331-01', 6800, '号码重复'),
        ('C260401018', '6758', CORRECT_CARD_HASH, '2026-04-01', 'test01', 'test', 'B260401-T1', 100, '接口联调测试'),
        ('C260402071', '6758', fake_hash('6222000000006758'), '2026-04-02', 'liu08', 'closed', 'B260402-02', 12000, '未继续跟进'),
        ('C260408109', '6758', fake_hash('6233000000006758'), '2026-04-08', 'liu05', 'following', 'B260408-04', 36000, '持续跟进'),
        ('C260409137', '6758', CORRECT_CARD_HASH, '2026-04-09', 'liu07', 'completed', 'B260409-03', 72800, '已完成'),
        ('C260409188', '6758', fake_hash('6244000000006758'), '2026-04-09', 'liu11', 'completed', 'B260409-05', 51000, '已完成'),
        ('C260412227', '6758', fake_hash('6255000000006758'), '2026-04-12', 'liu02', 'invalid', 'B260412-06', 9000, '无效数据'),
        ('C260409031', '1936', fake_hash('6200000000001936'), '2026-04-09', 'liu17', 'completed', 'B260409-01', 42000, ''),
        ('C260409044', '7586', fake_hash('6200000000007586'), '2026-04-09', 'liu70', 'following', 'B260409-02', 26000, ''),
        ('C260410201', '6759', fake_hash('6200000000006759'), '2026-04-10', 'liu09', 'closed', 'B260410-01', 15000, ''),
    ]
    cur.executemany('INSERT INTO customer_relation VALUES (?,?,?,?,?,?,?,?,?)', rows)
    cur.execute('CREATE INDEX idx_card_last4 ON customer_relation(card_last4)')
    cur.execute('CREATE INDEX idx_card_hash ON customer_relation(card_sha256)')
    con.commit()
    con.close()


STYLE = '''
<style>
body{font-family:Arial,"Microsoft YaHei",sans-serif;background:#f4f6f8;margin:0;color:#25313c}
header{background:#1f3552;color:#fff;padding:18px 28px} main{max-width:1050px;margin:28px auto;background:#fff;padding:26px;border-radius:8px;box-shadow:0 2px 8px #0001}
a{color:#1769aa;text-decoration:none} nav a{margin-right:18px}.muted{color:#6b7785}.card{border:1px solid #dfe5eb;border-radius:6px;padding:16px;margin:12px 0}
table{border-collapse:collapse;width:100%;font-size:14px} th,td{border:1px solid #d9e0e7;padding:8px 10px;text-align:left} th{background:#eef3f7}
input{padding:9px 10px;margin:6px 0;width:320px;max-width:90%}button{padding:9px 18px;background:#1f5f99;color:#fff;border:0;border-radius:4px}.bad{color:#b42318}.good{color:#087a3e}code{background:#eef2f5;padding:2px 5px;border-radius:3px}
</style>'''


def page(title, body, nav=False):
    n = ''
    if nav:
        n = '<nav><a href="/admin/dashboard.php">首页</a><a href="/admin/profile.php">个人资料</a><a href="/admin/import-audit.php">数据导入审计</a><a href="/admin/backup.php">备份中心</a><a href="/admin/files.php">文件中心</a></nav><hr>'
    return f'<!doctype html><html><head><meta charset="utf-8"><title>{html.escape(title)}</title>{STYLE}</head><body><header><b>WH838 业务管理平台</b></header><main>{n}{body}</main></body></html>'.encode('utf-8')


class Handler(BaseHTTPRequestHandler):
    server_version = 'nginx/1.24.0'

    def log_message(self, fmt, *args):
        with open('/var/log/wh838-access.log', 'a', encoding='utf-8') as f:
            f.write(f'{self.client_address[0]} {self.log_date_time_string()} {fmt % args}\n')

    def send_bytes(self, body, status=200, ctype='text/html; charset=utf-8', headers=None):
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
        cookie = self.headers.get('Cookie', '')
        return f'session={SESSION_TOKEN}' in cookie

    def require_auth(self):
        if not self.authed():
            self.redirect('/admin/login.php')
            return False
        return True

    def do_GET(self):
        p = urlparse(self.path).path
        if p == '/':
            body = '''<h2>WH838 H5 业务系统</h2><div class="card"><p>系统运行正常。</p><p class="muted">客户服务、数据同步及商家接口已连接。</p></div><script src="/static/app.js"></script>'''
            self.send_bytes(page('WH838 H5', body))
            return
        if p == '/robots.txt':
            self.send_bytes(b'User-agent: *\nDisallow: /admin/\nDisallow: /internal/\n', ctype='text/plain; charset=utf-8')
            return
        if p == '/static/app.js':
            js = b'''window.WH838={apiBase:"/api/v2/",adminBase:"/admin/",adminEntry:"login.php",build:"2026.04.3"};'''
            self.send_bytes(js, ctype='application/javascript; charset=utf-8')
            return
        if p in ('/admin', '/admin/'):
            self.redirect('/admin/login.php')
            return
        if p == '/admin/login.php':
            if self.authed():
                self.redirect('/admin/dashboard.php')
                return
            body = '''<h2>测试服后台登录</h2><p class="muted">WH838 Admin Console</p><form method="post"><div><input name="username" placeholder="用户名"></div><div><input name="password" type="password" placeholder="密码"></div><button type="submit">登录</button></form>'''
            self.send_bytes(page('后台登录', body))
            return
        if p == '/admin/dashboard.php':
            if not self.require_auth():
                return
            body = '''<h2>后台首页</h2><div class="card"><b>数据中心</b><p>今日任务、客户导入、业务资料与系统备份。</p></div><div class="card"><b>当前用户：admin</b><p>角色：系统管理员</p></div>'''
            self.send_bytes(page('后台首页', body, True))
            return
        if p == '/admin/profile.php':
            if not self.require_auth():
                return
            body = f'''<h2>个人资料</h2><table><tr><th>用户名</th><td>admin</td></tr><tr><th>角色</th><td>系统管理员</td></tr><tr><th>个人签名</th><td><code>{PROFILE_FLAG}</code></td></tr><tr><th>最后登录</th><td>2026-04-15 02:18:31</td></tr></table>'''
            self.send_bytes(page('个人资料', body, True))
            return
        if p == '/admin/import-audit.php':
            if not self.require_auth():
                return
            rows = ''.join(f'<tr><td>{html.escape(r[0])}</td><td><code>{r[1]}</code></td><td>{r[2]}</td><td>{r[3]}</td><td>{r[4]}</td><td>{r[5]}</td><td>{r[6]}</td></tr>' for r in IMPORT_AUDIT)
            body = f'''<h2>数据导入审计</h2><p class="muted">系统按原始文件 SHA-256 记录导入任务。</p><table><tr><th>文件名</th><th>SHA-256</th><th>操作账号</th><th>总数</th><th>成功</th><th>失败</th><th>时间</th></tr>{rows}</table>'''
            self.send_bytes(page('导入审计', body, True))
            return
        if p == '/admin/backup.php':
            if not self.require_auth():
                return
            body = '''<h2>备份中心</h2><div class="card"><b>customer_relation.db</b><p>客户关联库（SQLite3），包含客户编号、银行卡摘要、日期、操作账号及业务状态。</p><a href="/download/customer_relation.db">下载备份</a></div><div class="card"><b>说明</b><p class="muted">敏感银行卡数据仅保留后四位和 SHA-256 摘要。</p></div>'''
            self.send_bytes(page('备份中心', body, True))
            return
        if p == '/admin/files.php':
            if not self.require_auth():
                return
            body = '''<h2>文件中心</h2><table><tr><th>目录</th><th>文件</th><th>状态</th></tr><tr><td>话术库</td><td><a href="/download/1-打招呼话术.txt">1-打招呼话术.txt</a></td><td>在线</td></tr><tr><td>客户资料</td><td>260420客户资料.xlsx</td><td>已导入/原文件归档</td></tr><tr><td>业绩归档</td><td>4.20 (3).xlsx</td><td>归档</td></tr></table>'''
            self.send_bytes(page('文件中心', body, True))
            return
        if p == '/download/customer_relation.db':
            if not self.require_auth():
                return
            with open(DB_PATH, 'rb') as f:
                data = f.read()
            self.send_bytes(data, ctype='application/octet-stream', headers={'Content-Disposition':'attachment; filename="customer_relation.db"'})
            return
        if p == '/download/1-打招呼话术.txt':
            if not self.require_auth():
                return
            data = ('打招呼话术，顺序根据客户反应调整，最后一定要解释清楚自己确实是加错人了。\n\n'
                    '我是伊琳娜，你还记得我吗\n'
                    'lol，抱歉，如果按照你意思来理解，我可能搞错啦，错误的事情总是让人很尴尬\n'
                    '有时候错误的事也能让大家互相认识，成为朋友，也不见得是一件坏事咯\n').encode('utf-8')
            self.send_bytes(data, ctype='text/plain; charset=utf-8', headers={'Content-Disposition':'attachment; filename="script.txt"'})
            return
        self.send_bytes(page('404', '<h2>404 Not Found</h2>'), status=404)

    def do_POST(self):
        p = urlparse(self.path).path
        if p != '/admin/login.php':
            self.send_bytes(b'not found', status=404, ctype='text/plain')
            return
        length = int(self.headers.get('Content-Length','0') or 0)
        data = parse_qs(self.rfile.read(length).decode('utf-8', errors='ignore'))
        u = data.get('username',[''])[0]
        pw = data.get('password',[''])[0]
        if u == ADMIN_USER and pw == ADMIN_PASS:
            self.send_response(302)
            self.send_header('Location','/admin/dashboard.php')
            self.send_header('Set-Cookie', f'session={SESSION_TOKEN}; Path=/; HttpOnly')
            self.end_headers()
            return
        body = '''<h2>测试服后台登录</h2><p class="bad">用户名或密码错误</p><form method="post"><div><input name="username" placeholder="用户名"></div><div><input name="password" type="password" placeholder="密码"></div><button type="submit">登录</button></form>'''
        self.send_bytes(page('登录失败', body), status=401)


if __name__ == '__main__':
    init_db()
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
