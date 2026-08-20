#!/bin/bash
set -u
TARGET_HOST="node01"
TARGET_IP="172.30.2.2"
STATUS_FILE="/tmp/remote-forensics-setup-status.txt"
RAW_BASE="https://raw.githubusercontent.com/MalloryGo/remote-forensics-lab/main/remote-forensics"

for i in $(seq 1 45); do
  if ssh -o BatchMode=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=no "$TARGET_HOST" true 2>/dev/null; then break; fi
  sleep 1
done

mkdir -p /tmp/remote-forensics-assets
curl -fsSL "$RAW_BASE/target_app.py" -o /tmp/remote-forensics-assets/target_app.py
curl -fsSL "$RAW_BASE/tcp_services.py" -o /tmp/remote-forensics-assets/tcp_services.py
curl -fsSL "$RAW_BASE/tcp_forward.py" -o /tmp/remote-forensics-assets/tcp_forward.py

# Fail early if the downloaded target app does not match the frozen challenge contract.
grep -q "LOGIN_PATH = '/administrator/login.php'" /tmp/remote-forensics-assets/target_app.py || { echo 'target_app login path mismatch' >&2; exit 1; }
grep -q 'consoleBase: "/administrator/"' /tmp/remote-forensics-assets/target_app.py || { echo 'target_app JS clue mismatch' >&2; exit 1; }
grep -q "PROFILE_FLAG = 'flag{991c4becc9a979aa096b23d0065f3f02}'" /tmp/remote-forensics-assets/target_app.py || { echo 'target_app profile flag mismatch' >&2; exit 1; }

scp -q -o StrictHostKeyChecking=no /tmp/remote-forensics-assets/target_app.py "$TARGET_HOST:/tmp/target_app.py"
scp -q -o StrictHostKeyChecking=no /tmp/remote-forensics-assets/tcp_services.py "$TARGET_HOST:/tmp/tcp_services.py"

ssh -o StrictHostKeyChecking=no "$TARGET_HOST" 'bash -s' <<'REMOTE'
set -u
BASE="/srv/remote-forensics"
mkdir -p "$BASE/landing" "$BASE/assets" /opt/remote-forensics
systemctl mask --now kubelet >/dev/null 2>&1 || true
pkill -f 'kube-proxy' 2>/dev/null || true
rm -f /root/.kube/config /etc/kubernetes/admin.conf 2>/dev/null || true

install -m 700 /tmp/target_app.py /opt/remote-forensics/target_app.py
install -m 700 /tmp/tcp_services.py /opt/remote-forensics/tcp_services.py

cat > "$BASE/assets/1-打招呼话术.txt" <<'TXT'
打招呼话术，顺序根据客户反应调整，才能把我们和客户的谈论进行下去，最后一定要解释清楚自己确实是加错人了。
我是伊琳娜，你还记得我吗
lol，抱歉，如果按照你意思来理解，我可能搞错啦，错误的事情总是让人很尴尬
有时候错误的事也能让大家互相认识，成为朋友，也不见得是一件坏事咯
TXT

cat > "$BASE/assets/performance_0420.csv" <<'CSV'
team,username,amount,date
张总团队,zhao369,3000,2026-04-20
张总团队,Lyb369,3000,2026-04-20
张总团队,li789,5000,2026-04-20
张总团队,zhang789,3000,2026-04-20
张总团队,liu07,3000,2026-04-20
张总团队,liu70x,2800,2026-04-20
阜总团队,liu17,3500,2026-04-20
阜总团队,liu70,4200,2026-04-20
杜总团队,liu02,2600,2026-04-20
湖总团队,liu03,3800,2026-04-20
南总团队,liu11,3100,2026-04-20
太总团队,liu08,3300,2026-04-20
CSV

cat > "$BASE/landing/index.html" <<'HTML'
<!doctype html><html><head><meta charset="utf-8"><title>WH838 Gateway</title></head><body><h2>WH838 Service Gateway</h2><p>gateway status: online</p><p>H5 business service is running.</p></body></html>
HTML

pkill -f '/opt/remote-forensics/target_app.py' 2>/dev/null || true
pkill -f '/opt/remote-forensics/tcp_services.py' 2>/dev/null || true
pkill -f 'http.server 8080' 2>/dev/null || true
pkill -f 'http.server 80 --bind 0.0.0.0 --directory /srv/remote-forensics/landing' 2>/dev/null || true
nohup python3 /opt/remote-forensics/target_app.py >/var/log/wh838-web.log 2>&1 </dev/null &
nohup python3 /opt/remote-forensics/tcp_services.py >/var/log/wh838-services.log 2>&1 </dev/null &
nohup python3 -m http.server 80 --bind 0.0.0.0 --directory "$BASE/landing" >/var/log/wh838-gateway.log 2>&1 </dev/null &
sleep 2

mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/00-remote-forensics.conf <<'SSHCFG'
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
SSHCFG
rm -f /root/.ssh/authorized_keys /root/.ssh/authorized_keys2 2>/dev/null || true
passwd -l root >/dev/null 2>&1 || true
userdel -r rf_test >/dev/null 2>&1 || true
/usr/sbin/sshd -t && (systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true)
REMOTE

systemctl mask --now kubelet >/dev/null 2>&1 || true
if command -v crictl >/dev/null 2>&1; then
  for name in kube-apiserver kube-controller-manager kube-scheduler etcd; do
    ids="$(crictl ps --name "$name" -q 2>/dev/null || true)"
    [ -z "$ids" ] || crictl stop $ids >/dev/null 2>&1 || true
  done
fi
pkill -f 'kube-apiserver' 2>/dev/null || true
pkill -f 'kube-controller-manager' 2>/dev/null || true
pkill -f 'kube-scheduler' 2>/dev/null || true
pkill -f 'etcd.*--' 2>/dev/null || true
rm -f /root/.kube/config /etc/kubernetes/admin.conf 2>/dev/null || true

install -m 700 /tmp/remote-forensics-assets/tcp_forward.py /opt/remote-forensics-forward.py
pkill -f '/opt/remote-forensics-forward.py' 2>/dev/null || true
nohup python3 /opt/remote-forensics-forward.py >/var/log/remote-forensics-forward.log 2>&1 </dev/null &

export DEBIAN_FRONTEND=noninteractive
(apt-get update -qq && apt-get install -y -qq nmap sqlite3 >/dev/null 2>&1) || true
cat > /root/REMOTE_TARGET.txt <<EOF
Remote target: $TARGET_IP
Use this controlplane only as the examination workstation.
The competition questions and answer submission are provided by the external competition system.
EOF
sleep 2
{
 echo "target_ip=$TARGET_IP"
 echo "configured_at=$(date -Is)"
 curl -fsS --max-time 4 "http://$TARGET_IP:8080/" >/dev/null 2>&1 && echo "web=ok" || echo "web=failed"
 timeout 3 bash -c "</dev/tcp/$TARGET_IP/3306" 2>/dev/null && echo "tcp_services=ok" || echo "tcp_services=failed"
 if ssh -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=no root@"$TARGET_IP" true >/dev/null 2>&1; then echo "root_ssh=FAILED_OPEN"; else echo "root_ssh=blocked"; fi
 if timeout 4 kubectl get nodes >/dev/null 2>&1; then echo "kubectl=FAILED_OPEN"; else echo "kubectl=blocked"; fi
 curl -fsS --max-time 4 http://127.0.0.1:8080/ >/dev/null 2>&1 && echo "browser_proxy=ok" || echo "browser_proxy=failed"
 command -v nmap >/dev/null 2>&1 && echo "nmap=ready" || echo "nmap=unavailable"
 command -v sqlite3 >/dev/null 2>&1 && echo "sqlite3=ready" || echo "sqlite3=unavailable"
} > "$STATUS_FILE"
