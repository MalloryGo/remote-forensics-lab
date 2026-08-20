#!/bin/bash
set -u

TARGET_HOST="node01"
TARGET_IP="172.30.2.2"
WORKSTATION_IP="172.30.1.2"
STATUS_FILE="/tmp/remote-forensics-setup-status.txt"
RAW_BASE="https://raw.githubusercontent.com/MalloryGo/remote-forensics-lab/main/remote-forensics"

# Wait for Killercoda's bootstrap SSH path. It is intentionally removed after provisioning.
for i in $(seq 1 45); do
  if ssh -o BatchMode=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=no "$TARGET_HOST" true 2>/dev/null; then
    break
  fi
  sleep 1
done

# Fetch challenge components before locking down node01.
mkdir -p /tmp/remote-forensics-assets
curl -fsSL "$RAW_BASE/target_app.py" -o /tmp/remote-forensics-assets/target_app.py
curl -fsSL "$RAW_BASE/tcp_services.py" -o /tmp/remote-forensics-assets/tcp_services.py
curl -fsSL "$RAW_BASE/tcp_forward.py" -o /tmp/remote-forensics-assets/tcp_forward.py
scp -q -o StrictHostKeyChecking=no /tmp/remote-forensics-assets/target_app.py "$TARGET_HOST:/tmp/target_app.py"
scp -q -o StrictHostKeyChecking=no /tmp/remote-forensics-assets/tcp_services.py "$TARGET_HOST:/tmp/tcp_services.py"

# Provision the remote target while the bootstrap root path still exists.
ssh -o StrictHostKeyChecking=no "$TARGET_HOST" 'bash -s' <<'REMOTE'
set -u
WORKSTATION_IP="172.30.1.2"
BASE="/srv/remote-forensics"
mkdir -p "$BASE/landing" /opt/remote-forensics

# node01 is a plain remote Linux target, not a Kubernetes worker for the challenge.
systemctl mask --now kubelet >/dev/null 2>&1 || true
pkill -f 'kube-proxy' 2>/dev/null || true
rm -f /root/.kube/config /etc/kubernetes/admin.conf 2>/dev/null || true

install -m 700 /tmp/target_app.py /opt/remote-forensics/target_app.py
install -m 700 /tmp/tcp_services.py /opt/remote-forensics/tcp_services.py

cat > "$BASE/landing/index.html" <<'HTML'
<!doctype html>
<html><head><meta charset="utf-8"><title>WH838 Gateway</title></head>
<body><h2>WH838 Service Gateway</h2><p>gateway status: online</p><p>H5 business service is running.</p></body></html>
HTML

# Stop prototype leftovers, then expose the intended service set.
pkill -f '/opt/remote-forensics/target_app.py' 2>/dev/null || true
pkill -f '/opt/remote-forensics/tcp_services.py' 2>/dev/null || true
pkill -f 'http.server 8080' 2>/dev/null || true
pkill -f 'http.server 80 --bind 0.0.0.0 --directory /srv/remote-forensics/landing' 2>/dev/null || true
nohup python3 /opt/remote-forensics/target_app.py >/var/log/wh838-web.log 2>&1 </dev/null &
nohup python3 /opt/remote-forensics/tcp_services.py >/var/log/wh838-services.log 2>&1 </dev/null &
nohup python3 -m http.server 80 --bind 0.0.0.0 --directory "$BASE/landing" >/var/log/wh838-gateway.log 2>&1 </dev/null &
sleep 2

# From controlplane, make exactly these TCP services reachable.
# In the 1000-9999 range the intended open ports are 3306, 8080, 8888 and 9090.
if command -v iptables >/dev/null 2>&1; then
  iptables -I INPUT 1 -s "$WORKSTATION_IP" -p tcp -j REJECT --reject-with tcp-reset 2>/dev/null || true
  for p in 22 80 3306 8080 8888 9090; do
    iptables -I INPUT 1 -s "$WORKSTATION_IP" -p tcp --dport "$p" -j ACCEPT 2>/dev/null || true
  done
fi

# Remove the platform-provided root SSH shortcut after provisioning.
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

# Disable the original Kubernetes control plane as an obvious bypass to node01.
systemctl mask --now kubelet >/dev/null 2>&1 || true
if command -v crictl >/dev/null 2>&1; then
  for name in kube-apiserver kube-controller-manager kube-scheduler etcd; do
    ids="$(crictl ps --name "$name" -q 2>/dev/null || true)"
    if [ -n "$ids" ]; then crictl stop $ids >/dev/null 2>&1 || true; fi
  done
fi
pkill -f 'kube-apiserver' 2>/dev/null || true
pkill -f 'kube-controller-manager' 2>/dev/null || true
pkill -f 'kube-scheduler' 2>/dev/null || true
pkill -f 'etcd.*--' 2>/dev/null || true
rm -f /root/.kube/config /etc/kubernetes/admin.conf 2>/dev/null || true

# Forward controlplane:8080 to node01:8080 so the Killercoda Traffic tab can display the site.
install -m 700 /tmp/remote-forensics-assets/tcp_forward.py /opt/remote-forensics-forward.py
pkill -f '/opt/remote-forensics-forward.py' 2>/dev/null || true
nohup python3 /opt/remote-forensics-forward.py >/var/log/remote-forensics-forward.log 2>&1 </dev/null &

# Useful contestant tools. If package installation fails, Python and curl still suffice.
export DEBIAN_FRONTEND=noninteractive
(apt-get update -qq && apt-get install -y -qq nmap sqlite3 >/dev/null 2>&1) || true

cat > /root/REMOTE_TARGET.txt <<EOF
Remote target: $TARGET_IP
Use this controlplane only as the examination workstation.
The competition questions and answer submission are provided by the external competition system.
EOF

# Readiness only; no challenge answers are written here.
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
