#!/bin/bash
set -u

TARGET_HOST="node01"
TARGET_IP="172.30.2.2"

# Wait until the second host is reachable via the Killercoda-provided bootstrap SSH path.
for i in $(seq 1 30); do
  if ssh -o BatchMode=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=no "$TARGET_HOST" true 2>/dev/null; then
    break
  fi
  sleep 1
done

# Configure node01 while the platform bootstrap SSH path is still available.
ssh -o StrictHostKeyChecking=no "$TARGET_HOST" 'bash -s' <<'REMOTE'
set -u

mkdir -p /srv/remote-forensics-test
cat > /srv/remote-forensics-test/index.html <<'HTML'
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Remote Forensics Target</title></head>
<body>
  <h1>Remote Forensics Target</h1>
  <p>node01 test service is running.</p>
</body>
</html>
HTML

# Start a deliberately simple HTTP service for the network-isolation test.
pkill -f 'python3 -m http.server 8080 --directory /srv/remote-forensics-test' 2>/dev/null || true
nohup python3 -m http.server 8080 --bind 0.0.0.0 --directory /srv/remote-forensics-test \
  >/var/log/remote-forensics-test-http.log 2>&1 </dev/null &

# Remove the obvious controlplane -> node01 root SSH shortcut.
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/99-remote-forensics.conf <<'EOF'
PermitRootLogin no
PasswordAuthentication yes
KbdInteractiveAuthentication no
EOF
chmod 600 /etc/ssh/sshd_config.d/99-remote-forensics.conf

# Keep a non-root test account for later SSH-path testing; this is not a competition credential.
id -u rf_test >/dev/null 2>&1 || useradd -m -s /bin/bash rf_test
echo 'rf_test:RF-Test-Only-2026!' | chpasswd

# Stop Kubernetes node services so node01 is used as a plain Linux target for this prototype.
systemctl stop kubelet 2>/dev/null || true
systemctl disable kubelet 2>/dev/null || true

systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
REMOTE

# Remove the Kubernetes API as an easy controlplane -> node01 bypass.
systemctl stop kubelet 2>/dev/null || true
systemctl disable kubelet 2>/dev/null || true

if command -v crictl >/dev/null 2>&1; then
  for name in kube-apiserver kube-controller-manager kube-scheduler etcd; do
    ids="$(crictl ps --name "$name" -q 2>/dev/null || true)"
    if [ -n "$ids" ]; then
      crictl stop $ids >/dev/null 2>&1 || true
    fi
  done
fi

# Record setup status for creator-side troubleshooting.
{
  echo "target_ip=$TARGET_IP"
  echo "configured_at=$(date -Is)"
  if curl -fsS --max-time 3 "http://$TARGET_IP:8080/" >/dev/null 2>&1; then
    echo "http_8080=ok"
  else
    echo "http_8080=failed"
  fi
} > /tmp/remote-forensics-setup-status.txt
