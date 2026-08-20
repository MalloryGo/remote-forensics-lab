#!/bin/bash
set -u

TARGET_HOST="node01"
TARGET_IP="172.30.2.2"
STATUS_FILE="/tmp/remote-forensics-setup-status.txt"

# Wait until the second host is reachable through Killercoda's bootstrap SSH path.
for i in $(seq 1 30); do
  if ssh -o BatchMode=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=no "$TARGET_HOST" true 2>/dev/null; then
    break
  fi
  sleep 1
done

# Configure node01 while the platform bootstrap path is still available.
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

# Start a deliberately simple HTTP service for the isolation test.
pkill -f 'python3 -m http.server 8080 --directory /srv/remote-forensics-test' 2>/dev/null || true
nohup python3 -m http.server 8080 --bind 0.0.0.0 --directory /srv/remote-forensics-test \
  >/var/log/remote-forensics-test-http.log 2>&1 </dev/null &

# Temporary non-root account used only to prove that normal SSH still works.
id -u rf_test >/dev/null 2>&1 || useradd -m -s /bin/bash rf_test
echo 'rf_test:RF-Test-Only-2026!' | chpasswd

# Put our SSH policy first. OpenSSH uses the first obtained value for many options,
# so 00-* intentionally precedes Killercoda's existing drop-ins.
mkdir -p /etc/ssh/sshd_config.d
rm -f /etc/ssh/sshd_config.d/99-remote-forensics.conf
cat > /etc/ssh/sshd_config.d/00-remote-forensics.conf <<'EOF'
PermitRootLogin no
PasswordAuthentication yes
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AllowUsers rf_test
EOF
chmod 600 /etc/ssh/sshd_config.d/00-remote-forensics.conf

# Remove the platform-provided root trust material after setup has completed.
rm -f /root/.ssh/authorized_keys /root/.ssh/authorized_keys2 2>/dev/null || true
passwd -l root >/dev/null 2>&1 || true

# Stop and mask Kubernetes on the target. The target is used as a plain Linux host.
systemctl mask --now kubelet >/dev/null 2>&1 || true
rm -f /root/.kube/config /etc/kubernetes/admin.conf 2>/dev/null || true

# Validate and reload SSH policy.
/usr/sbin/sshd -t
systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
REMOTE

# Disable Kubernetes on the contestant workstation as an obvious bypass to node01.
systemctl mask --now kubelet >/dev/null 2>&1 || true

if command -v crictl >/dev/null 2>&1; then
  for name in kube-apiserver kube-controller-manager kube-scheduler etcd; do
    ids="$(crictl ps --name "$name" -q 2>/dev/null || true)"
    if [ -n "$ids" ]; then
      crictl stop $ids >/dev/null 2>&1 || true
    fi
  done
fi

# Belt-and-suspenders: kill any remaining local control-plane listeners/processes.
pkill -f 'kube-apiserver' 2>/dev/null || true
pkill -f 'kube-controller-manager' 2>/dev/null || true
pkill -f 'kube-scheduler' 2>/dev/null || true
pkill -f 'etcd.*--' 2>/dev/null || true
rm -f /root/.kube/config /etc/kubernetes/admin.conf 2>/dev/null || true

# Creator-side status file. No competition answers are stored here.
{
  echo "target_ip=$TARGET_IP"
  echo "configured_at=$(date -Is)"

  if curl -fsS --max-time 3 "http://$TARGET_IP:8080/" >/dev/null 2>&1; then
    echo "http_8080=ok"
  else
    echo "http_8080=failed"
  fi

  if ssh -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=no root@"$TARGET_IP" true >/dev/null 2>&1; then
    echo "root_ssh=FAILED_OPEN"
  else
    echo "root_ssh=blocked"
  fi

  if timeout 4 kubectl get nodes >/dev/null 2>&1; then
    echo "kubectl=FAILED_OPEN"
  else
    echo "kubectl=blocked"
  fi
} > "$STATUS_FILE"
