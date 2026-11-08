#!/usr/bin/env bash
# Installs KestreLynx on a throwaway Kubernetes cluster by the steps of the
# getting started page, and checks that it scans an image a Pod runs from a
# registry that asks for a login. Unlike the other live tests this one goes
# through the supplied manifests, the permissions they grant and the commands the
# page tells the reader to run. It then runs KestreLynx outside the cluster, as
# a container that reaches the API server with the address, token and CA set in
# its configuration, and checks the same scan, and that a certificate which does
# not carry the name used is refused unless tls_server_name gives one it does.
#
# Needs Docker, k3d, kubectl, openssl, curl and python3. The cluster, the
# registry, the images and every file are removed at the end, and the user's
# kubeconfig is not touched. Run it from the repository root.
#
# What differs from what a reader does, and why:
#   - the image is built here, with the test registry's certificate added to it;
#   - the configuration scans one namespace, so the cluster's own images do not
#     lengthen the run, and sends every report to a webhook the test can read.
set -euo pipefail

id="$$"
cluster="kx-k8s-$id"
net="kx-k8s-$id"
registry_name="kx-k8s-registry-$id"
outside_name="kx-k8s-outside-$id"
outside_hook="kx-k8s-hook-$id"
image="kx-k8s-test:$id"
# A fixed subnet, because the certificate has to name the address before the
# registry starts. It is private on purpose: that is what a registry on the
# user's own network looks like to KestreLynx's address rules.
subnet="172.30.77.0/24"
registry_ip="172.30.77.200"
registry="$registry_ip:5443"
private_ref="$registry/kx/app:1.2.3"
public_ref="python:3.14-alpine"
user=klive
cycle_limit=1200

work="$(mktemp -d)"
chmod 700 "$work"
repo="$work/repo"
export KUBECONFIG="$work/kubeconfig"

# The commands the page gives, kept word for word. check_docs fails when the page
# no longer has them, so the page and this test cannot drift apart unnoticed.
cmd_namespace='kubectl create namespace kestrelynx'
cmd_apply='kubectl apply -f deploy/kubernetes/'
cmd_rollout='kubectl rollout status -n kestrelynx deployment/kestrelynx'
cmd_logs='kubectl logs -n kestrelynx deployment/kestrelynx -f'
cmd_config="sed '1,/config.yml: |/d; s/^    //' deploy/kubernetes/configmap.yaml > config.yml"
cmd_secret='kubectl create secret generic kestrelynx-config \
  --namespace kestrelynx \
  --from-file=config.yml=config.yml \
  --save-config'
cmd_secret_update='kubectl create secret generic kestrelynx-config \
  --namespace kestrelynx \
  --from-file=config.yml=config.yml \
  --dry-run=client -o yaml | kubectl apply -f -'
cmd_restart='kubectl rollout restart -n kestrelynx deployment/kestrelynx'
secret_volume='- name: config
  secret:
    secretName: kestrelynx-config'
# Running outside the cluster.
cmd_out_account='kubectl apply -f deploy/kubernetes/serviceaccount.yaml \
  -f deploy/kubernetes/clusterrole.yaml \
  -f deploy/kubernetes/clusterrolebinding.yaml'
cmd_out_token="kubectl apply -f - <<'EOF'
apiVersion: v1
kind: Secret
metadata:
  name: kestrelynx-token
  namespace: kestrelynx
  annotations:
    kubernetes.io/service-account.name: kestrelynx
type: kubernetes.io/service-account-token
EOF
kubectl wait -n kestrelynx secret/kestrelynx-token --for=jsonpath='{.data.token}'"
cmd_out_files="kubectl get secret -n kestrelynx kestrelynx-token -o jsonpath='{.data.token}' | base64 -d > token
kubectl get secret -n kestrelynx kestrelynx-token -o jsonpath='{.data.ca\.crt}' | base64 -d > ca.crt
chmod 600 token"
cmd_out_server="kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}'"
out_config='kubernetes:
  enabled: true
  api_server: "https://kubernetes.example.com:6443"
  token_file: /etc/kestrelynx/token
  ca_file: /etc/kestrelynx/ca.crt'
cmd_out_run='docker run -d --name kestrelynx \
  --restart unless-stopped \
  -e TZ=UTC \
  -v "$PWD/config.yml:/etc/kestrelynx/config.yml:ro" \
  -v "$PWD/token:/etc/kestrelynx/token:ro" \
  -v "$PWD/ca.crt:/etc/kestrelynx/ca.crt:ro" \
  -v kestrelynx-state:/var/lib/kestrelynx \
  ghcr.io/kitsunetrail/kestrelynx:latest
docker logs -f kestrelynx'

diagnostics() {
  echo "--- pods" >&2
  kubectl get pods -A -o wide >&2 || true
  echo "--- kestrelynx pod" >&2
  kubectl describe pod -n kestrelynx -l app=kestrelynx >&2 || true
  echo "--- kestrelynx log" >&2
  kubectl logs -n kestrelynx deployment/kestrelynx --tail=200 >&2 || true
  echo "--- events" >&2
  kubectl get events -A --sort-by=.lastTimestamp >&2 || true
}

cleanup() {
  local status=$?
  trap - EXIT
  if [ "$status" != 0 ] && [ -s "$KUBECONFIG" ]; then
    diagnostics
  fi
  k3d cluster delete "$cluster" >/dev/null 2>&1 || true
  docker rm -fv "$outside_name" "$outside_hook" "$registry_name" >/dev/null 2>&1 || true
  docker volume rm "$outside_name" >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  docker rmi -f "$image" "$image-base" >/dev/null 2>&1 || true
  if [ -n "${host_registry:-}" ]; then
    docker rmi -f "$host_registry/kx/app:1.2.3" >/dev/null 2>&1 || true
  fi
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

check_docs() { # each file must hold each block, however far the block is indented
  python3 - "$@" <<'EOF'
import sys

def lines(text):
    # A line of only spaces counts as empty; any other line is kept as it is,
    # trailing spaces included, since a space after a line-continuing backslash
    # or an empty line inside a command breaks the command.
    return [line if line.strip() else "" for line in text.splitlines()]

def dedent(block):
    # Only the indentation the lines share goes, so YAML that loses its
    # structure on the page no longer matches.
    n = min((len(line) - len(line.lstrip(" ")) for line in block if line), default=0)
    return [line[n:] for line in block]

missing = False
docs, blocks = sys.argv[1:3], sys.argv[3:]
for path in docs:
    with open(path, encoding="utf-8") as f:
        doc = lines(f.read())
    for block in blocks:
        want = dedent(lines(block.strip("\n")))
        if not any(dedent(doc[i : i + len(want)]) == want for i in range(len(doc) - len(want) + 1)):
            print(f"{path} no longer has:\n{block}", file=sys.stderr)
            missing = True
sys.exit(1 if missing else 0)
EOF
}

edit() { # file, old text, new text; the old text must occur exactly once
  python3 - "$@" <<'EOF'
import sys

path, old, new = sys.argv[1:]
with open(path, encoding="utf-8") as f:
    text = f.read()
if text.count(old) != 1:
    sys.exit(f"{path}: expected one occurrence of {old!r}, found {text.count(old)}")
with open(path, "w", encoding="utf-8") as f:
    f.write(text.replace(old, new))
EOF
}

replace() { # text, old, new; the old text must occur exactly once
  python3 -c '
import sys
text, old, new = sys.argv[1:]
if text.count(old) != 1:
    sys.exit(f"expected one occurrence of {old!r}, found {text.count(old)}")
sys.stdout.write(text.replace(old, new))
' "$@"
}

run() { # a command from the page, in the copy of the repository
  echo "+ $1"
  (cd "$repo" && bash -euo pipefail -c "$1")
}

wait_for_cycle() { # the scan cycle of the current Pod has ended
  kubectl rollout status -n kestrelynx deployment/kestrelynx --timeout=300s
  local waited=0
  until kubectl logs -n kestrelynx deployment/kestrelynx 2>/dev/null | grep -q 'msg="next scan scheduled"'; do
    if [ "$waited" -ge "$cycle_limit" ]; then
      fail "no scan cycle ended within ${cycle_limit}s"
    fi
    sleep 5
    waited=$((waited + 5))
  done
}

reports=0
check_cycle() { # step name, ok or failed for the private image, plan or noplan
  local step="$1" want="$2" plan="$3" log="$work/kestrelynx.log" hooks="$work/webhook.log"
  echo "--- checking: $step"
  wait_for_cycle
  kubectl logs -n kestrelynx deployment/kestrelynx >"$log"
  kubectl logs -n kx-app pod/webhook | sed -n 's/^BODY //p' >"$hooks"

  if grep 'scan cycle failed' "$log"; then
    fail "$step: the scan cycle failed"
  fi
  grep -q "msg=\"scanned image\" ref=[^ ]*$public_ref " "$log" || fail "$step: the public image was not scanned"

  local scanned=0 failed=0
  grep -q "msg=\"scanned image\" ref=$private_ref content_id=$digest " "$log" && scanned=1
  grep -q "msg=\"image scan failed\" image=$private_ref " "$log" && failed=1
  case "$want" in
    ok) [ "$scanned" = 1 ] && [ "$failed" = 0 ] || fail "$step: the private image should have been scanned" ;;
    failed) [ "$scanned" = 0 ] && [ "$failed" = 1 ] || fail "$step: the private image should have failed to scan" ;;
  esac
  if grep -i 'forbidden' "$log"; then
    fail "$step: the supplied permissions were not enough"
  fi

  local count
  count="$(wc -l <"$hooks")"
  [ "$count" -gt "$reports" ] || fail "$step: no report reached the webhook"
  reports="$count"
  tail -n 1 "$hooks" | check_report "$step" "$want" "$plan"
  echo "ok: $step"
}

check_report() { # step name, ok or failed, plan or noplan; the report on stdin
  python3 -c '
import json, sys

step, want, plan, ref = sys.argv[1:]
report = json.load(sys.stdin)
errors = [e["image"] for e in report["scan_errors"]]
if want == "ok" and ref in errors:
    sys.exit(f"{step}: the report lists the private image as failed: {errors}")
if want == "failed" and ref not in errors:
    sys.exit(f"{step}: the report does not list the private image as failed: {errors}")
if plan == "plan":
    status = report.get("remediation", {}).get("status")
    if status != "ok":
        sys.exit(f"{step}: the report has no usable fix plan: {status}")
elif "remediation" in report:
    sys.exit(f"{step}: the report has a fix plan although it is off")
' "$1" "$2" "$3" "$private_ref"
}

check_docs docs/documentation/getting-started.md docs-ja/documentation/getting-started.md \
  "$cmd_namespace" "$cmd_apply
$cmd_rollout
$cmd_logs" "$cmd_config" "$cmd_secret" "$cmd_secret_update" "$cmd_restart" "$secret_volume" \
  "$cmd_namespace
$cmd_out_account" "$cmd_out_token" "$cmd_out_files" "$cmd_out_server" "$out_config" "$cmd_out_run"
check_docs README.md README.ja.md "$cmd_apply
$cmd_rollout
$cmd_logs"

echo "--- building the image"
docker build -q -t "$image-base" . >/dev/null

echo "--- starting the registry"
mkdir "$work/auth" "$work/certs" "$work/image"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=kx-k8s" \
  -keyout "$work/certs/key.pem" -out "$work/certs/cert.pem" \
  -addext "subjectAltName=IP:$registry_ip,IP:127.0.0.1" 2>/dev/null
# The registry container reads the key as another user.
chmod 755 "$work"
chmod 644 "$work/certs/key.pem"
password="$(openssl rand -hex 16)"
docker run --rm httpd:2-alpine htpasswd -Bbn "$user" "$password" >"$work/auth/htpasswd"

docker network create --subnet "$subnet" "$net" >/dev/null
docker run -d --name "$registry_name" --network "$net" --ip "$registry_ip" -p 127.0.0.1::5443 \
  -v "$work/auth:/auth:ro" -v "$work/certs:/certs:ro" \
  -e REGISTRY_HTTP_ADDR=0.0.0.0:5443 \
  -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/cert.pem \
  -e REGISTRY_HTTP_TLS_KEY=/certs/key.pem \
  -e REGISTRY_AUTH=htpasswd \
  -e REGISTRY_AUTH_HTPASSWD_REALM=kx \
  -e REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd \
  registry:2 >/dev/null
host_registry="$(docker port "$registry_name" 5443/tcp | head -n 1)"

code=""
for _ in $(seq 1 30); do
  code="$(curl -s -o /dev/null -w '%{http_code}' --cacert "$work/certs/cert.pem" "https://$host_registry/v2/" || true)"
  [ "$code" = 401 ] && break
  sleep 1
done
[ "$code" = 401 ] || fail "the registry did not come up asking for a login (last answer: $code)"

# Docker accepts the certificate only for a loopback address, which it treats as
# an insecure registry.
mkdir "$work/docker"
docker --config "$work/docker" login "$host_registry" -u "$user" --password-stdin <<<"$password" >/dev/null 2>&1
docker pull -q --platform linux/amd64 alpine:3.19 >/dev/null
docker tag alpine:3.19 "$host_registry/kx/app:1.2.3"
docker --config "$work/docker" push -q "$host_registry/kx/app:1.2.3" >/dev/null

digest="$(curl -fsSI --cacert "$work/certs/cert.pem" -u "$user:$password" \
  -H 'Accept: application/vnd.oci.image.index.v1+json' \
  -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
  -H 'Accept: application/vnd.docker.distribution.manifest.list.v2+json' \
  -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' \
  "https://$host_registry/v2/kx/app/manifests/1.2.3" | tr -d '\r' | sed -n 's/^[Dd]ocker-[Cc]ontent-[Dd]igest: //p')"
[ -n "$digest" ] || fail "could not read the digest of kx/app:1.2.3"

cp "$work/certs/cert.pem" "$work/image/ca.pem"
cat >"$work/image/Dockerfile" <<EOF
FROM $image-base
COPY ca.pem /tmp/ca.pem
RUN cat /tmp/ca.pem >>/etc/ssl/certs/ca-certificates.crt && rm /tmp/ca.pem
EOF
docker build -q -t "$image" "$work/image" >/dev/null

echo "--- starting the cluster"
# Only the node's own pull of the Pod's image skips the certificate check.
# KestreLynx and its Trivy check it against the certificate added to the image.
cat >"$work/registries.yaml" <<EOF
configs:
  "$registry":
    tls:
      insecure_skip_verify: true
EOF
k3d cluster create "$cluster" --network "$net" --registry-config "$work/registries.yaml" \
  --no-lb --wait --timeout 300s \
  --k3s-arg '--disable=traefik,metrics-server@server:*' \
  --kubeconfig-update-default=false --kubeconfig-switch-context=false >/dev/null
k3d kubeconfig get "$cluster" >"$KUBECONFIG"
chmod 600 "$KUBECONFIG"
k3d image import -c "$cluster" "$image" >/dev/null

echo "--- starting the Pods to scan"
kubectl create namespace kx-app
kubectl create secret docker-registry pull -n kx-app \
  --docker-server="$registry" --docker-username="$user" --docker-password="$password"
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: private-app
  namespace: kx-app
spec:
  imagePullSecrets:
    - name: pull
  containers:
    - name: app
      image: $private_ref
      command: ["sleep", "86400"]
---
apiVersion: v1
kind: Pod
metadata:
  name: webhook
  namespace: kx-app
  labels:
    app: webhook
spec:
  containers:
    - name: receiver
      image: $public_ref
      command:
        - python
        - -c
        - |
          import http.server
          class Handler(http.server.BaseHTTPRequestHandler):
              def do_POST(self):
                  body = self.rfile.read(int(self.headers["Content-Length"]))
                  print("BODY", body.decode(), flush=True)
                  self.send_response(204)
                  self.end_headers()
              def log_message(self, *args):
                  pass
          http.server.HTTPServer(("", 8080), Handler).serve_forever()
---
apiVersion: v1
kind: Service
metadata:
  name: webhook
  namespace: kx-app
spec:
  selector:
    app: webhook
  ports:
    - port: 8080
EOF
kubectl wait --for=condition=Ready -n kx-app pod/private-app pod/webhook --timeout=300s

mkdir "$repo"
cp -R deploy "$repo/deploy"
manifests="$repo/deploy/kubernetes"

# The steps of "Start KestreLynx".
edit "$manifests/deployment.yaml" 'image: ghcr.io/kitsunetrail/kestrelynx:latest' "image: $image"
edit "$manifests/configmap.yaml" 'slack_webhook_url: ""' 'generic_webhook_url: "http://webhook.kx-app:8080/"'
edit "$manifests/configmap.yaml" 'namespaces: []' 'namespaces: [kx-app]'
edit "$manifests/configmap.yaml" 'mode: "diff"' 'mode: "full"'
edit "$manifests/configmap.yaml" 'notify_on_clean: false' 'notify_on_clean: true'
run "$cmd_namespace"
run "$cmd_apply"
run "timeout 300 $cmd_rollout"
# The log follows until it is stopped, so the time limit ending it is the good case.
echo "+ $cmd_logs"
follow=0
(cd "$repo" && timeout 30 bash -c "$cmd_logs") >"$work/follow.log" 2>&1 || follow=$?
[ "$follow" = 124 ] || fail "following the log ended by itself with status $follow"
grep -q 'msg="kestrelynx started"' "$work/follow.log" || fail "following the log did not show the start"
check_cycle "no login: the private image fails and the public one is scanned" failed noplan

# The steps of "Authenticate to private registries". Step 1 takes what is under
# config.yml: in the ConfigMap, which has already been edited above.
run "$cmd_config"
chmod 600 "$repo/config.yml"
cp "$repo/config.yml" "$work/config-no-login.yml"

write_config() { # the password to log in with, then any extra top-level YAML
  cp "$work/config-no-login.yml" "$repo/config.yml"
  cat >>"$repo/config.yml" <<EOF

registries:
  - host: $registry
    username: $user
    password: "$1"
${2:-}
EOF
}

# A login added to a config that kept the ConfigMap's indentation would not be
# read, so such a file must stop the program from starting.
{
  sed '1,/config.yml: |/d' "$manifests/configmap.yaml"
  printf '\nregistries:\n  - host: %s\n    username: %s\n    password: "%s"\n' "$registry" "$user" "$password"
} >"$work/indented.yml"
chmod 644 "$work/indented.yml"
if docker run --rm -v "$work/indented.yml:/indented.yml:ro" "$image" --config /indented.yml >"$work/indented.log" 2>&1; then
  fail "the program started with a config whose login it would not read"
fi
grep -q 'after its first YAML document' "$work/indented.log" || {
  cat "$work/indented.log" >&2
  fail "the program did not refuse the indented config for the expected reason"
}
echo "ok: a config that kept the ConfigMap's indentation is refused"

write_config "$password"
run "$cmd_secret"
edit "$manifests/deployment.yaml" '- name: config
          configMap:
            name: kestrelynx-config' "$(sed 's/^/        /' <<<"$secret_volume" | sed '1s/^ *//')"
run "$cmd_apply"
check_cycle "the right login: the private image is scanned" ok noplan

# Changing the settings afterwards, by the commands the page gives for it.
write_config "not-$password"
run "$cmd_secret_update"
run "$cmd_restart"
check_cycle "a wrong login: the private image fails" failed noplan

# The fix plan switches the cycle to another scanner and lists more resources.
write_config "$password" 'remediation:
  enabled: true'
run "$cmd_secret_update"
run "$cmd_restart"
check_cycle "the right login with the fix plan on: the private image is scanned" ok plan

# The steps of "Run outside the cluster": KestreLynx runs as a plain container
# that reaches the API server over the network, with the address, a token of the
# supplied ServiceAccount and the cluster's CA given in the configuration. The
# namespace already exists, so that one command is only checked on the page.
echo "--- running outside the cluster"
# What the steps inside the cluster created goes first, so the scans below have
# only what these steps create, and a step missing from the page shows.
(cd "$repo" && kubectl delete -f deploy/kubernetes/ --wait=true >/dev/null)
for kind in serviceaccount/kestrelynx clusterrole/kestrelynx clusterrolebinding/kestrelynx; do
  if kubectl get -n kestrelynx "$kind" >/dev/null 2>&1; then
    fail "$kind is still there after removing the in-cluster install"
  fi
done
run "$cmd_out_account"
run "$cmd_out_token"
run "$cmd_out_files"
[ -s "$repo/token" ] || fail "the token was not saved"
grep -q 'BEGIN CERTIFICATE' "$repo/ca.crt" || fail "the cluster CA was not saved"
[ "$(stat -c %a "$repo/token")" = 600 ] || fail "the token can be read by others"
server="$(run "$cmd_out_server" | tail -n 1)"
case "$server" in
  https://*) ;;
  *) fail "the command for the API server's URL printed $server" ;;
esac

api_ip="$(docker inspect -f "{{(index .NetworkSettings.Networks \"$net\").IPAddress}}" "k3d-$cluster-server-0")"
[ -n "$api_ip" ] || fail "could not find the address of the API server"
# A name the API server's certificate does not carry, as a load balancer or a
# DNS name in front of a cluster can be.
api_name="kx-apiserver.test"

docker run -d --name "$outside_hook" --network "$net" "$public_ref" python -c '
import http.server
class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        print("BODY", body.decode(), flush=True)
        self.send_response(204)
        self.end_headers()
    def log_message(self, *args):
        pass
http.server.HTTPServer(("", 8080), Handler).serve_forever()
' >/dev/null

outside_reports=0
check_outside() { # step name, API server URL, TLS server name, ok or refused
  local step="$1" url="$2" server_name="$3" want="$4" log="$work/outside.log" hooks="$work/outside-hooks.log"
  echo "--- checking: $step"
  # The page's kubernetes block with this cluster's address, and what the test
  # needs besides: a webhook it can read, one namespace, the login and the plan.
  local kube="${out_config/https:\/\/kubernetes.example.com:6443/$url}"
  [ "$kube" != "$out_config" ] || fail "the page's kubernetes block has no api_server to replace"
  cat >"$repo/config.yml" <<EOF
notify:
  generic_webhook_url: "http://$outside_hook:8080/"
  mode: "full"
  notify_on_clean: true
$kube
  tls_server_name: "$server_name"
  namespaces: [kx-app]
registries:
  - host: $registry
    username: $user
    password: "$password"
remediation:
  enabled: true
EOF
  chmod 600 "$repo/config.yml"

  # The page's docker run, as another container on the cluster's network that
  # resolves the extra name to the API server, with the image built here.
  local cmd="$cmd_out_run"
  cmd="$(replace "$cmd" '--name kestrelynx ' "--name $outside_name --network $net --add-host $api_name:$api_ip ")"
  cmd="$(replace "$cmd" 'kestrelynx-state:' "$outside_name:")"
  cmd="$(replace "$cmd" 'ghcr.io/kitsunetrail/kestrelynx:latest' "$image")"
  cmd="$(replace "$cmd" $'\ndocker logs -f kestrelynx' '')"
  docker rm -fv "$outside_name" >/dev/null 2>&1 || true
  run "$cmd" >/dev/null

  local waited=0
  until docker logs "$outside_name" 2>&1 | grep -q 'msg="next scan scheduled"'; do
    docker inspect -f '{{.State.Running}}' "$outside_name" | grep -q true || {
      docker logs "$outside_name" >&2
      fail "$step: KestreLynx stopped"
    }
    [ "$waited" -lt "$cycle_limit" ] || fail "$step: no scan cycle ended within ${cycle_limit}s"
    sleep 5
    waited=$((waited + 5))
  done
  docker logs "$outside_name" >"$log" 2>&1
  docker logs "$outside_hook" 2>/dev/null | sed -n 's/^BODY //p' >"$hooks"

  if grep -i 'forbidden' "$log"; then
    fail "$step: the supplied permissions were not enough"
  fi
  # Outside a Pod there is no Pod of its own to wait for.
  if grep 'did not show as running' "$log"; then
    fail "$step: KestreLynx waited for a Pod of its own"
  fi
  case "$want" in
    ok)
      if grep 'scan cycle failed' "$log"; then
        fail "$step: the scan cycle failed"
      fi
      grep -q "msg=\"scanned image\" ref=[^ ]*$public_ref " "$log" || fail "$step: the public image was not scanned"
      grep -q "msg=\"scanned image\" ref=$private_ref content_id=$digest " "$log" || fail "$step: the private image was not scanned"
      local count
      count="$(wc -l <"$hooks")"
      [ "$count" -gt "$outside_reports" ] || fail "$step: no report reached the webhook"
      outside_reports="$count"
      tail -n 1 "$hooks" | check_report "$step" ok plan
      ;;
    refused)
      grep 'initial scan cycle failed' "$log" | grep -q 'x509' || {
        cat "$log" >&2
        fail "$step: the API server's certificate was not refused"
      }
      if grep -q 'msg="scanned image"' "$log"; then
        fail "$step: images were scanned without a trusted connection"
      fi
      ;;
  esac
  echo "ok: $step"
}

check_outside "outside, by the API server's address: both images are scanned with the fix plan on" \
  "https://$api_ip:6443" "" ok
check_outside "outside, by a name its certificate does not carry: the connection is refused" \
  "https://$api_name:6443" "" refused
check_outside "outside, by that name with tls_server_name: both images are scanned" \
  "https://$api_name:6443" "kubernetes" ok

echo "passed"
