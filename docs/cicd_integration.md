# CI/CD Pipeline Security Integration Guide

Integrating **nspect** into your CI/CD pipelines allows you to enforce strict containment policies, ensuring that containers, sandboxes, or systemd services built in your pipelines do not expose host systems to breakout or privilege escalation vulnerabilities. 

---

## Failure Assertion Flags (CLI Reference)

We have extended `nspect` with a set of CI/CD-specific flags. When any of these flags are used, `nspect` evaluates the corresponding security rules and, if any rule is violated, prints a failure summary to `stderr` and exits with code **`1`**. If all checks pass, it prints a success summary and exits with code **`0`**.

| Flag | Description | Recommendation / Baseline |
| :--- | :--- | :--- |
| `--fail-score <score>` | Fails if the overall security score is below this value (0-100). | Set to `80` or higher for hardened production containers. |
| `--fail-on-shared-ns` | Fails if any critical namespace (`mnt`, `pid`, `net`, `ipc`, `uts`) is shared with the host. | Containers should always run with isolated namespaces. |
| `--fail-on-caps` | Fails if any **Critical** or **High** risk capabilities are present in the active/effective set (e.g., `CAP_SYS_ADMIN`, `CAP_SYS_RAWIO`). | Drop all capabilities by default (`--cap-drop=ALL`) and only add required ones. |
| `--fail-on-mount-risks` | Fails if any **Critical**, **High**, or **Medium** risk mounts are found (e.g., writable `/sys` or `/proc`, unhardened host-bind mounts). | Mount filesystems read-only or with `nosuid,nodev,noexec` flags. |
| `--fail-on-secrets` | Fails if any sensitive credentials/secrets are found exposed in environment variables. | Use Kubernetes Secrets, Docker Secrets, or Vault instead of env vars. |
| `--fail-on-fd-leaks` | Fails if any high-risk leaked host file descriptors are found in the target process (e.g., directory handles allowing `openat` breakout). | Set `O_CLOEXEC` on host file descriptors before spawning container engines. |
| `--fail-on-fs-risks` | Fails if any **Critical**, **High**, or **Medium** filesystem risks are found inside the container (e.g., world-writable `/etc` files or dangerous SUID/SGID binaries). | Keep container filesystems minimal, and remove SUID flags where possible. |
| `--fail-on-root` | Fails if the container is running as root on the host (`EUID=0` and not virtualized using a user namespace). | Run containers as a non-root user (`USER 1000`) or use rootless Docker/Podman. |

---

## How to Audit a Container in CI/CD

Because `nspect` performs **dynamic runtime auditing** by inspecting the `/proc` filesystem on the host, you need to:
1. Build the target container image.
2. Spin up the container in the background (or run a systemd/sandbox service).
3. Find the container process's host PID.
4. Run `nspect` against that host PID with sudo privileges (required to read namespace inodes and `/proc/[pid]/environ`).

### Locating the Container PID
You can retrieve the host PID of a container using:
* **Docker:** `docker inspect -f '{{.State.Pid}}' <container_name_or_id>`
* **Podman:** `podman inspect -f '{{.State.Pid}}' <container_name_or_id>`
* **Kubernetes (on-node):** Query container runtime socket or `crictl inspect`

---

## Integration Example: GitHub Actions

Here is a complete, working GitHub Actions workflow file (`.github/workflows/security-audit.yml`) that builds a Dockerfile, spins up a test container, audits it with `nspect`, and fails the build if the container is insecure.

```yaml
name: Container Sandbox Audit

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  nspect-audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.26'

      # 1. Compile nspect on the runner
      - name: Build nspect
        run: |
          go build -o nspect main.go
          chmod +x nspect

      # 2. Build the target application container
      - name: Build Target Image
        run: |
          docker build -t test-app:latest ./test

      # 3. Spin up the target container in the background
      - name: Run Test Container
        run: |
          docker run -d --name app-container test-app:latest
          # Wait a moment to ensure it is running
          sleep 2

      # 4. Get the host PID of the container
      - name: Get Container PID
        id: container_info
        run: |
          CONTAINER_PID=$(docker inspect -f '{{.State.Pid}}' app-container)
          echo "PID: $CONTAINER_PID"
          echo "pid=$CONTAINER_PID" >> $GITHUB_OUTPUT

      # 5. Run nspect against the container PID
      # We require sudo to access the container's namespaces and environ files.
      - name: Audit Sandbox Boundary
        run: |
          sudo ./nspect --pid ${{ steps.container_info.outputs.pid }} \
            --fail-score 85 \
            --fail-on-shared-ns \
            --fail-on-caps \
            --fail-on-mount-risks \
            --fail-on-root

      # 6. Clean up test containers
      - name: Cleanup
        if: always()
        run: |
          docker stop app-container || true
          docker rm app-container || true
```

---

## Integration Example: GitLab CI/CD

If your GitLab runner has access to Docker-in-Docker or is a shell executor on a Linux runner:

```yaml
stages:
  - test

nspect_security_audit:
  stage: test
  image: golang:1.26
  services:
    - docker:dind
  variables:
    DOCKER_HOST: tcp://docker:2376
    DOCKER_TLS_VERIFY: 1
    DOCKER_CERT_PATH: "/certs/client"
  script:
    # 1. Build nspect
    - go build -o nspect main.go
    - chmod +x nspect
    
    # 2. Build and run target container
    - docker build -t test-app:latest ./test
    - docker run -d --name app-container test-app:latest
    - sleep 2
    
    # 3. Inspect container PID
    - CONTAINER_PID=$(docker inspect -f '{{.State.Pid}}' app-container)
    
    # 4. Run audit (Note: if running inside dind, make sure the runner has privileged: true
    # to allow namespace inspections, or run nspect on a shell/VM runner)
    - ./nspect --pid $CONTAINER_PID --fail-score 80 --fail-on-root
  after_script:
    - docker stop app-container || true
    - docker rm app-container || true
```

---

## Best Practices for CI/CD Auditing

1. **Verify Rootless Boundaries:** If your containers must run as root inside the container, configure `--fail-on-root` to ensure they are at least mapped to an unprivileged namespace (user namespace mapping) so they don't have host-root authority.
2. **Exclude Dev/Test Env False Positives:** When scanning environment secrets (`--fail-on-secrets`), ensure that test-only dummy variables (e.g. `DB_PASS=testpass`) do not trigger blockages, or skip env scanning for specific mock test contexts.
3. **Graceful Cleanup:** Always include cleanup steps (e.g., `if: always()` in GitHub Actions) to stop and remove test containers, preventing orphan processes on runner hosts.
4. **Publish HTML Report Artifacts:** If a build fails, upload the `nspect` report as a build artifact in HTML format for quick, interactive developer diagnosis:
   ```bash
   sudo ./nspect --pid $CONTAINER_PID -H > nspect-report.html
   ```
   You can then use the standard CI/CD artifact uploading step to publish `nspect-report.html`.
