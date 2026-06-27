# nspect

**nspect** is a lightweight, zero-dependency Go tool designed to audit the namespace isolation, kernel capabilities, filesystem mount vulnerabilities, environment variables, socket configurations, and file descriptor limits of containers, sandboxes, or system services.

Whether validating Docker configurations, Kubernetes pods, systemd sandboxes, Snap packages, or running system processes, **nspect** parses runtime metrics directly from the `/proc` filesystem to report an overall security exposure score and recommended remediation steps.

---

## Why nspect is Unique

Unlike static config parsers or traditional local privilege escalation scripts (like `linpeas`), `nspect` is built specifically for **dynamic runtime containment auditing**:

1. **Host-Side, Zero-API Auto-Discovery:** It discovers running containers, Snaps, and systemd sandboxes purely by analyzing `/proc` namespace inodes. No Docker socket or daemon API access is required.
2. **Inner-Namespace Socket Map:** It decodes active TCP/UDP ports inside isolated container network namespaces directly from the host.
3. **Advanced Sandbox Gaps:** It audits sophisticated escape vectors, such as inherited host directory file descriptors (FD leaks) and active user-namespace capability overrides.
4. **Statically Compilable:** Zero dependencies, compiling to a single lightweight binary you can copy anywhere.

---

## Ideal Use Cases

### 🛡️ Configuration Hardening (Defensive / Blue Team)
- **Sandbox Validation:** Verify that systemd daemons with sandboxing options (like `PrivateTmp` or `NoNewPrivileges`) are running with correct kernel constraints.
- **CI/CD Security Verification:** Audit container configurations post-deployment to ensure no writeable `/proc` or `/sys` filesystems are exposed.
- **Credential Protection:** Validate that container deployments do not leak plaintext API keys or database passwords in environment variables.

### ⚔️ Penetration Testing & Red Teaming (Offensive)
- **Escape Vector Identification:** Instantly identify container escape paths on a target host (e.g., finding `CAP_SYS_ADMIN`, writable `/proc`, or leaked directory FDs).
- **Post-Exploitation Enumeration:** Run `nspect` as a standalone binary to map internal container ports, secrets, and other sandboxed services running on the machine.

---

## Features

- **Namespace Auditing:** Compares process namespaces (`ipc`, `uts`, `mnt`, `net`, `pid`, `user`, `cgroup`, `time`) with baseline contexts to identify boundary leaks.
- **Capability Analysis:** Decodes hex capability bitmasks (`CapEff`, `CapPrm`, `CapBnd`) against a security risk matrix. Automatically adjusts risk weightings for rootless/non-root environments.
- **Mount Exposure Scan:** Parses mount points to detect writable kernel interfaces (`/sys`, `/proc`), runtime control sockets (Docker, containerd, podman), and missing filesystem hardening flags (`nosuid`, `nodev`, `noexec`).
- **Security Context Audit:** Audits user namespace mapping (rootless vs. root), Seccomp status, LSM profile states (AppArmor/SELinux), and the `NoNewPrivileges` configuration.
- **Environment Secret Scanner:** Decodes `/proc/[pid]/environ` to scan for key patterns pointing to credentials, tokens, or passwords (`*PASS*`, `*SECRET*`, `*KEY*`, `*TOKEN*`), displaying them masked to avoid output leakage.
- **Inner-Namespace Socket Analyzer:** Directly parses `/proc/[pid]/net/tcp` and `/proc/[pid]/net/tcp6` inside target network namespaces, exposing active listening ports and connections without needing namespace-entering tools.
- **FD Leak Detector:** Catalogue `/proc/[pid]/fd/` descriptors and alerts on inherited host directories (abuseable via `openat`), raw storage blocks, or critical configuration files.
- **Process Auto-Detection:** Automatically lists all isolated sandboxes and containers currently running on the host without depending on external Docker/containerd APIs.
- **Zero-Dependency Portability:** Compiled into a single, statically-linked binary, making it extremely easy to copy and run on target hosts during security assessments.

---

## Installation & Build

Build the binary using the provided `Makefile`:

```bash
# Clone the repository and build
git clone https://github.com/davidvhk/nspect.git
cd nspect
make
```

This compiles a statically-linked binary named `nspect` in the project root.

### Building Debian (.deb) & Red Hat (.rpm) Packages
To package the auditor for system installation, run:

```bash
make package
```

This will output:
- **Debian Package:** `nspect_0.0.1_amd64.deb` (install with `sudo dpkg -i nspect_0.0.1_amd64.deb`)
- **RPM Package:** `nspect-0.0.1-1.x86_64.rpm` (install with `sudo rpm -ivh nspect-0.0.1-1.x86_64.rpm`)

---

## Usage

### 1. List Isolated Processes (Containers & Sandboxes)
Scan the host for processes running in isolated namespaces (Docker, Podman, LXC, systemd-nspawn, Snap):

```bash
./nspect --list
```

> **Note:** To see all isolated processes running on the host, run the command with root privileges (`sudo ./nspect --list`).

### 2. Audit a Target Process
Analyze the sandbox boundaries of a target process using its PID:

```bash
./nspect --pid <PID>
```

For example, to audit your current shell context:
```bash
./nspect --pid $$
```

### 3. Mask Sensitive Environment Variables
By default, `nspect` displays the values of environment variables identified as sensitive (e.g. passwords, paths, keys) in plaintext. You can optionally mask them with:

```bash
./nspect --pid <PID> --mask
# Or using the shorthand:
./nspect --pid <PID> -m
```

### 4. Generate JSON Reports
For programmatic consumption, compliance auditing, or integration with security pipelines:

```bash
./nspect --pid <PID> --json
```

### 5. Example CLI Report Output

Running `nspect` prints a comprehensive isolation dashboard:

```text
=== LINUX CONTAINER & SANDBOX AUDIT REPORT ===
Target Process: snapd-desktop-i (PID: 2742)
Command Line:  /snap/snapd-desktop-integration/361/usr/bin/snapd-desktop-integration
Security Score: 65/100
------------------------------------------------------------

[1] NAMESPACE ISOLATION (Score: 15/100)
  - cgroup   : SHARED WITH HOST (Target Inode: 4026531835)
    Risk: Shares cgroup namespace with host. May leak host cgroup layout information.
  - ipc      : SHARED WITH HOST (Target Inode: 4026531839)
    Risk: Shares IPC namespace with host. The container can access host shared memory, semaphores, and message queues.
  - mnt      : ISOLATED (Target Inode: 4026532885)
  - net      : SHARED WITH HOST (Target Inode: 4026531840)
    Risk: Shares Network namespace with host. The container shares host interfaces, socket tables, and can sniff network traffic.
  - pid      : SHARED WITH HOST (Target Inode: 4026531836)
    Risk: Shares PID namespace with host. The container can view, trace, and terminate host processes.
  - user     : SHARED WITH HOST (Target Inode: 4026531837)
    Risk: Shares User namespace with host. No UID/GID virtualization is active.
  - uts      : SHARED WITH HOST (Target Inode: 4026531838)
    Risk: Shares UTS namespace with host. The container shares the host hostname, allowing modification.
  - time     : SHARED WITH HOST (Target Inode: 4026531834)
    Risk: Shares time namespace with host.

[2] PROCESS SECURITY CONTEXT (Score: 85/100)
  - User Context : UID=1000, EUID=1000
  - Seccomp      : Enabled (Filter)
  - NoNewPrivs   : No
  - LSM Status   : snap.snapd-desktop-integration.snapd-desktop-integration (enforce)
  Hardening Issues Identified:
    * NoNewPrivs flag is not set. Subprocesses can gain new privileges via SUID binaries or file capabilities.

[3] LINUX CAPABILITIES (Score: 100/100)
  - Effective Capabilities: [None / Dropped]
  - No critical capabilities found in active set.

[4] MOUNT & VOLUME EXPOSURE (Score: 44/100)
  - Total Mount Points Evaluated: 1329
  Mount Exposures Discovered:
    * Low none -> Mounted at / (tmpfs)
      Description: Root filesystem is mounted read-write. Hardened containers should utilize a read-only root filesystem with ephemeral tmpfs volumes where writing is needed.
    * High udev -> Mounted at /dev (devtmpfs)
      Description: Writable /dev or devtmpfs. Allows processes (with CAP_MKNOD or raw device write) to create raw physical drive nodes (e.g. sda) and read/write host filesystems directly.
    * Low tmpfs -> Mounted at /dev/shm (tmpfs)
      Description: Writable directory /dev/shm is missing hardening flags: noexec. An attacker can write and execute files or construct SUID payloads here.
    * Info proc -> Mounted at /proc (proc)
      Description: Writable /proc filesystem mount detected, but write access is restricted by the active LSM profile (snap.snapd-desktop-integration.snapd-desktop-integration (enforce)), preventing security exposure.
    * Info systemd-1 -> Mounted at /proc/sys/fs/binfmt_misc (autofs)
      Description: Writable /proc filesystem mount detected, but write access is restricted by the active LSM profile (snap.snapd-desktop-integration.snapd-desktop-integration (enforce)), preventing security exposure.
    * Info binfmt_misc -> Mounted at /proc/sys/fs/binfmt_misc (binfmt_misc)
      Description: Writable /proc filesystem mount detected, but write access is restricted by the active LSM profile (snap.snapd-desktop-integration.snapd-desktop-integration (enforce)), preventing security exposure.
    * Info sysfs -> Mounted at /sys (sysfs)
      Description: Writable /sys filesystem mount detected, but write access is restricted by the active LSM profile (snap.snapd-desktop-integration.snapd-desktop-integration (enforce)), preventing security exposure.
    * Info securityfs -> Mounted at /sys/kernel/security (securityfs)
      Description: Writable /sys filesystem mount detected, but write access is restricted by the active LSM profile (snap.snapd-desktop-integration.snapd-desktop-integration (enforce)), preventing security exposure.
    * Info cgroup2 -> Mounted at /sys/fs/cgroup (cgroup2)
      Description: Writable /sys filesystem mount detected, but write access is restricted by the active LSM profile (snap.snapd-desktop-integration.snapd-desktop-integration (enforce)), preventing security exposure.
    * Info pstore -> Mounted at /sys/fs/pstore (pstore)
      Description: Writable /sys filesystem mount detected, but write access is restricted by the active LSM profile (snap.snapd-desktop-integration.snapd-desktop-integration (enforce)), preventing security exposure.
    * Info efivarfs -> Mounted at /sys/firmware/efi/efivars (efivarfs)
      Description: Writable /sys filesystem mount detected, but write access is restricted by the active LSM profile (snap.snapd-desktop-integration.snapd-desktop-integration (enforce)), preventing security exposure.
    * Info bpf -> Mounted at /sys/fs/bpf (bpf)
      Description: Writable /sys filesystem mount detected, but write access is restricted by the active LSM profile (snap.snapd-desktop-integration.snapd-desktop-integration (enforce)), preventing security exposure.
    * Info debugfs -> Mounted at /sys/kernel/debug (debugfs)
      Description: Writable /sys filesystem mount detected, but write access is restricted by the active LSM profile (snap.snapd-desktop-integration.snapd-desktop-integration (enforce)), preventing security exposure.
    * Info tracefs -> Mounted at /sys/kernel/tracing (tracefs)
      Description: Writable /sys filesystem mount detected, but write access is restricted by the active LSM profile (snap.snapd-desktop-integration.snapd-desktop-integration (enforce)), preventing security exposure.
    * Info configfs -> Mounted at /sys/kernel/config (configfs)
      Description: Writable /sys filesystem mount detected, but write access is restricted by the active LSM profile (snap.snapd-desktop-integration.snapd-desktop-integration (enforce)), preventing security exposure.
    * Info fusectl -> Mounted at /sys/fs/fuse/connections (fusectl)
      Description: Writable /sys filesystem mount detected, but write access is restricted by the active LSM profile (snap.snapd-desktop-integration.snapd-desktop-integration (enforce)), preventing security exposure.
    * Low /dev/mmcblk1p2 -> Mounted at /tmp (ext4)
      Description: Writable directory /tmp is missing hardening flags: noexec, nosuid, nodev. An attacker can write and execute files or construct SUID payloads here.
    * Low /dev/mmcblk1p2 -> Mounted at /tmp (ext4)
      Description: Writable directory /tmp is missing hardening flags: noexec, nosuid, nodev. An attacker can write and execute files or construct SUID payloads here.

[5] FILE DESCRIPTOR LEAK SCAN (Score: 100/100)
  - Total File Descriptors Open: 3
  - No dangerous host file descriptors or sensitive file access detected.

[6] ENVIRONMENT SECRET SCAN (Score: 70/100)
  Sensitive Keys Exposed:
    * SSH_AUTH_SOCK = /run/user/1000/keyring/ssh
    * XAUTHORITY = /run/user/1000/.mutter-Xwaylandauth.84S9Q3

[7] HOST PORTS ACCESSIBLE TO CONTAINER
  - Active Listening Ports:
    * [tcp] 0.0.0.0:56721 (EXPOSED TO NETWORK)
    * [tcp] 127.0.0.1:631
    * [tcp] 127.0.0.1:44037
    * [tcp] 0.0.0.0:22 (EXPOSED TO NETWORK)
    * [tcp] 0.0.0.0:111 (EXPOSED TO NETWORK)
    * [tcp] 0.0.0.0:43917 (EXPOSED TO NETWORK)
    * [tcp] 127.0.0.1:7681
    * [tcp6] ::1:3350
    * [tcp6] :::3389 (EXPOSED TO NETWORK)
    * [tcp6] :::34141 (EXPOSED TO NETWORK)
    * [tcp6] :::46871 (EXPOSED TO NETWORK)
    * [tcp6] :::22 (EXPOSED TO NETWORK)
    * [tcp6] :::111 (EXPOSED TO NETWORK)
    * [tcp6] ::1:631
  - Established Connections:
    * [tcp] 192.168.1.80:22 -> 192.168.1.51:42984

RECOMMENDED REMEDIATIONS
  1. Set 'NoNewPrivileges=true' in systemd or '--security-opt=no-new-privileges' in Docker to prevent privilege escalation.
  2. Do not expose passwords, API keys, or security tokens in environment variables. Use secret stores (e.g. Docker Secrets, K8s Secrets, HashiCorp Vault) or mount credentials securely as files.
```

---

## Building block Architecture
```text
nspect/
├── main.go                 # Flag orchestration & CLI interface
├── Makefile                # Build scripts
├── README.md               # Documentation
├── go.mod                  # Go module definition
├── debian/                 # Debian/Kali source package metadata
├── pkg/
    ├── auditor/
    │   ├── auditor.go      # Sandbox discovery logic
    │   ├── namespace.go    # Namespace inode verification
    │   ├── capability.go   # Hex capability decoder & risk matrix
    │   ├── mount.go        # mountinfo scanning & vulnerability identification
    │   ├── security.go     # Seccomp, LSM, and credential context checks
    │   ├── env.go          # Environment variable secret scanner
    │   ├── net.go          # Inner-namespace tcp/tcp6 socket parser
    │   ├── fd.go           # File descriptor leak & permission auditor
    │   └── report.go       # Formatting, scoring, and remediation compiler
    └── util/
        └── proc.go         # Low-level procfs filesystem parsers
```

---

## CI/CD & Releases

The project includes a GitHub Actions release pipeline. Whenever you push a version tag matching `v*` (e.g., `v0.0.1`), the pipeline will automatically:
1. Run Go unit tests.
2. Compile the static Go binary.
3. Build the Debian (`.deb`) and Red Hat (`.rpm`) installers.
4. Create a new GitHub Release and upload the compiled packages as release assets.

To trigger a release manually:
```bash
git tag v0.0.1
git push origin v0.0.1
```

## Author

* **David Vanhoucke** - *Main Author & Maintainer* - [vanhouckedavid@gmail.com](mailto:vanhouckedavid@gmail.com)

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.
