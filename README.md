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
Target Process: sleep (PID: 371399)
Command Line:  sleep 300
Security Score: 41/100
------------------------------------------------------------

[1] NAMESPACE ISOLATION (Score: 95/100)
  - cgroup   : SHARED WITH HOST (Target Inode: 4026533862)
    Risk: Shares cgroup namespace with host. May leak host cgroup layout information.
  - ipc      : ISOLATED (Target Inode: 4026536084)
  - mnt      : ISOLATED (Target Inode: 4026535997)
  - net      : ISOLATED (Target Inode: 4026536087)
  - pid      : ISOLATED (Target Inode: 4026536086)
  - user     : ISOLATED (Target Inode: 4026535996)
  - uts      : ISOLATED (Target Inode: 4026536023)
  - time     : SHARED WITH HOST (Target Inode: 4026531834)
    Risk: Shares time namespace with host.

[2] PROCESS SECURITY CONTEXT (Score: 65/100)
  - User Context : UID=2005, EUID=2005
  - Seccomp      : Enabled (Filter)
  - NoNewPrivs   : No
  - LSM Status   : unconfined
  Hardening Issues Identified:
    * NoNewPrivs flag is not set. Subprocesses can gain new privileges via SUID binaries or file capabilities.
    * AppArmor/SELinux profile is unconfined or disabled. The process lacks mandatory access controls (MAC).

[3] LINUX CAPABILITIES (Score: 100/100)
  - Effective Capabilities: [None / Dropped]
  - No critical capabilities found in active set.

[4] MOUNT & VOLUME EXPOSURE (Score: 0/100)
  - Total Mount Points Evaluated: 47
  Mount Exposures Discovered:
    * Low  /dev/mapper/pve-vm--116--disk--0 -> Mounted at / (ext4)
      Description: Root filesystem is mounted read-write.
    * Critical  proc -> Mounted at /proc (proc)
      Description: Writable /proc filesystem. Allows altering kernel parameters, sysctl values, or modifying core_pattern to trigger host commands upon crashes.
    * Critical  sysfs -> Mounted at /sys (sysfs)
      Description: Writable /sys filesystem. Allows direct manipulation of kernel interfaces, cgroup configs, or loading modules/drivers.

[5] FILE DESCRIPTOR LEAK SCAN (Score: 100/100)
  - Total File Descriptors Open: 9
  - No dangerous host file descriptors or sensitive file access detected.

[6] ENVIRONMENT SECRET SCAN (Score: 70/100)
  Sensitive Keys Exposed:
    * FTLCONF_webserver_api_password = password

[7] INNER-NAMESPACE NETWORK SOCKETS
  - Active Listening Ports:
    * [tcp] 0.0.0.0:27017 (EXPOSED TO NETWORK)
    * [tcp6] :::27017 (EXPOSED TO NETWORK)
  - Established Connections:
    * [tcp] 192.168.1.19:22 -> 192.168.1.51:35418

RECOMMENDED REMEDIATIONS
  1. Set 'NoNewPrivileges=true' in systemd or '--security-opt=no-new-privileges' in Docker to prevent privilege escalation.
  2. Apply a confined AppArmor profile (e.g. apparmor:docker-default) or enable SELinux to enforce runtime restrictions.
  3. Do not expose passwords, API keys, or security tokens in environment variables. Use secret stores (e.g. Docker Secrets, K8s Secrets, HashiCorp Vault) or mount credentials securely as files.
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
