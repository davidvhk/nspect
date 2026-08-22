## Running nspect as a Rock (OCI container)

### Build the Rock

```bash
# Install rockcraft if needed
sudo snap install rockcraft --classic

# Build the Rock (produces nspect_0.0.10_amd64.rock)
rockcraft pack
# (or if make is installed: make rock)

# Load directly into Docker daemon using rockcraft's bundled skopeo:
rockcraft.skopeo --insecure-policy copy oci-archive:nspect_0.0.10_amd64.rock docker-daemon:nspect:0.0.10

# Alternatively, via standard docker load:
docker load -i nspect_0.0.10_amd64.rock
```

### Run: Web Console (default)

nspect needs access to the **host's `/proc`** to audit other containers.
It must run in the **host PID namespace** so it can see all container PIDs.

```bash
sudo docker run \
  --name nspect \
  --rm \
  --pid=host \
  --privileged \
  -v /proc:/proc:ro \
  -p 8080:8080 \
  nspect:0.0.10
```

Open **http://localhost:8080** for the live audit dashboard.

> **Why `--pid=host`?**  
> Without it, nspect only sees its own PID namespace and cannot discover
> other containers' processes. The host PID namespace gives it visibility
> into all container PIDs via `/proc`.

### Run: One-shot CLI list

```bash
sudo docker run \
  --rm \
  --pid=host \
  --privileged \
  -v /proc:/proc:ro \
  --entrypoint /usr/bin/nspect \
  nspect:0.0.10 \
  --list
```

### Run: Audit a specific container

```bash
# Find the PID of the container's init process on the host
TARGET_PID=$(sudo docker inspect --format '{{.State.Pid}}' <container-name>)

sudo docker run \
  --rm \
  --pid=host \
  --privileged \
  -v /proc:/proc:ro \
  --entrypoint /usr/bin/nspect \
  nspect:0.0.10 \
  --pid "$TARGET_PID"
```

### Docker Compose

```yaml
services:
  nspect:
    image: nspect:0.0.10
    pid: host
    privileged: true
    volumes:
      - /proc:/proc:ro
    ports:
      - "8080:8080"
    restart: unless-stopped
```

### Minimum capabilities (without --privileged)

If you want to avoid `--privileged`, the minimum set of Linux capabilities
required for full audit coverage is:

| Capability | Purpose |
|---|---|
| `CAP_SYS_PTRACE` | Read `/proc/<pid>/root` overlay filesystem of other containers |
| `CAP_DAC_READ_SEARCH` | Read files in other containers' namespaces |
| `CAP_SYS_ADMIN` | Read seccomp filter details from `/proc/<pid>/status` |
| `CAP_NET_ADMIN` | Inspect network namespace socket info |

```bash
sudo docker run \
  --rm \
  --pid=host \
  --cap-add=SYS_PTRACE \
  --cap-add=DAC_READ_SEARCH \
  --cap-add=SYS_ADMIN \
  --cap-add=NET_ADMIN \
  -v /proc:/proc:ro \
  -p 8080:8080 \
  nspect:0.0.10
```

### Why `base: bare` (no chisel slices needed)

nspect is compiled as a **statically linked Go binary** (`CGO_ENABLED=0`).
It has zero shared library dependencies — no libc, no libpthread, nothing.

```
$ ldd nspect
  not a dynamic executable
```

This means `base: bare` in `rockcraft.yaml` is the right choice:
- No Ubuntu packages to chisel
- The Rock contains **only the nspect binary** + the Pebble process manager
- Result: smallest possible hardened OCI image with no attack surface

### Auditing nspect itself (self-audit)

When nspect runs as a web console, you can audit its own container context from within using `docker exec`:

```bash
# Audit the nspect process itself
docker exec nspect /usr/bin/nspect --pid self

# List visible isolated processes (useful when running --pid=host)
docker exec nspect /usr/bin/nspect --list
```

#### What `--pid self` reveals

Running nspect against itself gives a realistic picture of its own security posture. With `--pid=host --privileged`:

| Check | Result | Reason |
|---|---|---|
| Namespace Isolation | 0/100 — all shared | `--pid=host` merges all namespaces with host |
| Capabilities | 100/100 — none | Running as uid 10001, all caps dropped |
| Filesystem | 100/100 — minimal | Only `nspect` + `pebble` binaries, no shell |
| Mounts (`/sys`, `/proc`, `/dev`) | Critical | `--privileged` mounts these writable |
| Seccomp | Disabled | `--privileged` bypasses seccomp |

The critical mount findings (`/sys`, `/proc`, `/dev`) and disabled Seccomp are **direct consequences of `--privileged`**, not nspect's own design. nspect self-reports these accurately.

### The privilege vs. discovery trade-off

nspect genuinely requires elevated privileges to audit other containers. This is an inherent tension:

```
Maximum discovery power                    Minimal attack surface
(--privileged, --pid=host)    ←——→    (--cap-drop=ALL, read-only, no --pid=host)
```

| Mode | Command flags | What nspect can see |
|---|---|---|
| **Full host audit** | `--privileged --pid=host -v /proc:/proc:ro` | All containers and host processes |
| **Minimal caps** | `--cap-add=SYS_PTRACE --cap-add=DAC_READ_SEARCH --pid=host` | Most containers (see Minimum capabilities section) |
| **Unprivileged** | `--user 10001:10001` (no `--privileged`) | Only itself (self-auditing mode) |

When nspect detects it lacks privileges to scan the host, it **automatically falls back to self-audit mode** and logs a notice rather than failing:

```
[!] Notice: Insufficient permissions to scan host namespaces (requires root privileges or CAP_SYS_PTRACE).
    Auditing current process/container context (PID 81226):
```

### Understanding PID 1 inside the container

When running with `--pid=host`, the container **shares the host PID namespace**. PID 1 inside the container is the **host's systemd**, not pebble:

```bash
# This audits the host's systemd (PID 1 = host init)
docker exec nspect /usr/bin/nspect --pid 1

# This audits pebble (the container's actual init process)
PEBBLE_PID=$(docker exec nspect /usr/bin/nspect --list | awk 'NR==3 {print $1}')
docker exec nspect /usr/bin/nspect --pid "$PEBBLE_PID"

# Or use self to audit the nspect server process directly
docker exec nspect /usr/bin/nspect --pid self
```

Without `--pid=host`, PID 1 inside the container is pebble as expected, but nspect loses host-wide container discovery capability.

### Debugging the container from the host

The Rock image uses `base: bare` — no shell, no `ls`, `cat`, `findmnt`, or any utilities. Use `nsenter` from the host to enter **individual namespaces** while keeping the host filesystem active.

> Each Linux namespace is independent. `nsenter` lets you enter only the ones you need:
> | Flag | Namespace | Use for |
> |---|---|---|
> | `--net` | Network | Inspect interfaces, ports, routes |
> | `--pid` | Process | See container's process tree |
> | `--ipc` | IPC | Shared memory, semaphores |
> | `--uts` | UTS | Container's hostname |
> | `-m` | **Mount** | ❌ Avoid — switches rootfs to container's bare image, host binaries unavailable |

```bash
NSPECT_PID=$(docker inspect --format '{{.State.Pid}}' nspect)

# Inspect the container's network interfaces (enter ONLY --net)
sudo nsenter -t $NSPECT_PID --net -- ip a

# Inspect the container's listening ports
sudo nsenter -t $NSPECT_PID --net -- ss -tlnp

# Open a shell inside all container namespaces EXCEPT mount (host binaries remain available)
sudo nsenter -t $NSPECT_PID --net --pid --ipc --uts -- /bin/bash
# Inside: ip a, ss, cat, findmnt, etc. all work — filesystem is still the host's
```

> **Note:** `-m` (mount namespace) switches the filesystem root to the container's rootfs.
> With a bare image this makes all host binaries unavailable. Don't combine `-m` with commands.

#### Inspecting mounts

There is no clean way to use host binaries inside a bare container's mount namespace. Read from `/proc` on the host instead — this is the same data nspect reads internally:

```bash
NSPECT_PID=$(docker inspect --format '{{.State.Pid}}' nspect)

# All mounts visible to the container (same format as /etc/fstab)
sudo cat /proc/$NSPECT_PID/mounts

# Full mountinfo with propagation flags (what nspect parses internally)
sudo cat /proc/$NSPECT_PID/mountinfo

# Filter to just the shared: propagation entries nspect warns about
sudo grep 'shared' /proc/$NSPECT_PID/mountinfo | awk '{print $5, $6}'
```

The `shared:` propagation warnings nspect reports mean that any mount/unmount event inside the container's namespace propagates back to the host — a container escape vector when combined with `CAP_SYS_ADMIN`.

