---
title: "RHEL Intensive – Network, User, and System Administration: A Beginner’s Guide"
author: M. Muzamil
pubDatetime: 2025-09-05T20:21:00Z
slug: rhel-network-user-admin
featured: false
draft: false
tags:
  - RHEL
  - Linux
  - Networking
  - User Management
  - System Administration
  - Package Management
  - Storage
  - Permissions
description:
  "A beginner-friendly guide to mastering network configuration, user management, and system administration on RHEL. Learn to set up IPs, manage users, configure permissions, handle packages, and monitor your system with simple explanations and practical examples."
timezone: "Asia/Karachi"
---

> 🎯 New to RHEL or Linux system administration? This guide breaks down networking, user management, and system admin tasks into easy-to-follow steps with plenty of theory to build your confidence. Whether you’re setting up a server or managing users, we’ve got you covered with clear examples and tips!

---

![Linux Server](https://img.freepik.com/free-vector/big-data-processing-concept-server-room-blockchain-technology-token-access_39422-812.jpg?t=st=1757085786~exp=1757089386~hmac=8494f3caa18b986e06abe98ae6aada457fa73448b0656c901f4b2a8bd0153489&w=1060)


> ⚠️ Before starting, make sure to first read: [RHEL Linux Fundamentals](https://0xmuzamil.dev/posts/rhel-linux-fundamentals)



## Table of Contents

- [Table of Contents](#table-of-contents)
- [🌐 Configuring Networking in RHEL](#-configuring-networking-in-rhel)
  - [Key Commands for Network Setup](#key-commands-for-network-setup)
- [🚪 Routing Basics](#-routing-basics)
  - [Key Commands](#key-commands)
- [📡 DNS and CIDR](#-dns-and-cidr)
  - [DNS Configuration (`/etc/resolv.conf`)](#dns-configuration-etcresolvconf)
  - [CIDR (Classless Inter-Domain Routing)](#cidr-classless-inter-domain-routing)
- [🔗 IP Aliasing](#-ip-aliasing)
- [🔌 Common Ports](#-common-ports)
- [🔍 Network Monitoring Tools](#-network-monitoring-tools)
- [📦 Package Management (.rpm and .deb)](#-package-management-rpm-and-deb)
  - [RPM Commands](#rpm-commands)
  - [YUM Commands](#yum-commands)
  - [DEB Commands](#deb-commands)
- [💾 Swap Space Management](#-swap-space-management)
- [📊 Monitoring with `top`](#-monitoring-with-top)
- [🔎 File Searching with `find`](#-file-searching-with-find)
- [⚙️ Process Management](#️-process-management)
- [🔍 Hardware Info with `dmidecode`](#-hardware-info-with-dmidecode)
- [🖨️ Printers and Tape Drives](#️-printers-and-tape-drives)
- [💾 Mounting ISOs and `/dev/null`](#-mounting-isos-and-devnull)
- [📦 YUM Package Manager](#-yum-package-manager)
- [🗄️ Configuring a YUM Local Repository](#️-configuring-a-yum-local-repository)
- [🔄 Rsync for File Syncing](#-rsync-for-file-syncing)
- [💾 Logical Volume Management (LVM)](#-logical-volume-management-lvm)
- [⏰ Scheduling Tasks with Cron and `at`](#-scheduling-tasks-with-cron-and-at)
- [👤 User Management](#-user-management)
- [🔐 Advanced Permissions](#-advanced-permissions)
- [⚙️ Kernel and Driver Management](#️-kernel-and-driver-management)
- [🧭 What’s Next?](#-whats-next)

---

## 🌐 Configuring Networking in RHEL

Networking is the backbone of any server. In RHEL, setting up and managing network interfaces is crucial for connecting to the internet or other devices. Let’s start with the basics.

**Why Networking Matters**: Your server needs an IP address (like a house address) to talk to other machines. You’ll also need to configure gateways (like a front door to the internet) and DNS (like a phonebook to find websites).

### Key Commands for Network Setup

1. **Check Network Hardware**: Use `lspci -vvv` to list all PCI devices, including network cards. It’s like checking what network hardware is plugged in.
   ```bash
   lspci -vvv
   ```

2. **Inspect Interface Settings**: `ethtool eth0` shows details like connection speed or whether the link is up.
   ```bash
   ethtool eth0
   ```

3. **Set a Static IP**: Edit `/etc/sysconfig/network-scripts/ifcfg-eth0` to assign a fixed IP address.
   ```bash
   nano /etc/sysconfig/network-scripts/ifcfg-eth0
   ```
   Example content:
   ```
   DEVICE=eth0
   BOOTPROTO=static
   IPADDR=192.168.1.10
   NETMASK=255.255.255.0
   GATEWAY=192.168.1.1
   ONBOOT=yes
   ```

4. **Apply Changes**: Restart the network service to use the new settings.
   ```bash
   service network restart
   ```

**Beginner Tip**: Always back up config files before editing. A typo can disconnect your server! Use `ip addr` to verify the IP after restarting.

---

## 🚪 Routing Basics

Routing tells your system how to send data to other networks. Think of it as giving directions to a delivery driver.

### Key Commands

1. **Add a Default Gateway**: This is your server’s “exit” to the internet.
   ```bash
   route add default gw 192.168.1.1
   ```

2. **View Routing Table**: `route -n` shows where data goes (numerical format for clarity).
   ```bash
   route -n
   ```
   Example output:
   ```
   Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
   0.0.0.0         192.168.1.1     0.0.0.0         UG    0      0        0 eth0
   ```

3. **Enable/Disable Interfaces**:
   - Turn off: `ifconfig eth1 down` or `ifdown eth1`
   - Turn on: `ifconfig eth1 up` or `ifup eth1`

**Theory**: Routes define paths for data packets. The default gateway (0.0.0.0) handles traffic to unknown destinations. Use `ifconfig` or `ip` commands for quick changes, but config files for persistence.

**Beginner Hack**: Use `ip route` instead of `route` for modern systems—it’s more detailed. Test connectivity with `ping 8.8.8.8`.

---

## 📡 DNS and CIDR

### DNS Configuration (`/etc/resolv.conf`)

DNS translates domain names (like google.com) to IP addresses. The `/etc/resolv.conf` file tells your system which DNS servers to use.

**Example**:
```
nameserver 8.8.8.8
nameserver 8.8.4.4
search example.com
options timeout:2
```

- **nameserver**: DNS server IPs (e.g., Google’s public DNS).
- **search**: Auto-appends domains for short names (e.g., `ping server` becomes `server.example.com`).
- **options**: Fine-tunes behavior, like query timeouts.

**Tip**: If `/etc/resolv.conf` gets overwritten, check NetworkManager or DHCP settings.

### CIDR (Classless Inter-Domain Routing)

CIDR is a way to define IP address ranges. It’s written as `IP/prefix`, like `192.168.1.0/24`, where `/24` means 24 bits for the network, leaving 8 bits for hosts (254 usable IPs).

**Common CIDR Ranges**:
| CIDR | Subnet Mask       | Usable Hosts |
|------|-------------------|--------------|
| /24  | 255.255.255.0     | 254          |
| /30  | 255.255.255.252   | 2            |
| /16  | 255.255.0.0       | 65,534       |

**Example**: Assign an IP with CIDR:
```bash
ip addr add 192.168.1.100/24 dev eth0
```

**Why CIDR?** It’s more flexible than old class-based networking, saving IP addresses for efficiency.

---

## 🔗 IP Aliasing

IP aliasing lets one network interface have multiple IP addresses. It’s like giving your server multiple phone numbers.

**Use Cases**:
- Hosting multiple websites on one server.
- Testing different network setups.
- Segmenting traffic without extra hardware.

**Example**:
```bash
sudo ip addr add 192.168.1.100/24 dev eth0
sudo ip addr del 192.168.1.100/24 dev eth0  # Remove it
```

**Tip for Beginners**: Check IPs with `ip addr show`. Be cautious with aliases in production—track them to avoid conflicts.

---

## 🔌 Common Ports

Ports are like doors for network services. Each service uses a specific port number.

**Well-Known Ports (0–1023)**:
| Port | Service | Protocol | Description |
|------|---------|----------|-------------|
| 22   | SSH     | TCP      | Secure remote login |
| 80   | HTTP    | TCP      | Web traffic |
| 443  | HTTPS   | TCP      | Secure web traffic |
| 53   | DNS     | TCP/UDP  | Name resolution |
| 25   | SMTP    | TCP      | Email sending |

**Dynamic Ports (1024–49151)**: Used for temporary connections (e.g., MySQL on 3306, PostgreSQL on 5432).

**Registered Ports (49152–65535)**: For custom or private apps.

**Check Ports**: View services with `less /etc/services`.

**Beginner Tip**: Use `netstat -tuln` to see which ports are open. Never expose sensitive ports (e.g., 22) to the public without a firewall.

---

## 🔍 Network Monitoring Tools

Keep an eye on your network to troubleshoot or spot issues.

1. **netstat**: Shows connections and ports.
   ```bash
   sudo netstat -tulnp
   ```

2. **pidof**: Finds process IDs (e.g., `pidof sshd`).

3. **ping**: Tests connectivity.
   ```bash
   ping -c 4 8.8.8.8
   ```

4. **tcpdump**: Captures packets for analysis.
   ```bash
   sudo tcpdump -i eth0 port 80
   ```

**Theory**: Monitoring helps detect slow connections, unauthorized access, or network overloads. Tools like `tcpdump` are advanced but great for debugging.

**Beginner Hack**: Start with `ping` to test internet, then `netstat` to check services. Save `tcpdump` output to a file for later analysis.

---

## 📦 Package Management (.rpm and .deb)

RHEL uses `.rpm` packages, managed by `rpm` or `yum/dnf`. Debian-based systems use `.deb` with `dpkg` or `apt`.

### RPM Commands
- Install: `sudo rpm -ivh package.rpm`
- Remove: `sudo rpm -e package`
- Check installed: `rpm -q package`
- List files: `rpm -ql package`

### YUM Commands
- Install: `sudo yum install package`
- Update: `sudo yum update`
- List installed: `yum list installed`

### DEB Commands
- Install: `sudo dpkg -i package.deb` or `sudo apt install ./package.deb`
- Remove: `sudo dpkg -r package`

**Theory**: Package managers handle dependencies (other software needed). YUM/DNF and APT are higher-level, resolving dependencies automatically.

**Tip**: Prefer `yum` over `rpm` for RHEL to avoid dependency headaches. Use `alien` to convert between `.rpm` and `.deb` if needed.

---

## 💾 Swap Space Management

Swap is like a backup for RAM, storing data when memory is full.

**Why Swap?** Prevents crashes during memory spikes, especially on low-RAM systems.

**Commands**:
- Check usage: `free -m`
- Create swap file:
  ```bash
  sudo fallocate -l 2G /swapfile
  sudo chmod 600 /swapfile
  sudo mkswap /swapfile
  sudo swapon /swapfile
  ```
- Make permanent: Add to `/etc/fstab`.

**Find Swap Users**:
```bash
cat /proc/<pid>/status | grep -i swap
```

**Beginner Tip**: Keep swap at 1-2x RAM size for small systems. Monitor with `free -h`.

---

## 📊 Monitoring with `top`

`top` shows live system stats—CPU, memory, processes.

**Key Shortcuts**:
- `M`: Sort by memory
- `P`: Sort by CPU
- `u`: Filter by user
- `f`: Customize columns

**Theory**: `top` helps spot resource hogs. Combine with `htop` for a prettier view.

**Tip**: Press `q` to quit `top`. Use `top -b > log.txt` for logs.

---

## 🔎 File Searching with `find`

The `find` command is your file-hunting tool.

**Examples**:
- Find by name: `find / -name file.txt`
- By user: `find / -user alice`
- By size: `find / -size +100M`
- Delete matches: `find / -name "*.log" -exec rm -f {} \;`

**Theory**: `find` searches recursively, filtering by name, type, size, or time. Use cautiously with `-exec` to avoid accidental deletes.

**Beginner Tip**: Start with `find . -name "pattern"` in your current directory to avoid searching the whole system.

---

## ⚙️ Process Management

Processes are running programs. Manage them to keep your system healthy.

**Tools**:
- `ps -ax`: List all processes.
- `sar -u 1 5`: CPU stats every second, 5 times.
- Kill zombies: `kill -HUP <parent_pid>`.

**Process States**:
- R: Running
- S: Sleeping
- Z: Zombie (needs parent cleanup)

**Theory**: Zombies waste resources. Use `ps` or `top` to find and fix them.

**Tip**: Use `pkill -u username` to stop all user processes safely.

---

## 🔍 Hardware Info with `dmidecode`

`dmidecode` reads hardware details from BIOS/UEFI.

**Examples**:
- BIOS: `sudo dmidecode -t bios`
- CPU: `sudo dmidecode -t processor`

**Theory**: Great for inventory or troubleshooting hardware issues.

**Tip**: Run with `sudo` for full details. Use in scripts for automation.

---

## 🖨️ Printers and Tape Drives

- **/dev/lp0**: Parallel port printer (old-school).
  ```bash
  echo "Test" > /dev/lp0
  ```
- **mt -f**: Controls tape drives.
  ```bash
  mt -f /dev/st0 rewind
  ```

**Theory**: Device files like `/dev/lp0` treat hardware as files, a Linux hallmark.

**Tip**: Rarely used today, but handy for legacy systems.

---

## 💾 Mounting ISOs and `/dev/null`

- **Mount ISO**: `sudo mount -o loop centos.iso /mnt`
- **/dev/null**: Discards output.
  ```bash
  command > /dev/null
  ```

**Theory**: Loop mounting treats files as devices. `/dev/null` is a “black hole” for unwanted output.

**Tip**: Use `/dev/null` in scripts to silence noisy commands.

---

## 📦 YUM Package Manager

YUM manages `.rpm` packages with ease.

**Key Commands**:
- Install: `sudo yum install package`
- Update: `sudo yum update`
- History: `yum history`

**Theory**: YUM resolves dependencies, unlike raw `rpm`. It’s RHEL’s go-to for software management.

**Tip**: Run `yum clean all` if updates fail.

---

## 🗄️ Configuring a YUM Local Repository

Set up a local repo for offline package installs.

**Steps**:
1. Create directory: `mkdir /repo/local`
2. Add `.rpm` files.
3. Generate metadata: `createrepo /repo/local`
4. Create repo file: `/etc/yum.repos.d/local.repo`
   ```
   [localrepo]
   name=Local YUM Repository
   baseurl=file:///repo/local
   enabled=1
   gpgcheck=0
   ```
5. Update cache: `yum clean all; yum repolist`

**Theory**: Local repos save bandwidth and work offline.

**Tip**: Use for air-gapped servers or custom software.

---

## 🔄 Rsync for File Syncing

`rsync` syncs files efficiently, copying only changes.

**Example**:
```bash
rsync -parv /home/docs/ /backup/
```
- p: Preserve permissions
- a: Archive mode
- r: Recursive
- v: Verbose

**Theory**: Rsync uses deltas for speed, ideal for backups.

**Tip**: Test with `--dry-run` to preview.

---

## 💾 Logical Volume Management (LVM)

LVM makes storage flexible, allowing resizing without downtime.

**Steps**:
1. `pvcreate /dev/sdb`
2. `vgcreate my_vg /dev/sdb`
3. `lvcreate -L 5G -n my_lv my_vg`
4. `mkfs.ext4 /dev/my_vg/my_lv`
5. Mount: `mount /dev/my_vg/my_lv /mnt`

**Theory**: LVM abstracts physical disks into logical volumes for easy management.

**Tip**: Use `lvresize` to grow/shrink volumes.

---

## ⏰ Scheduling Tasks with Cron and `at`

Automate tasks with `cron` (recurring) or `at` (one-time).

**Cron**:
- Edit: `crontab -e`
- Example (daily backup at 3 AM):
  ```
  0 3 * * * /backup.sh
  ```

**at**:
- Schedule: `at 14:30`, type command, then Ctrl+D.
- View: `atq`

**Theory**: Cron is for routines, `at` for one-offs. Control access with `/etc/cron.allow` or `at.deny`.

**Tip**: Use https://crontab.guru for cron schedules.

---

## 👤 User Management

Manage users to control access and security.

**Commands**:
- Add: `adduser username` (interactive) or `useradd -m -s /bin/bash username`
- Password: `passwd username`
- Lock: `usermod -L username`

**Key Files**:
- `/etc/passwd`: User info
- `/etc/shadow`: Passwords
- `/etc/group`: Group membership

**Theory**: Users and groups organize access. `/etc/login.defs` sets defaults.

**Tip**: Use `adduser` for simplicity; `useradd` for scripts.

---

## 🔐 Advanced Permissions

Fine-tune access with SUID, SGID, Sticky Bit, `sudoers`, and `setfacl`.

- **SUID**: Run as owner (`chmod u+s`).
- **SGID**: Run as group or inherit group (`chmod g+s`).
- **Sticky Bit**: Protect files in shared folders (`chmod +t`).
- **sudoers**: Grant root access via `visudo`.
- **setfacl**: Custom permissions (`setfacl -m u:alice:rw file.txt`).
- **umask**: Default permissions (`umask 027`).

**Theory**: These extend basic permissions for complex scenarios.

**Tip**: Test `setfacl` on non-critical files first.

---

## ⚙️ Kernel and Driver Management

Manage kernel modules (drivers) for hardware.

**Commands**:
- List loaded: `lsmod`
- Load: `modprobe module_name`
- Blacklist: Add to `/etc/modprobe.d/blacklist.conf`

**Kernel Tuning**:
- Max open files: `echo 600000 > /proc/sys/fs/file-max`
- Swappiness: `sysctl -w vm.swappiness=10`

**Theory**: Modules add functionality to the kernel. Tuning optimizes performance.

**Tip**: Use `modinfo` to check module details before loading.

---

## 🧭 What’s Next?

You’re now equipped to handle networking, users, and admin tasks on RHEL! Practice in a VM, explore tools like `firewalld` for security, or dive into scripting for automation. Got questions? Leave a comment, and keep exploring Linux—it’s a journey!