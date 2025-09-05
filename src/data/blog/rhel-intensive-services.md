---
title: "RHEL Intensive - Services: AWS, Networking, FTP, Apache, Firewalls, SELinux, and Samba"
author: M. Muzamil
pubDatetime: 2025-09-05T10:32:00Z
slug: rhel-intensive-services
featured: false
draft: false
tags:
  - RHEL
  - AWS
  - Linux
  - Networking
  - FTP
  - Apache
  - Firewalld
  - SELinux
  - Samba
description:
  "A beginner-friendly guide to mastering AWS services, networking, FTP, Apache, Firewalld, SELinux, and Samba on RHEL. Learn to set up services, configure firewalls, manage users, and secure your system with practical examples and step-by-step instructions."
timezone: "Asia/Karachi"
---

> 🎯 New to RHEL or AWS? This guide covers essential services for system administration, including AWS integration, networking, FTP, Apache, Firewalld, SELinux, and Samba. Each section includes theory, commands, and beginner tips to help you confidently manage RHEL systems and cloud services.

---

![Linux Server](https://www.softkit.dev/static/images/Amazon_web_services_main_image_2_84c24de2df.png)

## Table of Contents

- [Table of Contents](#table-of-contents)
- [🌐 Introduction to AWS Services](#-introduction-to-aws-services)
  - [Creating a Free AWS Account](#creating-a-free-aws-account)
  - [Global Infrastructure](#global-infrastructure)
  - [Core AWS Services](#core-aws-services)
  - [Specialty Services](#specialty-services)
  - [Compute Services](#compute-services)
  - [Containers](#containers)
  - [Storage](#storage)
  - [Databases](#databases)
  - [Analytics \& Big Data](#analytics--big-data)
  - [Machine Learning \& AI](#machine-learning--ai)
  - [Security \& Identity](#security--identity)
  - [Communication](#communication)
  - [Developer Tools](#developer-tools)
  - [Cost Management](#cost-management)
  - [EC2 Instance Families](#ec2-instance-families)
  - [EBS Volume Types](#ebs-volume-types)
  - [S3 Storage Classes](#s3-storage-classes)
- [📡 Server-Client Model (NFS Setup)](#-server-client-model-nfs-setup)
  - [On Server](#on-server)
  - [On Client](#on-client)
- [📂 FTP (File Transfer Protocol)](#-ftp-file-transfer-protocol)
  - [Installation](#installation)
  - [Start Service](#start-service)
  - [Firewall Rules](#firewall-rules)
  - [Configure vsftpd](#configure-vsftpd)
  - [Add FTP User](#add-ftp-user)
  - [Test Connection](#test-connection)
  - [SELinux Context](#selinux-context)
- [🌐 Apache HTTP Server](#-apache-http-server)
  - [Installation](#installation-1)
  - [Start Service](#start-service-1)
  - [Firewall Rules](#firewall-rules-1)
  - [Configure Virtual Host](#configure-virtual-host)
  - [SELinux Context](#selinux-context-1)
  - [Test Config](#test-config)
- [🔥 Firewalld](#-firewalld)
  - [Key Commands](#key-commands)
- [🔒 SELinux](#-selinux)
  - [Check Status](#check-status)
  - [Set Mode](#set-mode)
  - [Manage Contexts](#manage-contexts)
  - [Booleans](#booleans)
  - [Logs](#logs)
- [📂 Samba](#-samba)
  - [Installation](#installation-2)
  - [Configure Share](#configure-share)
  - [SELinux Context](#selinux-context-2)
  - [Firewall Rules](#firewall-rules-2)
  - [Start Services](#start-services)
  - [Add Samba User](#add-samba-user)
  - [Test Share](#test-share)
- [🧭 What’s Next?](#-whats-next)

---

## 🌐 Introduction to AWS Services

Amazon Web Services (AWS) is a leading cloud platform offering over **250 services** for computing, storage, networking, databases, AI, analytics, and more. It’s widely used for scalable, cost-effective infrastructure.

### Creating a Free AWS Account

AWS offers a **Free Tier** for new users to explore services with limited usage for 12 months. Here’s how to create one:

1. Visit [aws.amazon.com/free](https://aws.amazon.com/free/).
2. Click **Create a Free Account**.
3. Provide an email, password, and account name.
4. Enter contact and billing details (a valid credit/debit card is required for verification, but you won’t be charged unless you exceed Free Tier limits).
5. Verify your identity via phone or SMS.
6. Select the **Basic Support Plan** (free) and complete the setup.

**Free Tier Highlights**:
- **EC2**: 750 hours/month of `t2.micro` or `t3.micro` instances (Linux/Windows).
- **S3**: 5 GB standard storage, 20,000 GET requests.
- **RDS**: 750 hours/month of a `db.t2.micro` database.
- **Lambda**: 1 million free requests/month.

**Tip**: Monitor usage via the [AWS Billing Dashboard](https://console.aws.amazon.com/billing/) to stay within Free Tier limits. For detailed setup, see [AWS Free Tier Guide](https://aws.amazon.com/free/free-tier-get-started/).

### Global Infrastructure

AWS operates globally, ensuring low-latency and high-availability services:
- **Regions**: 33 active regions (e.g., `us-east-1`, `eu-west-1`) as of 2025.
- **Availability Zones (AZs)**: Each region has 3+ isolated AZs for redundancy.
- **Edge Locations**: 600+ points for CloudFront (CDN) caching.

**Theory**: Choose a region close to your users for lower latency. AZs provide fault tolerance by isolating failures.

### Core AWS Services

| Category          | Service       | Purpose                                  | Example Use Case                     |
|-------------------|---------------|------------------------------------------|--------------------------------------|
| **Compute**       | EC2           | Virtual machines                        | Hosting RHEL servers                 |
|                   | Lambda        | Serverless code execution               | Event-driven scripts                 |
|                   | Auto Scaling  | Scale EC2 based on demand               | Handle traffic spikes                |
| **Networking**    | VPC           | Isolated private network                | Secure RHEL deployments              |
|                   | ELB           | Load balancer for EC2                   | Distribute web traffic               |
|                   | Route 53      | Scalable DNS service                    | Domain management                    |
| **Storage**       | S3            | Object storage                          | Store backups, media                 |
|                   | EBS           | Block storage for EC2                   | Persistent storage for RHEL VMs      |
| **Database**      | RDS           | Managed SQL databases                   | MySQL/PostgreSQL for apps            |
|                   | DynamoDB      | NoSQL key-value store                   | High-speed data for mobile apps      |
|                   | ElastiCache   | In-memory cache (Redis/Memcached)       | Speed up web apps                    |
| **Content Delivery** | CloudFront | Content Delivery Network (CDN)          | Cache static content globally        |
| **Security**      | IAM           | User and role access control            | Restrict AWS resource access         |
|                   | KMS           | Key management for encryption           | Encrypt sensitive data               |
|                   | WAF           | Web Application Firewall                | Protect against SQL injection        |
|                   | ACM           | SSL/TLS certificate management          | Secure HTTPS for websites            |
|                   | Inspector     | Vulnerability scanner for EC2           | Audit RHEL instances                 |
| **Monitoring**    | CloudWatch    | Logs, metrics, alarms                   | Monitor RHEL server health           |
| **Analytics**     | Kinesis       | Real-time data streaming                | Track user clicks                    |
|                   | EMR           | Managed Hadoop for big data             | Process large datasets               |
|                   | Glue          | ETL (Extract, Transform, Load)          | Data integration                     |
|                   | Redshift      | Data warehouse                          | Business analytics                   |
|                   | Athena        | Query S3 data with SQL                  | Analyze logs                         |
|                   | QuickSight    | Business intelligence dashboards        | Visualize metrics                    |
| **App Services**  | Rekognition   | Image/video analysis                    | Detect objects in media              |
|                   | SNS           | Notifications (SMS, email, push)        | Send alerts                          |
|                   | SES           | Email sending service                   | Bulk email campaigns                 |
|                   | SQS           | Message queue                           | Queue tasks for apps                 |
|                   | API Gateway   | Create and manage REST APIs             | Build APIs for RHEL apps             |
|                   | Cognito       | User authentication and identity        | User login for web apps              |
| **DevOps**        | CloudFormation| Infrastructure as Code (IaC)            | Automate RHEL deployments            |
|                   | CodeCommit    | Git repository                          | Store code                           |
|                   | CodeBuild     | Build and test code                     | Compile RHEL apps                    |
|                   | CodeDeploy    | Deploy code to EC2/Lambda               | Update RHEL servers                  |
|                   | CodePipeline  | CI/CD automation                        | Automate app deployment              |
|                   | CodeStar      | All-in-one DevOps dashboard             | Manage projects with JIRA integration|

**Beginner Tip**: Start with EC2 for RHEL servers, S3 for storage, and IAM for security. Use [AWS Management Console](https://aws.amazon.com/console/) for a user-friendly interface.

### Specialty Services

- **RoboMaker**: Simulate and train robotics applications.
- **IoT Core**: Connect IoT devices (e.g., smart sensors) to AWS.
- **Ground Station**: Communicate with satellites.
- **Braket**: Experiment with quantum computing.

**Example**: Use IoT Core to manage smart devices with RHEL as a gateway. Learn more at [AWS IoT Core](https://aws.amazon.com/iot-core/).

### Compute Services

- **EC2**: Virtual servers for RHEL, customizable with CPU, RAM, and OS.
- **Elastic Load Balancer (ELB)**: Distributes traffic across EC2 instances.
- **CloudWatch**: Monitors EC2 metrics (CPU, disk I/O).
- **Auto Scaling**: Adjusts EC2 capacity based on load.
- **Elastic Beanstalk**: Simplifies app deployment (e.g., Node.js on RHEL).
- **Lightsail**: Easy hosting for small RHEL apps (e.g., WordPress).
- **Lambda**: Run code without servers (e.g., automate RHEL tasks).
- **Serverless Application Repository**: Prebuilt Lambda functions.
- **Outposts**: Run AWS services on-premises.
- **Snowball/Snowcone**: Physical devices for data transfer in remote areas.

**Example**: Deploy a RHEL-based web server on EC2. See [EC2 Getting Started](https://aws.amazon.com/ec2/getting-started/).

### Containers

- **ECR**: Store Docker images for RHEL apps.
- **ECS**: Run Docker containers on AWS.
- **EKS**: Kubernetes for container orchestration.
- **Fargate**: Serverless container management.
- **App Runner**: Deploy containers with minimal setup.

**Tip**: Use ECS with RHEL-based Docker images for scalable apps. Learn at [AWS ECS](https://aws.amazon.com/ecs/).

### Storage

- **S3**: Store files (e.g., RHEL backups, logs).
- **Glacier**: Low-cost archival storage.
- **EBS**: Fast block storage for EC2.
- **EFS**: Shared file system for multiple EC2 instances.

**Example**: Back up RHEL logs to S3. See [S3 Getting Started](https://aws.amazon.com/s3/getting-started/).

### Databases

- **SimpleDB**: Basic NoSQL database.
- **DynamoDB**: Scalable NoSQL for high-traffic apps.
- **DocumentDB**: MongoDB-compatible database.
- **OpenSearch**: Search engine for logs and analytics.
- **RDS**: Managed SQL (e.g., MySQL on RHEL).
- **Aurora**: High-performance SQL database.
- **Neptune**: Graph database for relationships.
- **ElastiCache**: In-memory cache (Redis/Memcached).
- **TimeStream**: Time-series data (e.g., IoT metrics).
- **QLDB**: Tamper-proof ledger database.

**Tip**: Use RDS for RHEL-hosted databases. See [RDS Documentation](https://aws.amazon.com/rds/).

### Analytics & Big Data

- **Redshift**: Data warehouse for analytics.
- **Lake Formation**: Centralize data storage.
- **Kinesis**: Real-time data streaming.
- **EMR**: Big data processing with Hadoop/Spark.
- **MSK**: Managed Kafka for streaming.
- **Glue**: ETL for data integration.

**Example**: Analyze RHEL server logs with Athena. Learn at [AWS Athena](https://aws.amazon.com/athena/).

### Machine Learning & AI

- **Data Exchange**: Access public datasets.
- **SageMaker**: Build and deploy ML models.
- **Rekognition**: Image/video analysis.
- **Lex**: Create chatbots.
- **DeepRacer**: Learn ML with racing simulations.

**Example**: Use Rekognition to analyze images stored in S3. See [AWS Rekognition](https://aws.amazon.com/rekognition/).

### Security & Identity

- **IAM**: Control access to AWS resources.
- **Cognito**: Manage user authentication.

**Tip**: Secure RHEL EC2 instances with IAM roles. See [IAM Best Practices](https://aws.amazon.com/iam/).

### Communication

- **SNS**: Send notifications (SMS, email).
- **SES**: Send bulk emails.

**Example**: Notify admins via SNS for RHEL server alerts. Learn at [AWS SNS](https://aws.amazon.com/sns/).

### Developer Tools

- **CloudFormation**: Automate infrastructure setup.
- **Amplify**: Connect RHEL apps to AWS services.

**Example**: Use CloudFormation to deploy RHEL EC2 instances. See [CloudFormation Guide](https://aws.amazon.com/cloudformation/).

### Cost Management

- **Cost Explorer**: Analyze AWS spending.
- **Budgets**: Set cost alerts.

**Tip**: Use Budgets to monitor Free Tier usage. See [AWS Cost Management](https://aws.amazon.com/aws-cost-management/).

### EC2 Instance Families

EC2 instances are grouped by use case:

| Family         | Purpose                          | Examples            |
|----------------|----------------------------------|---------------------|
| General Purpose | Balanced CPU/memory             | `t4g.micro`, `m5.large` |
| Compute Optimized | High-performance CPUs           | `c7g.large`, `c5n.xlarge` |
| Memory Optimized | RAM-intensive apps              | `r6i.large`, `x2idn.24xlarge` |
| Storage Optimized | High-speed storage              | `i4i.large`, `d3.xlarge` |
| Accelerated Computing | GPU/ML tasks                 | `p4d.24xlarge`, `g5.xlarge` |

**Tip**: Use `t4g.micro` (ARM-based Graviton) for Free Tier RHEL instances. See [EC2 Instance Types](https://aws.amazon.com/ec2/instance-types/).

### EBS Volume Types

EBS provides block storage for EC2:

| Type            | Description                     | Use Case                  |
|-----------------|---------------------------------|---------------------------|
| `gp3`           | General-purpose SSD            | Default for RHEL VMs      |
| `gp2`           | Older general-purpose SSD      | Legacy workloads          |
| `io2`/`io2 Block Express` | High-performance SSD  | Databases (MySQL, Oracle) |
| `st1`           | Throughput-optimized HDD       | Big data, logs            |
| `sc1`           | Cold HDD (cheapest)            | Archival                  |

**Tip**: Use `gp3` for cost-effective performance. See [EBS Volume Types](https://aws.amazon.com/ebs/volume-types/).

### S3 Storage Classes

S3 storage classes optimize cost and access speed:

| Class                  | Retrieval Time | Use Case                    |
|------------------------|----------------|-----------------------------|
| Standard               | Instant        | Frequent access             |
| Intelligent-Tiering    | Instant        | Unpredictable access        |
| Standard-IA            | Instant        | Infrequent access           |
| One Zone-IA            | Instant        | Non-critical backups        |
| Glacier Instant Retrieval | Milliseconds | Rare access                 |
| Glacier Flexible Retrieval | Minutes/Hours | Cold storage                |
| Glacier Deep Archive   | 12+ hours      | Long-term archival          |

**Tip**: Use Intelligent-Tiering for RHEL logs with varying access patterns. See [S3 Storage Classes](https://aws.amazon.com/s3/storage-classes/).

---

## 📡 Server-Client Model (NFS Setup)

Network File System (NFS) allows file sharing between RHEL servers and clients.

### On Server

1. **Set Hostname**:
   ```bash
   sudo hostnamectl set-hostname server1.example.com
   cat /etc/hostname
   ```

2. **Add DNS Entry**:
   Edit `/etc/hosts`:
   ```bash
   sudo nano /etc/hosts
   ```
   Add:
   ```
   192.168.1.10  server1.example.com
   ```

3. **Install NFS**:
   ```bash
   sudo yum install nfs-utils -y
   ```

4. **Start Services**:
   ```bash
   sudo systemctl start rpcbind nfs-server
   sudo systemctl enable rpcbind nfs-server
   ```

5. **Verify Ports** (NFS uses 2049):
   ```bash
   sudo ss -tulpn | grep 2049
   ```

6. **Create Share**:
   ```bash
   sudo mkdir -p /server
   sudo chmod -R 755 /server
   ```

7. **Configure Exports**:
   Edit `/etc/exports`:
   ```bash
   sudo nano /etc/exports
   ```
   Add:
   ```
   /server 192.168.1.0/24(rw,sync,no_root_squash)
   ```

8. **Export Share**:
   ```bash
   sudo exportfs -rv
   ```

9. **Firewall Rules**:
   ```bash
   sudo firewall-cmd --permanent --add-service=nfs
   sudo firewall-cmd --reload
   ```

### On Client

1. **Check Exports**:
   ```bash
   showmount -e server1.example.com
   ```

2. **Mount Share**:
   ```bash
   sudo mkdir -p /data
   sudo mount server1.example.com:/server /data
   ```

3. **Persistent Mount**:
   Edit `/etc/fstab`:
   ```
   server1.example.com:/server /data nfs defaults 0 0
   ```

**Theory**: NFS enables seamless file sharing in a server-client model, ideal for centralized storage.

**Tip**: Use `firewalld` instead of disabling the firewall. See [NFS Documentation](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/managing_file_systems/sharing-a-file-system-with-nfs_managing-file-systems).

---

## 📂 FTP (File Transfer Protocol)

FTP transfers files between systems. **vsftpd** is the default FTP server in RHEL.

### Installation

```bash
sudo yum install vsftpd -y
```

### Start Service

```bash
sudo systemctl start vsftpd
sudo systemctl enable vsftpd
```

### Firewall Rules

```bash
sudo firewall-cmd --permanent --add-service=ftp
sudo firewall-cmd --reload
```

### Configure vsftpd

Edit `/etc/vsftpd/vsftpd.conf`:
```bash
anonymous_enable=NO
local_enable=YES
write_enable=YES
chroot_local_user=YES
allow_writeable_chroot=YES
pasv_enable=YES
pasv_min_port=30000
pasv_max_port=31000
```

Restart:
```bash
sudo systemctl restart vsftpd
```

### Add FTP User

```bash
sudo adduser ftpuser
sudo passwd ftpuser
sudo mkdir -p /home/ftpuser/ftp_files
sudo chown ftpuser:ftpuser /home/ftpuser/ftp_files
```

### Test Connection

```bash
ftp 192.168.1.10
```

### SELinux Context

Set context for FTP directories:
```bash
sudo chcon -t public_content_t /home/ftpuser/ftp_files
sudo semanage fcontext -a -t public_content_t "/home/ftpuser/ftp_files(/.*)?"
sudo restorecon -Rv /home/ftpuser/ftp_files
```

**Theory**: FTP uses ports 21 (control) and 20 (data in active mode). SFTP (port 22) is more secure. See [vsftpd Documentation](https://security.appspot.com/vsftpd.html).

**Tip**: Enable passive mode for firewall compatibility.

---

## 🌐 Apache HTTP Server

Apache serves web content and is widely used in RHEL.

### Installation

```bash
sudo yum install httpd -y
```

### Start Service

```bash
sudo systemctl start httpd
sudo systemctl enable httpd
```

### Firewall Rules

```bash
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
```

### Configure Virtual Host

Edit `/etc/httpd/conf.d/site1.conf`:
```
<VirtualHost *:80>
    ServerName site1.example.com
    DocumentRoot /var/www/site1
    <Directory /var/www/site1>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    ErrorLog /var/log/httpd/site1_error.log
    CustomLog /var/log/httpd/site1_access.log combined
</VirtualHost>
```

Create directory:
```bash
sudo mkdir -p /var/www/site1
sudo echo "<h1>Hello from site1</h1>" > /var/www/site1/index.html
sudo chown -R apache:apache /var/www/site1
```

### SELinux Context

```bash
sudo chcon -R -t httpd_sys_content_t /var/www/site1
sudo semanage fcontext -a -t httpd_sys_content_t "/var/www/site1(/.*)?"
sudo restorecon -Rv /var/www/site1
```

### Test Config

```bash
sudo httpd -t
sudo systemctl restart httpd
```

**Theory**: Apache uses a modular architecture with virtual hosts for multiple websites. See [Apache Documentation](https://httpd.apache.org/docs/).

**Tip**: Use `apachectl configtest` to avoid downtime from config errors.

---

## 🔥 Firewalld

Firewalld is RHEL’s default firewall, using zones and services for dynamic management.

### Key Commands

- List services:
  ```bash
  firewall-cmd --list-services
  ```
- Add service:
  ```bash
  firewall-cmd --permanent --add-service=http
  firewall-cmd --reload
  ```
- List zones:
  ```bash
  firewall-cmd --get-zones
  ```
- Set default zone:
  ```bash
  firewall-cmd --set-default-zone=block
  ```

**Theory**: Firewalld simplifies firewall management with predefined services (e.g., `http`, `ftp`). Zones allow context-based rules.

**Tip**: Always use `--permanent` to persist rules. See [Firewalld Documentation](https://firewalld.org/documentation/).

---

## 🔒 SELinux

SELinux enforces mandatory access control in RHEL.

### Check Status

```bash
getenforce
sestatus
```

### Set Mode

Temporary:
```bash
setenforce 0  # Permissive
setenforce 1  # Enforcing
```

Permanent:
Edit `/etc/selinux/config`:
```
SELINUX=enforcing
```

### Manage Contexts

View file context:
```bash
ls -Z /var/www/html
```

Set context:
```bash
sudo chcon -t httpd_sys_content_t /var/www/html/index.html
sudo semanage fcontext -a -t httpd_sys_content_t "/var/www/html(/.*)?"
sudo restorecon -Rv /var/www/html
```

### Booleans

List:
```bash
getsebool -a | grep httpd
```

Set:
```bash
setsebool -P httpd_enable_homedirs on
```

### Logs

Check denials:
```bash
grep denied /var/log/audit/audit.log
```

Analyze:
```bash
sudo yum install policycoreutils-devel -y
audit2why < /var/log/audit/audit.log
```

**Theory**: SELinux uses contexts to enforce security policies, even for root. See [Red Hat SELinux Guide](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/using_selinux/).

**Tip**: Use permissive mode for troubleshooting, then re-enable enforcing.

---

## 📂 Samba

Samba enables file sharing between RHEL and Windows systems.

### Installation

```bash
sudo yum install samba samba-client samba-common -y
```

### Configure Share

Edit `/etc/samba/smb.conf`:
```
[global]
   workgroup = WORKGROUP
   server string = Samba Server %v
   netbios name = rhel-server
   security = user
   map to guest = bad user

[shared]
   path = /srv/samba/shared
   browsable = yes
   writable = yes
   guest ok = yes
   read only = no
```

Create directory:
```bash
sudo mkdir -p /srv/samba/shared
sudo chown -R nobody:nogroup /srv/samba/shared
sudo chmod -R 0775 /srv/samba/shared
```

### SELinux Context

```bash
sudo chcon -t samba_share_t /srv/samba/shared
sudo semanage fcontext -a -t samba_share_t "/srv/samba/shared(/.*)?"
sudo restorecon -Rv /srv/samba/shared
```

### Firewall Rules

```bash
sudo firewall-cmd --permanent --add-service=samba
sudo firewall-cmd --reload
```

### Start Services

```bash
sudo systemctl start smbd nmbd
sudo systemctl enable smbd nmbd
```

### Add Samba User

```bash
sudo adduser smbuser
sudo smbpasswd -a smbuser
sudo smbpasswd -e smbuser
```

### Test Share

From Windows: `\\<server-ip>\shared`

From Linux:
```bash
smbclient //192.168.1.10/shared -U smbuser
```

**Theory**: Samba uses SMB/CIFS for cross-platform file sharing. See [Samba Documentation](https://www.samba.org/samba/docs/).

**Tip**: Restrict access with `valid users` for security.

---

## 🧭 What’s Next?

You’re now ready to manage AWS services, NFS, FTP, Apache, Firewalld, SELinux, and Samba on RHEL! Practice in a Free Tier AWS account or a local VM. Explore advanced topics like Ansible for automation or AWS CloudFormation for infrastructure. Questions? Check [Red Hat Documentation](https://access.redhat.com/documentation) or [AWS Training](https://aws.amazon.com/training/).