---
title: Deploying Static Website to AWS S3 with GitHub Actions (CI/CD)
author: M. Muzamil
pubDatetime: 2025-10-29T20:00:00Z
slug: aws-s3-cicd-deployment
featured: false
draft: false
tags:
  - AWS
  - CI/CD
  - S3
  - GitHub Actions
  - DevOps
  - Astro
description:
  "A complete step-by-step walkthrough on how to automatically deploy your static npm website from GitHub to AWS S3 using GitHub Actions — with free-tier resources."
timezone: "Asia/Karachi"
---

> 🚀 Build, Deploy, and Automate — Learn how to set up CI/CD for a static website hosted on AWS S3 using GitHub Actions.

---

![AWS S3 Deployment](/aws-web1.png)

<script async="async" data-cfasync="false" src="//pl27965007.effectivegatecpm.com/b6a41421a0c168a58753dacfe5fbedfa/invoke.js"></script>
<div id="container-b6a41421a0c168a58753dacfe5fbedfa"></div>

## 🧭 Table of Contents

- [🚀 CI/CD Deployment of Static Website to AWS S3 (`web-pipline`)](#-cicd-deployment-of-static-website-to-aws-s3-web-pipline)
  - [🧱 1. Project Overview](#-1-project-overview)
  - [⚙️ 2. Prerequisites](#️-2-prerequisites)
  - [🪣 3. Create an S3 Bucket](#-3-create-an-s3-bucket)
  - [🌐 4. Enable Static Website Hosting](#-4-enable-static-website-hosting)
  - [🔐 5. Create an IAM User for Deployment](#-5-create-an-iam-user-for-deployment)
  - [🔑 6. Add Secrets to GitHub](#-6-add-secrets-to-github)
  - [⚙️ 7. Create GitHub Actions Workflow](#️-7-create-github-actions-workflow)
  - [](#)
  - [🔓 8. Configure Bucket Policy for Public Access](#-8-configure-bucket-policy-for-public-access)
  - [⚡ 9. Run the Pipeline](#-9-run-the-pipeline)
  - [🌍 (Optional) 10. Add CloudFront for HTTPS \& Speed](#-optional-10-add-cloudfront-for-https--speed)
  - [🧠 Summary](#-summary)

---


# 🚀 CI/CD Deployment of Static Website to AWS S3 (`web-pipline`)

This guide explains how to automatically build and deploy your **Astro (or any NPM static)** website to **AWS S3** using **GitHub Actions**.  
Your site will deploy to the S3 bucket: **`web-pipline`** in region **`ap-south-1 (Mumbai)`**.

---

## 🧱 1. Project Overview

**Goal:**  
Whenever you push code → GitHub Actions automatically:
1. Builds your Astro/NPM website  
2. Deploys the output folder (`dist`) to AWS S3  
3. Makes your website live via Static Website Hosting

**Architecture:**
```

GitHub Repo (main branch)
↓
GitHub Actions (CI/CD)
↓
AWS S3 Bucket
↓
Public Website URL

```

---

## ⚙️ 2. Prerequisites
- ✅ AWS account (Free Tier)
- ✅ Public GitHub repository
- ✅ Your static site builds into `/dist` (Astro, React, etc.)

---

## 🪣 3. Create an S3 Bucket

1. Go to **AWS Console → S3 → Create bucket**
2. **Bucket name:** `web-pipline`
3. **Region:** `ap-south-1`
4. **Uncheck:** “Block all public access”
5. ✅ Acknowledge the warning checkbox
6. Click **Create bucket**

---

## 🌐 4. Enable Static Website Hosting

1. Click on your bucket → **Properties tab**  
2. Scroll down to **Static website hosting**
3. Click **Edit**
4. Choose **Enable**
   - Hosting type: *Host a static website*
   - Index document: `index.html`
   - Error document: `index.html`
5. Click **Save changes**
6. Note down your **Website endpoint**, for example:  
```

[http://web-pipline.s3-website-ap-south-1.amazonaws.com](http://web-pipline.s3-website-ap-south-1.amazonaws.com)

````

---

## 🔐 5. Create an IAM User for Deployment

1. Go to **IAM → Users → Add user**
2. Name it `github-deployer`
3. Choose **Programmatic access**
4. Click **Next → Attach policies directly**
5. Click **Create policy**
- Choose **JSON** and paste this (minimal permissions):

  ````json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ],
        "Resource": [
          "arn:aws:s3:::web-pipline",
          "arn:aws:s3:::web-pipline/*"
        ]
      }
    ]
  }
  ````
- Click **Next → Name it:** `S3DeployPolicy` → Create policy
6. Back in user creation, attach this policy
7. Finish user creation and copy:
- **Access key ID**
- **Secret access key**

---

## 🔑 6. Add Secrets to GitHub

In your GitHub repo →  
**Settings → Secrets → Actions → New repository secret**

Add these four:

| Secret Name | Value |
|--------------|--------|
| `AWS_ACCESS_KEY_ID` | your key ID |
| `AWS_SECRET_ACCESS_KEY` | your secret key |
| `AWS_REGION` | `ap-south-1` |
| `S3_BUCKET` | `web-pipline` |

---

## ⚙️ 7. Create GitHub Actions Workflow

In your repo root, make the folder and file:  
````
.github/workflows/deploy.yml
````

Paste this:

````
name: Deploy Astro Site to AWS S3

on:
  push:
    branches:
      - main

jobs:
  deploy:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 18

      - name: Install dependencies
        run: npm ci

      - name: Build Astro project
        run: npm run build

      - name: Sync files to S3
        uses: jakejarvis/s3-sync-action@master
        with:
          args: --delete
        env:
          AWS_S3_BUCKET: ${{ secrets.S3_BUCKET }}
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          AWS_REGION: ${{ secrets.AWS_REGION }}
          SOURCE_DIR: "dist"

````


Commit and push this file.

![AWS S3 Deployment](/aws-web3.png)
---

## 🔓 8. Configure Bucket Policy for Public Access

In AWS S3 → **Permissions tab → Bucket policy → Edit**

Paste this exact JSON (for your bucket):

````json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicReadGetObject",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::web-pipline/*"
    }
  ]
}
````

Then click **Save changes** ✅

Also confirm in the same tab:

* “Block all public access” → **Turned OFF**

---

## ⚡ 9. Run the Pipeline

1. Push your latest code to the `main` branch
2. Go to **GitHub → Actions tab**
3. Wait for the workflow to run

   * It will: install → build → upload → sync with S3

When it finishes:

* Open:

  ````
  http://web-pipline.s3-website-ap-south-1.amazonaws.com
  ````

  Your site is now **LIVE** 🎉

---

## 🌍 (Optional) 10. Add CloudFront for HTTPS & Speed

Later you can:

1. Go to **CloudFront → Create Distribution**
2. Origin = your S3 bucket
3. Add a custom domain + SSL certificate via **ACM**

Then you’ll get a secure global URL like:

````
https://dxxxxxxxx.cloudfront.net
````

---

## 🧠 Summary

| Step | Action                           |
| ---- | -------------------------------- |
| 1    | Create S3 bucket (`web-pipline`) |
| 2    | Enable static hosting            |
| 3    | Create IAM deploy user           |
| 4    | Add GitHub secrets               |
| 5    | Add GitHub Actions workflow      |
| 6    | Add public bucket policy         |
| 7    | Push → auto build + deploy       |
| 8    | Visit website endpoint URL       |

---

✅ **Final Website URL:**

````
http://web-pipline.s3-website-ap-south-1.amazonaws.com
````

![AWS S3 Deployment](/aws-web2.png)