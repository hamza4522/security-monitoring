# 🚀 Deploying LLM Models on K3s on AWS EC2 (GPU Instance)

> **Author:** Hamza | **Date:** June 2026  
> **Target Environment:** AWS EC2 GPU Instance + K3s Kubernetes + vLLM / KServe

---

## 📋 Table of Contents

1. [Overview & Architecture](#overview--architecture)
2. [Why vLLM? And Its Alternatives](#why-vllm-and-its-alternatives)
3. [Why KServe? And Its Alternatives](#why-kserve-and-its-alternatives)
4. [CPU vs GPU LLM Deployment Comparison](#cpu-vs-gpu-llm-deployment-comparison)
5. [Prerequisites](#prerequisites)
6. [Step 1 — Launch & Configure AWS EC2 GPU Instance](#step-1--launch--configure-aws-ec2-gpu-instance)
7. [Step 2 — Install NVIDIA Drivers & CUDA](#step-2--install-nvidia-drivers--cuda)
8. [Step 3 — Install Docker & NVIDIA Container Toolkit](#step-3--install-docker--nvidia-container-toolkit)
9. [Step 4 — Install K3s (Lightweight Kubernetes)](#step-4--install-k3s-lightweight-kubernetes)
10. [Step 5 — Install NVIDIA GPU Operator on K3s](#step-5--install-nvidia-gpu-operator-on-k3s)
11. [Step 6 — Install Helm](#step-6--install-helm)
12. [Step 7 — Deploy vLLM on K3s](#step-7--deploy-vllm-on-k3s)
13. [Step 8 — Deploy KServe (Optional Advanced Setup)](#step-8--deploy-kserve-optional-advanced-setup)
14. [Step 9 — Expose LLM via LoadBalancer / Ingress](#step-9--expose-llm-via-loadbalancer--ingress)
15. [Step 10 — Test Your LLM Endpoint](#step-10--test-your-llm-endpoint)
16. [Step 11 — Monitoring & Observability](#step-11--monitoring--observability)
17. [Step 12 — Auto-Scaling with KEDA](#step-12--auto-scaling-with-keda)
18. [Security Best Practices](#security-best-practices)
19. [Troubleshooting](#troubleshooting)
20. [Cost Optimization Tips](#cost-optimization-tips)
21. [Kubernetes Components Deep-Dive](#kubernetes-components-deep-dive)
22. [kubectl → API Server → Components: Full Call Flow](#kubectl--api-server--components-full-call-flow)
23. [Production Error Encyclopedia](#production-error-encyclopedia)
24. [Real Production Scenarios](#real-production-scenarios)

---

## Overview & Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   AWS EC2 GPU Instance                   │
│  (g4dn.xlarge / g5.2xlarge / p3.2xlarge)                │
│                                                         │
│  ┌──────────────────────────────────────────────────┐   │
│  │                  K3s Cluster                     │   │
│  │                                                  │   │
│  │  ┌─────────────┐    ┌──────────────────────┐    │   │
│  │  │  vLLM Pod   │    │   KServe InferenceService│  │   │
│  │  │  (GPU)      │    │   (optional)         │    │   │
│  │  └─────────────┘    └──────────────────────┘    │   │
│  │                                                  │   │
│  │  ┌─────────────┐    ┌─────────────────────┐     │   │
│  │  │  Prometheus │    │     Grafana          │     │   │
│  │  └─────────────┘    └─────────────────────┘     │   │
│  │                                                  │   │
│  │  ┌─────────────────────────────────────────┐    │   │
│  │  │  NVIDIA GPU Operator + Device Plugin    │    │   │
│  │  └─────────────────────────────────────────┘    │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
              │
              ▼
    ┌──────────────────┐
    │  API Gateway /   │
    │  Nginx Ingress   │
    └──────────────────┘
              │
              ▼
    ┌──────────────────┐
    │  Client / App    │
    │  (OpenAI-compat) │
    └──────────────────┘
```

**What this guide covers:**
- Provisioning an AWS EC2 GPU machine
- Installing K3s (lightweight K8s) with GPU support
- Deploying an LLM (e.g., Mistral, Llama-3, Qwen) using **vLLM**
- Optionally wrapping it with **KServe** for production-grade serving
- Exposing it via a REST API compatible with the OpenAI spec
- Monitoring with Prometheus + Grafana

---

## Why vLLM? And Its Alternatives

### 🔥 What is vLLM?

[vLLM](https://github.com/vllm-project/vllm) is a **high-throughput and memory-efficient inference engine** for LLMs. It was developed at UC Berkeley and is the industry standard for GPU-based LLM serving.

### Why We Use vLLM

| Feature | Explanation |
|---|---|
| **PagedAttention** | Novel memory management — allows serving more requests in parallel by treating KV-cache like OS virtual memory pages |
| **Continuous Batching** | Dynamically batches incoming requests (unlike static batching), maximizing GPU utilization |
| **OpenAI-compatible API** | Drop-in replacement for OpenAI API (`/v1/chat/completions`, `/v1/completions`) |
| **Multi-GPU support** | Tensor parallelism and pipeline parallelism across multiple GPUs |
| **Quantization** | Supports GPTQ, AWQ, INT4, INT8 quantization |
| **Wide model support** | Llama, Mistral, Falcon, Qwen, Gemma, Phi, GPT-2, etc. |
| **Streaming** | Supports streaming responses (SSE) |

### vLLM Alternatives Comparison

| Tool | Best For | Pros | Cons |
|---|---|---|---|
| **vLLM** | Production GPU serving | Fastest throughput, OpenAI-compatible, continuous batching | Requires GPU, complex setup |
| **Ollama** | Local/dev testing | Very easy setup, supports many models | Not production-grade, no advanced batching |
| **llama.cpp** | CPU/low-resource inference | Runs on CPU/Metal/ROCm, quantized models | Slow throughput, no batching |
| **TGI (Text Gen Inference)** | HuggingFace ecosystem | Good performance, Rust-based | Less flexible than vLLM, HF-centric |
| **TorchServe** | PyTorch native | Deep PyTorch integration | Verbose config, lower throughput |
| **Triton Inference Server** | Multi-framework, enterprise | NVIDIA native, high performance | Complex setup, NVIDIA-only |
| **Ray Serve** | Distributed serving | Great for large-scale Ray workloads | Heavyweight, steep learning curve |
| **LiteLLM** | API proxy/router | Supports 100+ LLM providers | Proxy only, not an inference engine |
| **LocalAI** | CPU-based alternative to vLLM | No GPU required, OpenAI-compat | Much slower on large models |

> **✅ Recommendation:** Use **vLLM** for GPU-based production, **Ollama** for dev/testing, **llama.cpp** for CPU-only setups.

---

## Why KServe? And Its Alternatives

### 🔥 What is KServe?

[KServe](https://kserve.github.io/website/) (formerly KFServing) is a **Kubernetes-native model serving framework** that provides:
- Model versioning and canary deployments
- Automatic scaling (including scale-to-zero)
- Pre/post-processing pipelines
- REST and gRPC endpoints

### Why We Use KServe

| Feature | Explanation |
|---|---|
| **Model versioning** | Easily deploy v1, v2, canary releases |
| **Auto-scaling** | Native HPA + KEDA integration |
| **Scale to zero** | Save costs when no traffic |
| **Inference graph** | Chain pre/post processing steps |
| **Multi-framework** | TensorFlow, PyTorch, ONNX, Triton, HuggingFace |
| **Traffic splitting** | A/B testing between models |

### KServe Alternatives Comparison

| Tool | Best For | Pros | Cons |
|---|---|---|---|
| **KServe** | K8s-native serving | Versioning, canary, auto-scale | Complex install, needs Istio/Knative |
| **Seldon Core** | Enterprise ML serving | MLOps, drift detection | Commercial features locked |
| **BentoML** | Packaging + serving | Easy to package, cloud-agnostic | Not K8s-native |
| **MLflow Models** | MLflow ecosystems | Easy experiment tracking | Not a serving solution per se |
| **Cortex** | AWS-specific | Managed, simple YAML | AWS lock-in |
| **Ray Serve** | Distributed serving | Scalable, Python native | Heavyweight |
| **Plain K8s Deployment** | Simple, custom | Full control | No model versioning or auto-scale out of box |

> **✅ Recommendation:** For a single-model production setup, **vLLM + plain K8s Deployment + HPA** is simpler. Use **KServe** only if you need canary deployments, multiple models, or scale-to-zero.

---

## CPU vs GPU LLM Deployment Comparison

### 🏆 Performance & Capability Comparison

| Dimension | CPU Deployment | GPU Deployment |
|---|---|---|
| **Inference Speed** | 1–10 tokens/sec (7B model) | 50–150+ tokens/sec (7B model) |
| **Latency (TTFT)** | High (5–30 seconds) | Low (0.2–1 second) |
| **Model Size Limit** | Practical: up to ~7B (quantized) | Practical: up to 70B+ (multi-GPU) |
| **Concurrency** | 1–4 concurrent requests | 50–200+ concurrent requests |
| **Throughput** | ~100 tokens/min | ~5,000–15,000 tokens/min |
| **Memory Type** | RAM (DDR4/DDR5) | VRAM (HBM2/GDDR6) |
| **Memory Bandwidth** | ~50–100 GB/s | ~500–2,000+ GB/s |
| **Quantization Support** | GGUF (Q4, Q8), GGML | GPTQ, AWQ, INT8, FP8 |
| **Cost (AWS)** | ~$0.05–$0.20/hr (t3, c5) | ~$0.53–$3.00+/hr (g4dn, g5) |

### Limitations of CPU-Based LLM Deployment

#### ❌ Critical Limitations:
1. **Bandwidth bottleneck:** LLM inference is memory-bandwidth-bound. CPUs have 10-20x less bandwidth than GPUs.
2. **No parallel matrix ops:** Transformer attention heads require massive parallelism — CPUs can only do sequential or limited SIMD operations.
3. **Context window limits:** Longer prompts exponentially increase CPU processing time.
4. **No FP16 acceleration:** Most CPUs lack native FP16 support; GPUs have tensor cores for this.
5. **KV Cache size:** On CPU, KV cache must fit in RAM; on GPU it fits in VRAM with PagedAttention.
6. **Quantization quality tradeoff:** CPU requires aggressive Q4 quantization, losing model quality; GPU can use Q8 or FP16 with no quality loss.
7. **Batch processing:** CPUs cannot efficiently batch multiple inference requests simultaneously.
8. **Scaling cost:** To double throughput on CPU, you double your instance count; GPU can batch more requests per instance.

#### ❌ Deployment Tooling Limitations on CPU:
- **vLLM** does not support CPU-only inference (requires CUDA)
- **PagedAttention** is GPU-only
- **Continuous batching** is not effective on CPU
- Cannot use AWQ/GPTQ quantization (GPU formats)
- Flash Attention (critical for speed) is GPU-only

#### ✅ When CPU Deployment Makes Sense:
- Development and testing only
- Very small models (≤3B parameters, heavily quantized)
- Ultra-low budget scenarios
- Air-gapped environments without GPU support
- Batch offline processing where latency doesn't matter

### Limitations of GPU-Based LLM Deployment

| Limitation | Details |
|---|---|
| **Cost** | g4dn.xlarge = ~$0.53/hr; p3.8xlarge = ~$12.24/hr |
| **VRAM limits** | g4dn.xlarge has only 16GB VRAM — limits model size |
| **Driver complexity** | NVIDIA drivers, CUDA, cuDNN must match exactly |
| **Spot interruptions** | Spot GPU instances can be reclaimed by AWS |
| **Overkill for tiny loads** | For <10 req/day, GPU is wasteful |
| **Cooling & power** | Not a concern on AWS, but in on-prem it's critical |

---

## Prerequisites

### AWS Requirements
- AWS Account with EC2 access
- IAM user/role with EC2, VPC, Security Group permissions
- Key pair for SSH access
- VPC with public subnet (or private subnet + bastion)

### Local Machine Requirements
```bash
# Install AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Verify
aws --version
# Output: aws-cli/2.x.x

# Configure AWS credentials
aws configure
# AWS Access Key ID: <your-access-key>
# AWS Secret Access Key: <your-secret-key>
# Default region: us-east-1
# Default output format: json
```

### Recommended AWS GPU Instance Types

| Instance | GPU | VRAM | vCPUs | RAM | Use Case | Price/hr |
|---|---|---|---|---|---|---|
| `g4dn.xlarge` | NVIDIA T4 | 16 GB | 4 | 16 GB | Dev/small models ≤7B | ~$0.53 |
| `g4dn.2xlarge` | NVIDIA T4 | 16 GB | 8 | 32 GB | 7B–13B models | ~$0.75 |
| `g4dn.12xlarge` | 4x NVIDIA T4 | 64 GB | 48 | 192 GB | 30B–70B models | ~$3.91 |
| `g5.xlarge` | NVIDIA A10G | 24 GB | 4 | 16 GB | Better perf, 13B | ~$1.01 |
| `g5.2xlarge` | NVIDIA A10G | 24 GB | 8 | 32 GB | 13B–30B | ~$1.21 |
| `g5.12xlarge` | 4x NVIDIA A10G | 96 GB | 48 | 192 GB | 70B models | ~$5.67 |
| `p3.2xlarge` | NVIDIA V100 | 16 GB | 8 | 61 GB | Training+inference | ~$3.06 |
| `p3.8xlarge` | 4x NVIDIA V100 | 64 GB | 32 | 244 GB | Large model training | ~$12.24 |

> **✅ Recommended starting point:** `g4dn.xlarge` for Llama-3-8B, `g5.2xlarge` for 13B models.

---

## Step 1 — Launch & Configure AWS EC2 GPU Instance

### 1.1 — Launch EC2 Instance (CLI Method)

```bash
# Find the latest Deep Learning AMI (Ubuntu 20.04) with CUDA pre-installed
# This saves hours of driver installation time
aws ec2 describe-images \
  --region us-east-1 \
  --owners amazon \
  --filters \
    "Name=name,Values=Deep Learning AMI GPU PyTorch*Ubuntu 20.04*" \
    "Name=state,Values=available" \
  --query "sort_by(Images, &CreationDate)[-1].ImageId" \
  --output text
# Example Output: ami-0xxxxxxxxxxxxxxxx

# Store the AMI ID
AMI_ID="ami-0xxxxxxxxxxxxxxxx"   # Replace with actual output above

# Create a security group for the LLM server
aws ec2 create-security-group \
  --group-name llm-k3s-sg \
  --description "Security group for K3s LLM deployment" \
  --vpc-id <your-vpc-id>
# Output: { "GroupId": "sg-xxxxxxxxxxxxxxxxx" }

SG_ID="sg-xxxxxxxxxxxxxxxxx"   # Replace with actual output

# Allow SSH access (port 22) — restrict to your IP for security
aws ec2 authorize-security-group-ingress \
  --group-id $SG_ID \
  --protocol tcp \
  --port 22 \
  --cidr <your-ip>/32
# Why: SSH is needed for remote management of the instance

# Allow Kubernetes API server (port 6443) — for kubectl access
aws ec2 authorize-security-group-ingress \
  --group-id $SG_ID \
  --protocol tcp \
  --port 6443 \
  --cidr <your-ip>/32
# Why: K3s API server runs on 6443, kubectl connects here

# Allow LLM API port (8000) — for accessing the model API
aws ec2 authorize-security-group-ingress \
  --group-id $SG_ID \
  --protocol tcp \
  --port 8000 \
  --cidr 0.0.0.0/0
# Why: vLLM serves OpenAI-compatible API on port 8000

# Allow NodePort range (30000-32767) — for K3s NodePort services
aws ec2 authorize-security-group-ingress \
  --group-id $SG_ID \
  --protocol tcp \
  --port 30000-32767 \
  --cidr 0.0.0.0/0
# Why: Kubernetes NodePort services are exposed in this range

# Launch the EC2 GPU instance
aws ec2 run-instances \
  --image-id $AMI_ID \
  --instance-type g4dn.xlarge \
  --key-name <your-key-pair-name> \
  --security-group-ids $SG_ID \
  --subnet-id <your-subnet-id> \
  --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":200,"VolumeType":"gp3","DeleteOnTermination":true}}]' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=llm-k3s-server}]' \
  --count 1
# Why 200GB EBS: LLM model weights are large (Llama-3-8B = ~16GB, 70B = ~140GB)
# Why gp3: Better IOPS/cost ratio than gp2

# Get the public IP of the instance
aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=llm-k3s-server" \
  --query "Reservations[0].Instances[0].PublicIpAddress" \
  --output text
# Output: 54.xxx.xxx.xxx

EC2_IP="54.xxx.xxx.xxx"   # Replace with actual output

# SSH into the instance
ssh -i ~/.ssh/<your-key-pair>.pem ubuntu@$EC2_IP
```

### 1.2 — Initial System Configuration

```bash
# Update all packages — always do this first
sudo apt-get update && sudo apt-get upgrade -y
# Why: Ensures security patches and latest package versions

# Install essential tools
sudo apt-get install -y \
  curl \
  wget \
  git \
  htop \
  nvtop \
  vim \
  unzip \
  build-essential \
  python3-pip \
  jq
# Why each tool:
# curl/wget: Download scripts and files
# git: Clone model repos
# htop: CPU/memory monitoring
# nvtop: GPU monitoring (like htop but for GPU)
# vim: Text editor
# unzip: Extract archives
# build-essential: Compile tools
# jq: Parse JSON in shell scripts

# Set timezone (optional but good practice)
sudo timedatectl set-timezone UTC

# Increase file descriptor limits (needed for large model loading)
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "fs.file-max = 2097152" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
# Why: LLM inference opens many file handles for model weight shards
```

---

## Step 2 — Install NVIDIA Drivers & CUDA

> **Note:** If you used the AWS Deep Learning AMI, drivers may already be installed. Verify with `nvidia-smi`.

```bash
# Check if NVIDIA driver is already installed
nvidia-smi
# If this command works, skip to Step 3

# -----------------------------------------------------------------------
# If NOT installed, follow these steps:
# -----------------------------------------------------------------------

# Remove any existing NVIDIA installations to avoid conflicts
sudo apt-get remove --purge -y nvidia-* cuda-*
sudo apt-get autoremove -y
sudo apt-get autoclean

# Add NVIDIA package repository
wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2004/x86_64/cuda-keyring_1.1-1_all.deb
sudo dpkg -i cuda-keyring_1.1-1_all.deb
sudo apt-get update
# Why: Adds NVIDIA's official APT repository for CUDA packages

# Install CUDA 12.1 (compatible with most modern LLM frameworks)
sudo apt-get install -y cuda-12-1
# Why CUDA 12.1: vLLM and PyTorch have best support for CUDA 12.x
# Alternative: cuda-11-8 for older hardware compatibility

# Install the NVIDIA driver (535 = latest stable as of 2024)
sudo apt-get install -y nvidia-driver-535
# Why 535: Latest stable driver supporting CUDA 12.x

# Add CUDA to PATH (so nvidia-smi and nvcc can be found)
echo 'export PATH=/usr/local/cuda/bin:$PATH' >> ~/.bashrc
echo 'export LD_LIBRARY_PATH=/usr/local/cuda/lib64:$LD_LIBRARY_PATH' >> ~/.bashrc
source ~/.bashrc

# Reboot to apply driver changes
sudo reboot
# Wait for instance to come back up, then SSH again

# Verify GPU is detected and driver is working
nvidia-smi
# Expected output shows:
# - Driver Version: 535.x.x
# - CUDA Version: 12.x
# - GPU name (e.g., Tesla T4)
# - Memory usage

# Verify CUDA compiler is available
nvcc --version
# Expected: Cuda compilation tools, release 12.1

# Check GPU memory
nvidia-smi --query-gpu=name,memory.total,memory.free --format=csv
# Example: Tesla T4, 15360 MiB, 15360 MiB
```

---

## Step 3 — Install Docker & NVIDIA Container Toolkit

```bash
# Install Docker (required by K3s for container runtime)
curl -fsSL https://get.docker.com | sh
# Why Docker: K3s uses Docker (or containerd) to run pod containers

# Add current user to docker group (avoid using sudo with docker)
sudo usermod -aG docker $USER
newgrp docker
# Why: Allows running docker commands without sudo

# Verify Docker installation
docker --version
# Output: Docker version 24.x.x

# Test Docker works
docker run hello-world
# Output: "Hello from Docker!"

# -----------------------------------------------------------------------
# Install NVIDIA Container Toolkit
# This allows Docker/containers to access the GPU
# -----------------------------------------------------------------------

# Add NVIDIA container toolkit repository
curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list | \
  sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' | \
  sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list

sudo apt-get update

# Install the toolkit
sudo apt-get install -y nvidia-container-toolkit
# Why: This is the bridge between Docker/containers and the NVIDIA GPU driver

# Configure Docker daemon to use NVIDIA runtime
sudo nvidia-ctk runtime configure --runtime=docker
# Why: Tells Docker to use nvidia as the default GPU runtime

# Restart Docker to apply changes
sudo systemctl restart docker

# Verify GPU access from Docker container
docker run --rm --gpus all nvidia/cuda:12.1.0-base-ubuntu20.04 nvidia-smi
# Expected: Same output as running nvidia-smi on the host
# If this works, containers can access the GPU

# -----------------------------------------------------------------------
# Configure containerd (K3s uses containerd by default, not Docker)
# -----------------------------------------------------------------------

# Configure nvidia-ctk for containerd
sudo nvidia-ctk runtime configure --runtime=containerd
# Why: K3s uses containerd, not Docker, so we must configure containerd too

# Restart containerd
sudo systemctl restart containerd

# Verify containerd config was updated
grep -A 5 'nvidia' /etc/containerd/config.toml
# Should show nvidia runtime configuration
```

---

## Step 4 — Install K3s (Lightweight Kubernetes)

### Why K3s instead of full Kubernetes (K8s)?

| Feature | K3s | Full K8s (kubeadm) |
|---|---|---|
| **Binary size** | ~100MB single binary | Hundreds of components |
| **RAM usage** | ~512MB | ~2GB+ |
| **Install time** | 30 seconds | 15-30 minutes |
| **Setup complexity** | One command | Complex multi-step |
| **Production ready** | Yes (CNCF certified) | Yes |
| **Edge/IoT** | Designed for it | Not ideal |
| **NVIDIA GPU support** | Supported via operator | Supported via operator |
| **Best for** | Single/small node setups | Large multi-node clusters |

### Why K3s for LLM on EC2?
- Our LLM workload typically runs on 1-3 nodes
- K3s uses fewer resources, leaving more RAM/CPU for the model
- Easier to manage and update
- Still Kubernetes-compliant — all K8s manifests work

```bash
# -----------------------------------------------------------------------
# Install K3s with GPU support
# -----------------------------------------------------------------------

# Install K3s without Traefik (we'll use Nginx Ingress instead)
# and with containerd NVIDIA runtime
curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="\
  --disable traefik \
  --write-kubeconfig-mode 644 \
  --container-runtime-endpoint unix:///run/containerd/containerd.sock" sh -
# Explanation of flags:
# --disable traefik: Don't install the default Traefik ingress (use Nginx instead)
# --write-kubeconfig-mode 644: Makes kubeconfig readable without sudo
# --container-runtime-endpoint: Use containerd (which has NVIDIA runtime configured)

# Verify K3s is running
sudo systemctl status k3s
# Should show: Active: active (running)

# Check that the node is Ready
kubectl get nodes
# Expected output:
# NAME         STATUS   ROLES                  AGE   VERSION
# ip-xxx-xxx   Ready    control-plane,master   1m    v1.28.x+k3s1

# Copy kubeconfig to standard location for kubectl
mkdir -p ~/.kube
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown $USER:$USER ~/.kube/config
# Why: kubectl looks for config in ~/.kube/config by default

# Verify kubectl works
kubectl cluster-info
# Output: Kubernetes control plane is running at https://127.0.0.1:6443

# Check all system pods are running
kubectl get pods -n kube-system
# All pods should be Running or Completed

# -----------------------------------------------------------------------
# (Optional) Access K3s cluster from your LOCAL machine
# -----------------------------------------------------------------------

# On your LOCAL machine, install kubectl
# macOS:
brew install kubectl
# Linux:
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl && sudo mv kubectl /usr/local/bin/

# On EC2, get the kubeconfig and edit the server address
cat ~/.kube/config
# Copy the content to your local machine

# On local machine, create/edit ~/.kube/config
# Replace "server: https://127.0.0.1:6443" with "server: https://<EC2-PUBLIC-IP>:6443"
# Make sure port 6443 is open in the security group (done in Step 1)

# Test remote access
kubectl get nodes --kubeconfig ~/.kube/config
```

---

## Step 5 — Install NVIDIA GPU Operator on K3s

The NVIDIA GPU Operator automatically manages all NVIDIA software components (drivers, device plugins, etc.) as Kubernetes pods.

### Why GPU Operator?

| Component | What it does |
|---|---|
| **NVIDIA Device Plugin** | Exposes GPU as a schedulable Kubernetes resource (`nvidia.com/gpu`) |
| **DCGM Exporter** | Exports GPU metrics (temp, utilization, memory) to Prometheus |
| **GPU Feature Discovery** | Labels nodes with GPU capabilities |
| **MIG Manager** | Manages NVIDIA Multi-Instance GPU (for A100/H100) |

```bash
# Install Helm (needed to install GPU Operator)
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
helm version
# Output: version.BuildInfo{Version:"v3.x.x", ...}

# Add NVIDIA Helm repository
helm repo add nvidia https://helm.ngc.nvidia.com/nvidia
helm repo update
# Why: The GPU Operator chart is hosted in NVIDIA's official Helm repository

# Install NVIDIA GPU Operator
# Note: On K3s we specify the containerd runtime path
helm install gpu-operator nvidia/gpu-operator \
  --namespace gpu-operator \
  --create-namespace \
  --set driver.enabled=false \
  --set toolkit.enabled=false \
  --set operator.defaultRuntime=containerd \
  --set toolkit.env[0].name=CONTAINERD_CONFIG \
  --set toolkit.env[0].value=/var/lib/rancher/k3s/agent/etc/containerd/config.toml \
  --set toolkit.env[1].name=CONTAINERD_SOCKET \
  --set toolkit.env[1].value=/run/k3s/containerd/containerd.sock \
  --set toolkit.env[2].name=CONTAINERD_RUNTIME_CLASS \
  --set toolkit.env[2].value=nvidia
# Explanation of flags:
# --set driver.enabled=false: We already installed the driver manually
# --set toolkit.enabled=false: NVIDIA Container Toolkit already installed
# --set operator.defaultRuntime=containerd: Use containerd (K3s default)
# toolkit.env settings: Point to K3s-specific containerd paths

# Wait for GPU operator to be ready (may take 2-5 minutes)
kubectl wait --for=condition=ready pod \
  -l app=gpu-operator \
  -n gpu-operator \
  --timeout=300s

# Check all GPU operator pods are running
kubectl get pods -n gpu-operator
# All pods should be Running

# Verify GPU is schedulable in Kubernetes
kubectl describe nodes | grep -A 10 "Allocatable:"
# Should show: nvidia.com/gpu: 1 (or however many GPUs you have)

# Test GPU scheduling — run a pod that uses the GPU
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: gpu-test-pod
spec:
  restartPolicy: Never
  containers:
  - name: cuda-test
    image: nvidia/cuda:12.1.0-base-ubuntu20.04
    command: ["nvidia-smi"]
    resources:
      limits:
        nvidia.com/gpu: 1
EOF
# Why: This confirms Kubernetes can schedule GPU workloads

# Watch the pod run
kubectl wait --for=condition=complete pod/gpu-test-pod --timeout=120s
kubectl logs gpu-test-pod
# Should show nvidia-smi output with GPU details

# Clean up test pod
kubectl delete pod gpu-test-pod
```

---

## Step 6 — Install Helm

> Already installed in Step 5. Verify with:

```bash
helm version
# Output: version.BuildInfo{Version:"v3.x.x"}

# Add commonly needed Helm repositories
helm repo add stable https://charts.helm.sh/stable
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update
# Why: Pre-adds repositories so charts are ready to install
```

---

## Step 7 — Deploy vLLM on K3s

### 7.1 — Create Namespace and Hugging Face Secret

```bash
# Create a dedicated namespace for LLM workloads
kubectl create namespace llm-serving
# Why: Separates LLM workloads from system components for better organization

# Create a Kubernetes secret for Hugging Face token
# (Required for gated models like Llama-3, Mistral)
# Get your token from: https://huggingface.co/settings/tokens
kubectl create secret generic hf-token \
  --from-literal=token=hf_xxxxxxxxxxxxxxxxxxxx \
  --namespace llm-serving
# Why: Many models on HuggingFace require authentication
# The secret is mounted as an env variable in the vLLM pod
```

### 7.2 — Create Persistent Volume for Model Cache

```bash
# Create a PersistentVolumeClaim to store downloaded model weights
# This prevents re-downloading the model every time the pod restarts
kubectl apply -f - <<EOF
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: model-cache-pvc
  namespace: llm-serving
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: local-path   # K3s default storage class
  resources:
    requests:
      storage: 100Gi
EOF
# Why 100Gi: Llama-3-8B weights = ~16GB, 70B = ~140GB
# Why local-path: K3s ships with this storage class by default

# Verify PVC is created
kubectl get pvc -n llm-serving
# STATUS should be Pending (becomes Bound when a pod uses it)
```

### 7.3 — Deploy vLLM (Llama-3-8B Example)

```bash
# Deploy vLLM as a Kubernetes Deployment
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vllm-llama3-8b
  namespace: llm-serving
  labels:
    app: vllm
    model: llama3-8b
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vllm
      model: llama3-8b
  template:
    metadata:
      labels:
        app: vllm
        model: llama3-8b
    spec:
      containers:
      - name: vllm
        image: vllm/vllm-openai:latest
        # vllm/vllm-openai: Official vLLM image with OpenAI-compatible server
        # Alternative images:
        # - vllm/vllm-openai:v0.4.3 (pin to specific version for stability)
        # - ghcr.io/huggingface/text-generation-inference:2.1.0 (TGI alternative)
        command:
        - python
        - -m
        - vllm.entrypoints.openai.api_server
        args:
        - --model
        - meta-llama/Meta-Llama-3-8B-Instruct
        # Why this model: Llama-3-8B fits in 16GB VRAM with FP16
        # Alternative models:
        # - mistralai/Mistral-7B-Instruct-v0.3 (open weights, no token needed)
        # - Qwen/Qwen2-7B-Instruct (strong multilingual)
        # - microsoft/Phi-3-mini-4k-instruct (small, efficient)
        # - TheBloke/Llama-2-13B-GPTQ (quantized for less VRAM)
        - --host
        - 0.0.0.0
        - --port
        - "8000"
        - --dtype
        - float16
        # Why float16: Halves VRAM usage vs float32 with minimal quality loss
        # Alternative: bfloat16 (better on A100/H100), float32 (full precision, 2x VRAM)
        - --max-model-len
        - "4096"
        # Why 4096: Limits context window to save VRAM. Increase if you have more VRAM
        # For 16GB VRAM: max 4096-8192 for 8B models
        # For 24GB VRAM: max 8192-16384 for 8B models
        - --tensor-parallel-size
        - "1"
        # Why 1: We have 1 GPU. Set to 2+ if you have multiple GPUs
        # Tensor parallelism splits the model across GPUs
        - --gpu-memory-utilization
        - "0.9"
        # Why 0.9: Uses 90% of GPU VRAM for model+KV cache
        # Leave 10% headroom to avoid OOM errors
        ports:
        - containerPort: 8000
          name: http
        env:
        - name: HUGGING_FACE_HUB_TOKEN
          valueFrom:
            secretKeyRef:
              name: hf-token
              key: token
        # Why: Authenticates with HuggingFace to download gated models
        - name: HF_HOME
          value: /model-cache
        # Why: Sets HuggingFace cache dir to our persistent volume
        resources:
          requests:
            cpu: "4"
            memory: "16Gi"
            nvidia.com/gpu: "1"
          limits:
            cpu: "8"
            memory: "32Gi"
            nvidia.com/gpu: "1"
        # Why these resources:
        # nvidia.com/gpu: 1 — Request exactly 1 GPU (critical for scheduling)
        # memory: 16Gi — vLLM needs significant CPU RAM for tokenization
        # cpu: 4-8 — For tokenization preprocessing
        volumeMounts:
        - name: model-cache
          mountPath: /model-cache
        # Why: Mounts the PVC at /model-cache to persist model weights
        - name: shm
          mountPath: /dev/shm
        # Why: vLLM uses shared memory for inter-process communication
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 300
          periodSeconds: 30
          failureThreshold: 10
        # Why 300s initialDelay: Downloading and loading 8B model takes 3-5 minutes
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 60
          periodSeconds: 10
          failureThreshold: 30
      volumes:
      - name: model-cache
        persistentVolumeClaim:
          claimName: model-cache-pvc
      - name: shm
        emptyDir:
          medium: Memory
          sizeLimit: 8Gi
      # Why emptyDir for shm: Kubernetes doesn't expose /dev/shm, so we
      # create an in-memory tmpfs volume for shared memory
      tolerations:
      - key: nvidia.com/gpu
        operator: Exists
        effect: NoSchedule
      # Why tolerations: GPU nodes may have taints; this allows scheduling on them
EOF
```

### 7.4 — Create Service for vLLM

```bash
# Expose the vLLM deployment as a Kubernetes Service
kubectl apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: vllm-service
  namespace: llm-serving
  labels:
    app: vllm
spec:
  selector:
    app: vllm
  ports:
  - port: 8000
    targetPort: 8000
    protocol: TCP
    name: http
  type: ClusterIP
  # Why ClusterIP: Internal-only access; exposed externally via Ingress
  # Alternative: NodePort for direct node access without Ingress
EOF

# Watch the deployment rollout
kubectl rollout status deployment/vllm-llama3-8b -n llm-serving
# This will wait until the deployment is ready (may take 5-10 minutes for model download)

# Check pod status
kubectl get pods -n llm-serving -w
# Status goes: Pending -> ContainerCreating -> Running

# Watch model download logs (this is where most time is spent)
kubectl logs -f deployment/vllm-llama3-8b -n llm-serving
# You'll see:
# 1. Pulling model weights from HuggingFace
# 2. Loading model into GPU memory
# 3. "Application startup complete" — model is ready
```

### 7.5 — GPU Memory Optimization Flags

```bash
# For 7B/8B models on 16GB GPU (g4dn.xlarge):
# Already covered in the deployment above with:
# --dtype float16 --max-model-len 4096 --gpu-memory-utilization 0.9

# For 13B models on 24GB GPU (g5.xlarge):
# Change these args in the deployment:
# --model mistralai/Mistral-7B-Instruct-v0.3
# --max-model-len 8192
# --gpu-memory-utilization 0.88

# For 70B models on 4x GPU (g4dn.12xlarge):
# --model meta-llama/Meta-Llama-3-70B-Instruct
# --tensor-parallel-size 4     # Splits model across 4 GPUs
# --dtype float16
# --max-model-len 4096
# --gpu-memory-utilization 0.90

# For quantized models (fit large models in less VRAM):
# AWQ quantized (requires GPU):
# --model TheBloke/Llama-2-13B-chat-AWQ
# --quantization awq
# Why AWQ: 4-bit quantization with minimal quality loss vs GPTQ

# GPTQ quantized:
# --model TheBloke/Mistral-7B-Instruct-v0.2-GPTQ
# --quantization gptq
```

---

## Step 8 — Deploy KServe (Optional Advanced Setup)

> Use this if you need model versioning, canary deployments, or scale-to-zero.

### 8.1 — Install Cert-Manager (Required by KServe)

```bash
# Install cert-manager (manages TLS certificates for KServe)
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml
# Why cert-manager: KServe uses webhooks that require TLS certificates

# Wait for cert-manager pods to be ready
kubectl wait --for=condition=ready pod \
  -l app.kubernetes.io/instance=cert-manager \
  -n cert-manager \
  --timeout=120s

kubectl get pods -n cert-manager
# All 3 pods (cert-manager, webhook, cainjector) should be Running
```

### 8.2 — Install KServe

```bash
# Install KServe (standalone mode — no Istio/Knative required)
kubectl apply -f https://github.com/kserve/kserve/releases/download/v0.12.0/kserve.yaml
kubectl apply -f https://github.com/kserve/kserve/releases/download/v0.12.0/kserve-cluster-resources.yaml
# Why standalone mode: Knative and Istio are heavy; standalone is simpler for single-node

# Wait for KServe pods to be ready
kubectl wait --for=condition=ready pod \
  -l control-plane=kserve-controller-manager \
  -n kserve \
  --timeout=120s

kubectl get pods -n kserve
# kserve-controller-manager pod should be Running
```

### 8.3 — Create KServe InferenceService

```bash
# Deploy an LLM using KServe's InferenceService CRD
kubectl apply -f - <<EOF
apiVersion: serving.kserve.io/v1beta1
kind: InferenceService
metadata:
  name: llama3-8b
  namespace: llm-serving
  annotations:
    serving.kserve.io/enable-prometheus-scraping: "true"
spec:
  predictor:
    minReplicas: 1
    maxReplicas: 3
    # Why min/maxReplicas: Enables auto-scaling between 1 and 3 instances
    containerConcurrency: 5
    # Why 5: Each replica handles up to 5 concurrent requests
    containers:
    - name: kserve-container
      image: vllm/vllm-openai:latest
      command:
      - python
      - -m
      - vllm.entrypoints.openai.api_server
      args:
      - --model
      - meta-llama/Meta-Llama-3-8B-Instruct
      - --host
      - 0.0.0.0
      - --port
      - "8080"
      - --dtype
      - float16
      - --max-model-len
      - "4096"
      ports:
      - containerPort: 8080
        protocol: TCP
      env:
      - name: HUGGING_FACE_HUB_TOKEN
        valueFrom:
          secretKeyRef:
            name: hf-token
            key: token
      resources:
        requests:
          cpu: "4"
          memory: "16Gi"
          nvidia.com/gpu: "1"
        limits:
          nvidia.com/gpu: "1"
EOF

# Check InferenceService status
kubectl get inferenceservice llama3-8b -n llm-serving
# Wait until READY=True

# Get the KServe endpoint URL
kubectl get inferenceservice llama3-8b -n llm-serving -o jsonpath='{.status.url}'
```

---

## Step 9 — Expose LLM via LoadBalancer / Ingress

### 9.1 — Install NGINX Ingress Controller

```bash
# Install NGINX Ingress Controller via Helm
helm upgrade --install ingress-nginx ingress-nginx/ingress-nginx \
  --namespace ingress-nginx \
  --create-namespace \
  --set controller.hostNetwork=true \
  --set controller.service.type=NodePort \
  --set controller.service.nodePorts.http=80 \
  --set controller.service.nodePorts.https=443
# Why NGINX Ingress: Routes external HTTP/HTTPS traffic to internal K8s services
# Why hostNetwork=true: On single-node K3s, this is simpler than LoadBalancer
# Why NodePort: EC2 doesn't have a cloud load balancer by default

# Wait for ingress controller to be ready
kubectl wait --for=condition=ready pod \
  -l app.kubernetes.io/component=controller \
  -n ingress-nginx \
  --timeout=120s

kubectl get pods -n ingress-nginx
# nginx-ingress-controller pod should be Running
```

### 9.2 — Create Ingress Rule for vLLM

```bash
# Create Ingress to route /v1/ traffic to vLLM service
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: vllm-ingress
  namespace: llm-serving
  annotations:
    nginx.ingress.kubernetes.io/proxy-read-timeout: "300"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "300"
    nginx.ingress.kubernetes.io/proxy-body-size: "50m"
    # Why large timeouts: LLM inference can take 30-60+ seconds for long outputs
spec:
  ingressClassName: nginx
  rules:
  - host: llm.your-domain.com
    # Replace with your actual domain or use EC2 IP
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: vllm-service
            port:
              number: 8000
EOF

# For quick access without a domain, use NodePort directly
kubectl apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: vllm-nodeport
  namespace: llm-serving
spec:
  selector:
    app: vllm
  type: NodePort
  ports:
  - port: 8000
    targetPort: 8000
    nodePort: 30800
    # Port 30800 will be accessible at http://<EC2-IP>:30800
EOF

# Get the NodePort URL
EC2_PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)
echo "LLM API available at: http://${EC2_PUBLIC_IP}:30800"
```

---

## Step 10 — Test Your LLM Endpoint

```bash
# -----------------------------------------------------------------------
# Quick health check
# -----------------------------------------------------------------------
curl http://<EC2-IP>:30800/health
# Expected: {"status":"ok"}

# -----------------------------------------------------------------------
# List available models
# -----------------------------------------------------------------------
curl http://<EC2-IP>:30800/v1/models
# Expected: {"object":"list","data":[{"id":"meta-llama/Meta-Llama-3-8B-Instruct",...}]}

# -----------------------------------------------------------------------
# Chat completion (OpenAI-compatible format)
# -----------------------------------------------------------------------
curl http://<EC2-IP>:30800/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "meta-llama/Meta-Llama-3-8B-Instruct",
    "messages": [
      {"role": "system", "content": "You are a helpful assistant."},
      {"role": "user", "content": "Explain quantum computing in 3 sentences."}
    ],
    "max_tokens": 200,
    "temperature": 0.7,
    "stream": false
  }'

# -----------------------------------------------------------------------
# Streaming completion (tokens streamed as they are generated)
# -----------------------------------------------------------------------
curl http://<EC2-IP>:30800/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "meta-llama/Meta-Llama-3-8B-Instruct",
    "messages": [{"role": "user", "content": "Write a poem about Kubernetes."}],
    "max_tokens": 300,
    "stream": true
  }'
# Why streaming: Improves perceived response time — user sees output immediately

# -----------------------------------------------------------------------
# Text completion (legacy format)
# -----------------------------------------------------------------------
curl http://<EC2-IP>:30800/v1/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "meta-llama/Meta-Llama-3-8B-Instruct",
    "prompt": "The future of AI is",
    "max_tokens": 100
  }'

# -----------------------------------------------------------------------
# Python client test (using OpenAI SDK)
# -----------------------------------------------------------------------
pip install openai

python3 - <<'EOF'
from openai import OpenAI

# Point to your vLLM server instead of OpenAI
client = OpenAI(
    api_key="not-needed",      # vLLM doesn't require auth by default
    base_url="http://<EC2-IP>:30800/v1"
)

response = client.chat.completions.create(
    model="meta-llama/Meta-Llama-3-8B-Instruct",
    messages=[
        {"role": "user", "content": "What is Kubernetes?"}
    ],
    max_tokens=200
)

print(response.choices[0].message.content)
EOF

# -----------------------------------------------------------------------
# Benchmark throughput
# -----------------------------------------------------------------------
# Install vLLM benchmarking tool
pip install vllm

# Run benchmark with 100 requests, 512 input tokens, 512 output tokens
python3 -m vllm.benchmarks.benchmark_serving \
  --backend openai \
  --host <EC2-IP> \
  --port 30800 \
  --endpoint /v1/chat/completions \
  --model meta-llama/Meta-Llama-3-8B-Instruct \
  --num-prompts 100 \
  --input-len 512 \
  --output-len 512
# Output shows: throughput (req/s), tokens/s, latency percentiles (p50, p90, p99)
```

---

## Step 11 — Monitoring & Observability

### 11.1 — Install Prometheus + Grafana

```bash
# Install Prometheus Stack (includes Prometheus, Alertmanager, node-exporter)
helm upgrade --install kube-prometheus-stack \
  prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --create-namespace \
  --set prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false \
  --set grafana.adminPassword=admin123 \
  --set prometheus.service.type=NodePort \
  --set prometheus.service.nodePort=30090 \
  --set grafana.service.type=NodePort \
  --set grafana.service.nodePort=30030
# Why Prometheus: Industry-standard metrics collection for Kubernetes
# Why Grafana: Dashboard visualization for metrics
# Why NodePort: Easy access from EC2 public IP

# Wait for pods to be ready
kubectl wait --for=condition=ready pod \
  -l app=kube-prometheus-stack-grafana \
  -n monitoring \
  --timeout=300s

# Access URLs:
# Prometheus: http://<EC2-IP>:30090
# Grafana: http://<EC2-IP>:30030 (admin/admin123)
```

### 11.2 — Add GPU Metrics (DCGM Exporter)

```bash
# NVIDIA DCGM Exporter collects GPU-specific metrics
# (Already installed as part of GPU Operator)

# Verify DCGM exporter is running
kubectl get pods -n gpu-operator | grep dcgm
# dcgm-exporter-xxxxx pod should be Running

# Create ServiceMonitor to scrape GPU metrics
kubectl apply -f - <<EOF
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: dcgm-exporter
  namespace: monitoring
spec:
  selector:
    matchLabels:
      app: dcgm-exporter
  namespaceSelector:
    matchNames:
    - gpu-operator
  endpoints:
  - port: metrics
    interval: 15s
EOF
# Why DCGM: Provides GPU utilization, temperature, power draw, memory usage metrics
```

### 11.3 — Key Metrics to Monitor

```
GPU Metrics (from DCGM Exporter):
- DCGM_FI_DEV_GPU_UTIL          : GPU utilization % (target: >70% for efficiency)
- DCGM_FI_DEV_MEM_COPY_UTIL     : GPU memory bandwidth utilization
- DCGM_FI_DEV_FB_USED           : GPU VRAM used (in MiB)
- DCGM_FI_DEV_GPU_TEMP          : GPU temperature (alert if >85°C)
- DCGM_FI_DEV_POWER_USAGE       : Power draw (watts)

vLLM Metrics (built-in at /metrics):
- vllm:num_requests_running      : Active inference requests
- vllm:num_requests_waiting      : Queued requests (backpressure)
- vllm:gpu_cache_usage_perc      : KV cache utilization %
- vllm:time_to_first_token_seconds : TTFT latency
- vllm:generation_tokens_total   : Total tokens generated

Kubernetes Metrics (from kube-state-metrics):
- kube_pod_status_phase          : Pod health
- kube_deployment_status_replicas_ready : Replica count
```

### 11.4 — Import Grafana Dashboard

```bash
# Import the vLLM dashboard
# Go to Grafana UI → Dashboards → Import → Enter Dashboard ID

# Recommended Dashboard IDs:
# 12239 — NVIDIA DCGM Exporter Dashboard
# Custom vLLM dashboard JSON available at:
# https://github.com/vllm-project/vllm/blob/main/examples/prometheus_grafana

# Port-forward Grafana locally (alternative to NodePort)
kubectl port-forward -n monitoring svc/kube-prometheus-stack-grafana 3000:80
# Then access at http://localhost:3000
```

---

## Step 12 — Auto-Scaling with KEDA

KEDA (Kubernetes Event-Driven Autoscaling) scales your LLM deployment based on custom metrics like queue length or GPU utilization.

```bash
# Install KEDA
helm repo add kedacore https://kedacore.github.io/charts
helm repo update

helm install keda kedacore/keda \
  --namespace keda \
  --create-namespace
# Why KEDA: Built-in HPA only scales on CPU/memory. KEDA scales on any metric
# (queue length, GPU util, Prometheus metrics, etc.)

# Wait for KEDA to be ready
kubectl wait --for=condition=ready pod \
  -l app=keda-operator \
  -n keda \
  --timeout=120s

# Create ScaledObject to auto-scale vLLM based on waiting requests
kubectl apply -f - <<EOF
apiVersion: keda.sh/v1alpha1
kind: ScaledObject
metadata:
  name: vllm-scaler
  namespace: llm-serving
spec:
  scaleTargetRef:
    name: vllm-llama3-8b
  minReplicaCount: 1
  maxReplicaCount: 3
  # Why maxReplicas=3: More replicas = more GPU cost; limit based on budget
  cooldownPeriod: 300
  # Why 300s: Don't scale down too fast; model loading takes time
  triggers:
  - type: prometheus
    metadata:
      serverAddress: http://kube-prometheus-stack-prometheus.monitoring.svc.cluster.local:9090
      metricName: vllm_num_requests_waiting
      query: sum(vllm:num_requests_waiting)
      threshold: "5"
      # Why threshold 5: Scale up when 5+ requests are waiting in queue
EOF
# Note: Scaling GPU workloads is expensive; set conservative thresholds
```

---

## Security Best Practices

```bash
# -----------------------------------------------------------------------
# 1. Add API Key Authentication to vLLM
# -----------------------------------------------------------------------
# Generate a secure API key
API_KEY=$(openssl rand -hex 32)
echo "Generated API Key: $API_KEY"

# Store as Kubernetes secret
kubectl create secret generic vllm-api-key \
  --from-literal=api-key=$API_KEY \
  --namespace llm-serving

# Add to vLLM deployment args:
# - --api-key
# - $(VLLM_API_KEY)
# Add env var in deployment:
# - name: VLLM_API_KEY
#   valueFrom:
#     secretKeyRef:
#       name: vllm-api-key
#       key: api-key

# Now clients must include: Authorization: Bearer <api-key>

# -----------------------------------------------------------------------
# 2. Enable HTTPS with TLS
# -----------------------------------------------------------------------
# Create self-signed certificate secret
kubectl create secret tls llm-tls-secret \
  --cert=path/to/tls.crt \
  --key=path/to/tls.key \
  --namespace llm-serving

# Or use Let's Encrypt with cert-manager (requires a real domain)
kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: your-email@example.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: nginx
EOF

# -----------------------------------------------------------------------
# 3. Restrict AWS Security Group
# -----------------------------------------------------------------------
# Only allow your IP for SSH (already done in Step 1)
# Consider using AWS Systems Manager Session Manager instead of SSH:
aws ssm start-session --target <instance-id>
# Why: Eliminates need for open SSH port; uses AWS IAM for auth

# -----------------------------------------------------------------------
# 4. Enable Kubernetes RBAC
# -----------------------------------------------------------------------
# Create a read-only service account for monitoring
kubectl create serviceaccount monitoring-reader -n llm-serving
kubectl create clusterrolebinding monitoring-reader \
  --clusterrole=view \
  --serviceaccount=llm-serving:monitoring-reader
# Why: Least privilege — monitoring tools only need read access

# -----------------------------------------------------------------------
# 5. Use AWS Spot Instances with interruption handling
# -----------------------------------------------------------------------
# Use Spot for non-critical workloads (up to 70% cheaper)
# Add interruption handler to gracefully drain on spot interruption:
kubectl apply -f https://github.com/aws/aws-node-termination-handler/releases/latest/download/all-resources.yaml
```

---

## Troubleshooting

### Common Issues and Solutions

```bash
# -----------------------------------------------------------------------
# Issue 1: Pod stuck in "Pending" state
# -----------------------------------------------------------------------
kubectl describe pod <pod-name> -n llm-serving
# Look for "Events" section at the bottom
# Common cause: "0/1 nodes are available: 1 Insufficient nvidia.com/gpu"
# Fix: Verify GPU operator is running
kubectl get pods -n gpu-operator
# Fix: Check node has GPU resource
kubectl describe node | grep nvidia.com/gpu

# -----------------------------------------------------------------------
# Issue 2: OOM (Out of Memory) on GPU
# -----------------------------------------------------------------------
# Symptom: Pod crashes with "RuntimeError: CUDA out of memory"
# Fix: Reduce --max-model-len or --gpu-memory-utilization
# Fix: Use a quantized model (GPTQ/AWQ)
# Fix: Upgrade to an instance with more VRAM

# -----------------------------------------------------------------------
# Issue 3: Model download fails
# -----------------------------------------------------------------------
kubectl logs deployment/vllm-llama3-8b -n llm-serving | grep -i error
# Common causes:
# - Invalid HuggingFace token
# - Model requires license acceptance on HF website
# - Network connectivity issues
# Fix: Verify HF token
kubectl get secret hf-token -n llm-serving -o jsonpath='{.data.token}' | base64 -d

# -----------------------------------------------------------------------
# Issue 4: Slow inference / high latency
# -----------------------------------------------------------------------
# Check GPU utilization during inference
watch -n 1 nvidia-smi
# If GPU util is <50%: You may have CPU bottleneck in tokenization
# If GPU util is >90%: GPU is busy — add more replicas or upgrade instance

# Check vLLM metrics
curl http://<EC2-IP>:30800/metrics | grep vllm
# Check: vllm:num_requests_waiting (high = overloaded)
# Check: vllm:gpu_cache_usage_perc (high = KV cache pressure, reduce max_model_len)

# -----------------------------------------------------------------------
# Issue 5: K3s node not showing GPU
# -----------------------------------------------------------------------
kubectl describe node | grep -i gpu
# If no GPU shown, restart GPU device plugin
kubectl rollout restart daemonset/nvidia-device-plugin-daemonset -n gpu-operator

# -----------------------------------------------------------------------
# Issue 6: containerd not finding NVIDIA runtime
# -----------------------------------------------------------------------
sudo cat /etc/containerd/config.toml | grep nvidia
# If empty, re-run:
sudo nvidia-ctk runtime configure --runtime=containerd
sudo systemctl restart containerd
sudo systemctl restart k3s

# -----------------------------------------------------------------------
# Useful diagnostic commands
# -----------------------------------------------------------------------
# Check all pods across all namespaces
kubectl get pods -A

# Check pod logs
kubectl logs -f deployment/vllm-llama3-8b -n llm-serving

# Check resource usage
kubectl top pods -n llm-serving

# Check GPU usage from inside the pod
kubectl exec -it deployment/vllm-llama3-8b -n llm-serving -- nvidia-smi

# Check events for namespace
kubectl get events -n llm-serving --sort-by='.lastTimestamp'
```

---

## Cost Optimization Tips

| Strategy | Savings | Command/How-To |
|---|---|---|
| **Use Spot Instances** | Up to 70% | Launch with `--instance-market-options '{"MarketType":"spot"}'` |
| **Schedule shutdown** | Up to 60% | Stop instance when not in use: `aws ec2 stop-instances --instance-ids <id>` |
| **Use quantized models** | Smaller instance | Use GPTQ/AWQ models to fit 13B on 16GB VRAM |
| **Scale to zero** | 100% when idle | Use KServe with minReplicas=0 |
| **Reserved Instances** | Up to 40% | Buy 1yr/3yr reserved capacity for stable workloads |
| **Savings Plans** | Up to 30% | AWS Compute Savings Plans for flexible EC2 |
| **Right-size instance** | Varies | Profile VRAM usage; don't over-provision |

```bash
# Create a stop/start script to save money when not in use
cat > ~/manage-llm.sh <<'EOF'
#!/bin/bash
INSTANCE_ID="i-xxxxxxxxxxxxxxxxx"  # Your instance ID
ACTION=$1

case $ACTION in
  start)
    aws ec2 start-instances --instance-ids $INSTANCE_ID
    echo "Waiting for instance to start..."
    aws ec2 wait instance-running --instance-ids $INSTANCE_ID
    PUBLIC_IP=$(aws ec2 describe-instances --instance-ids $INSTANCE_ID \
      --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
    echo "Instance running at: $PUBLIC_IP"
    ;;
  stop)
    aws ec2 stop-instances --instance-ids $INSTANCE_ID
    echo "Instance stopped. Cost saving active."
    ;;
  status)
    aws ec2 describe-instances --instance-ids $INSTANCE_ID \
      --query 'Reservations[0].Instances[0].State.Name' --output text
    ;;
esac
EOF
chmod +x ~/manage-llm.sh

# Usage:
# ~/manage-llm.sh start   → Start the instance
# ~/manage-llm.sh stop    → Stop the instance
# ~/manage-llm.sh status  → Check status
```

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────────────────┐
│                    QUICK REFERENCE                           │
├──────────────────────────────┬──────────────────────────────┤
│  Check GPU status            │  nvidia-smi                  │
│  Check K3s status            │  kubectl get nodes           │
│  Check pods                  │  kubectl get pods -A         │
│  View vLLM logs              │  kubectl logs -f deploy/vllm │
│                              │    -n llm-serving            │
│  Test API                    │  curl http://IP:30800/health │
│  GPU inside pod              │  kubectl exec -it deploy/    │
│                              │    vllm -n llm-serving       │
│                              │    -- nvidia-smi             │
│  Restart vLLM                │  kubectl rollout restart     │
│                              │    deploy/vllm-llama3-8b     │
│                              │    -n llm-serving            │
│  Check resource usage        │  kubectl top pods -A         │
│  Check GPU operator          │  kubectl get pods            │
│                              │    -n gpu-operator           │
│  View GPU metrics            │  curl http://IP:30800/metrics│
├──────────────────────────────┴──────────────────────────────┤
│  LLM API Base URL: http://<EC2-IP>:30800                    │
│  Grafana URL:      http://<EC2-IP>:30030                    │
│  Prometheus URL:   http://<EC2-IP>:30090                    │
└─────────────────────────────────────────────────────────────┘
```

---

## Additional Resources

- [vLLM Documentation](https://docs.vllm.ai/)
- [K3s Documentation](https://docs.k3s.io/)
- [NVIDIA GPU Operator](https://docs.nvidia.com/datacenter/cloud-native/gpu-operator/latest/index.html)
- [KServe Documentation](https://kserve.github.io/website/)
- [HuggingFace Model Hub](https://huggingface.co/models?pipeline_tag=text-generation)
- [AWS EC2 GPU Instances](https://aws.amazon.com/ec2/instance-types/#Accelerated_Computing)
- [KEDA Documentation](https://keda.sh/docs/)

---

*Last updated: June 2026 | Author: Hamza*

---

## Kubernetes Components Deep-Dive

Every Kubernetes component used in this LLM deployment stack, what each one does, how they interact, and what breaks when absent.

---

### 🧠 Control Plane Components

#### 1. `kube-apiserver` — The Gatekeeper

```
┌────────────────────────────────────────────────────────────┐
│                    kube-apiserver                          │
│                                                            │
│  ┌──────────┐  ┌──────────────┐  ┌─────────────────────┐  │
│  │ REST API │  │ AuthN / AuthZ│  │ Admission Controllers│  │
│  └──────────┘  └──────────────┘  └─────────────────────┘  │
│         │              │                    │              │
│         └──────────────┴────────────────────┘              │
│                        │                                   │
│              ┌─────────▼──────────┐                        │
│              │   etcd (storage)   │                        │
│              └────────────────────┘                        │
└────────────────────────────────────────────────────────────┘
```

**Role in LLM deployment:** Every `kubectl` command, Helm install, and operator reconciliation loop calls the API server. It is the single entry point to the cluster.

**In K3s:** The API server is embedded inside the single `k3s server` binary (not a separate process).

| Sub-component | What it does |
|---|---|
| **REST endpoint** | Exposes HTTP REST API (versioned: `/api/v1`, `/apis/apps/v1`, etc.) |
| **Authentication** | Validates identity: X.509 certs, bearer tokens, OIDC, service accounts |
| **Authorization (RBAC)** | Decides what the authenticated entity can do (`get`, `create`, `delete`) |
| **Admission Controllers** | Mutate/validate resources before persisting (e.g., ResourceQuota, PodSecurity, GPU limits) |
| **etcd writer** | Persists approved resource specs to etcd |

**What breaks without it:** Nothing works. K3s will not accept any command.

---

#### 2. `etcd` — The Brain's Memory

**Role in LLM deployment:** Stores the desired state of every Kubernetes object — your vLLM Deployment spec, Service, PVC, Secret (HuggingFace token), ConfigMap, and node registration.

**In K3s:** K3s replaces etcd with **SQLite** (single node) or **embedded etcd** (HA mode). This is one reason K3s is so lightweight.

```
etcd stores:
  /registry/deployments/llm-serving/vllm-llama3-8b    <- Deployment spec
  /registry/pods/llm-serving/vllm-llama3-8b-xxx       <- Pod spec
  /registry/services/llm-serving/vllm-service          <- Service spec
  /registry/persistentvolumeclaims/llm-serving/model-cache-pvc
  /registry/secrets/llm-serving/hf-token              <- Encrypted HF token
  /registry/nodes/ip-xxx-xxx-xxx-xxx                  <- Node registration
```

**What breaks without it:** The API server cannot read or write state. The entire cluster is blind.

**Common etcd error in production:**
```
Error: etcdserver: request timed out
Fix: Check disk I/O — etcd is very sensitive to slow EBS volumes
     Use gp3 with provisioned IOPS for production etcd
```

---

#### 3. `kube-scheduler` — The Placement Engine

**Role in LLM deployment:** When you create the vLLM Pod, the scheduler picks which node to run it on. It **must** find a node with `nvidia.com/gpu: 1` available.

**In K3s:** Embedded in the same binary.

**Scheduler Decision Flow for GPU Pod:**
```
1. Filtering phase (eliminates ineligible nodes):
   - Node has enough CPU? (>=4 cores)       -> PASS
   - Node has enough Memory? (>=16Gi)       -> PASS
   - Node has nvidia.com/gpu >= 1?          -> PASS (only if GPU Operator running)
   - Node has taint? Check Pod tolerations  -> PASS (we added toleration)
   - PVC available on node?                 -> PASS (local-path is node-local)

2. Scoring phase (ranks eligible nodes):
   - Least requested resources    -> score
   - Node affinity rules          -> score
   - Spread/topology rules        -> score

3. Binding:
   - Scheduler writes nodeName into Pod spec in etcd
   - kubelet on selected node watches etcd and picks up the Pod
```

**What breaks without it:** Pods stay in `Pending` state forever with reason `Unschedulable`.

**Real production error:**
```
Events:
  Warning  FailedScheduling  0/1 nodes are available: 1 Insufficient nvidia.com/gpu

Cause: GPU device plugin not running — nvidia.com/gpu resource not advertised
Fix:
  kubectl get pods -n gpu-operator
  kubectl rollout restart daemonset/nvidia-device-plugin-daemonset -n gpu-operator
```

---

#### 4. `kube-controller-manager` — The Reconciliation Engine

**Role in LLM deployment:** Ensures that what *is* running matches what *should* be running. If your vLLM pod crashes, the ReplicaSet controller detects the divergence and creates a replacement pod.

**In K3s:** Embedded in the same binary.

**Controllers active in this deployment:**

| Controller | What it watches | What it does |
|---|---|---|
| **Deployment Controller** | Deployment objects | Creates/updates ReplicaSets |
| **ReplicaSet Controller** | ReplicaSet objects | Ensures correct number of Pods |
| **Node Controller** | Node objects | Marks nodes NotReady if they stop heartbeating |
| **PersistentVolume Controller** | PVC objects | Binds PVCs to available PVs |
| **ServiceAccount Controller** | Namespaces | Creates default service accounts |
| **Endpoint Controller** | Services + Pods | Updates endpoint slices for Service routing |

**Real scenario:** vLLM pod crashes due to OOM. Controller manager detects `currentReplicas=0 != desiredReplicas=1`. It creates a new Pod spec and sends it to the API server → scheduler assigns node → kubelet starts container.

---

#### 5. `kubelet` — The Node Agent

**Role in LLM deployment:** The most important component on each node. It:
1. Watches the API server for pods assigned to its node
2. Instructs the container runtime (containerd) to pull images and start containers
3. Mounts volumes (model-cache PVC, /dev/shm)
4. Reports pod status back to API server
5. Runs liveness/readiness probes (the `/health` endpoint checks)

**In K3s:** The kubelet is embedded inside the `k3s agent` process.

```bash
# Watch kubelet logs in real-time (very useful for debugging)
sudo journalctl -u k3s -f | grep -E "kubelet|pod|container"

# Common kubelet log messages during LLM pod startup:
# "Pulling image vllm/vllm-openai:latest"      <- Image pull started
# "Successfully pulled image"                   <- Image cached
# "Created container vllm"                      <- Container created
# "Started container vllm"                      <- Container started
# "Readiness probe failed"                      <- Model still loading
# "Readiness probe succeeded"                   <- Model ready!
```

---

#### 6. `kube-proxy` — The Traffic Router

**Role in LLM deployment:** Maintains iptables/IPVS rules on each node so that the `vllm-service` ClusterIP actually routes traffic to the correct pod IP.

**In K3s:** K3s replaces kube-proxy with **Flannel CNI** and its own iptables rules via `k3s-iptables`.

```bash
# See the iptables rules K3s creates for your Service
sudo iptables -t nat -L KUBE-SERVICES | grep vllm
# Output shows: Chain redirecting ClusterIP:8000 -> Pod IP:8000

# Check kube-proxy replacement in K3s
kubectl get pods -n kube-system | grep kube-proxy
# In K3s, you won't find a kube-proxy pod -- handled via flannel/iptables
```

---

### 🔧 Node-Level Components

#### 7. `containerd` — The Container Runtime

**Role in LLM deployment:** The actual engine that:
- Pulls `vllm/vllm-openai:latest` from Docker Hub
- Creates the container namespace and cgroups
- Mounts the NVIDIA GPU device into the container (via NVIDIA Container Runtime)
- Starts the vLLM Python process

```bash
# Check containerd status
sudo systemctl status containerd

# View container runtime info
kubectl get nodes -o wide
# CONTAINER-RUNTIME column shows: containerd://1.7.x

# List running containers via containerd (low-level)
sudo crictl ps | grep vllm
# Output: container ID, image, state, name

# Pull an image manually via containerd
sudo crictl pull vllm/vllm-openai:latest

# View containerd logs
sudo journalctl -u containerd -f
```

**NVIDIA hook in containerd:**
```
containerd -> calls nvidia-container-runtime-hook -> injects GPU devices
  -> /dev/nvidia0 mounted inside container
  -> /dev/nvidiactl mounted inside container
  -> LD_LIBRARY_PATH set for CUDA libraries
```

---

#### 8. NVIDIA Device Plugin — The GPU Advertiser

**Role in LLM deployment:** Runs as a DaemonSet on every GPU node. It:
1. Discovers all NVIDIA GPUs on the host (`nvidia-smi -L`)
2. Registers them with the kubelet as extended resources (`nvidia.com/gpu: 1`)
3. When a pod requests `nvidia.com/gpu: 1`, the plugin allocates that GPU
4. Tells containerd which GPU device files to inject into the container

```bash
# Check device plugin is running
kubectl get daemonset -n gpu-operator
# nvidia-device-plugin-daemonset should be DESIRED=1, READY=1

# Verify GPU is allocated to a pod
kubectl describe pod <vllm-pod-name> -n llm-serving | grep -A 5 "Limits:"
# Should show: nvidia.com/gpu: 1

# Check device plugin logs
kubectl logs -n gpu-operator -l app=nvidia-device-plugin-daemonset
# Look for: "Starting NVIDIA Device Plugin"
# Look for: "Retrieved GPU [0] model Tesla T4"
```

---

#### 9. DCGM Exporter — The GPU Metrics Collector

**Role in LLM deployment:** Runs as a DaemonSet. Queries NVIDIA DCGM (Data Center GPU Manager) for hardware-level metrics every 15 seconds and exposes them at `:9400/metrics` in Prometheus format.

```bash
# Manually scrape GPU metrics from DCGM exporter pod
DCGM_POD=$(kubectl get pods -n gpu-operator -l app=dcgm-exporter -o name | head -1)
kubectl exec -n gpu-operator $DCGM_POD -- curl localhost:9400/metrics \
  | grep -E "DCGM_FI_DEV_GPU_UTIL|DCGM_FI_DEV_FB_USED"
# Output: DCGM_FI_DEV_GPU_UTIL{gpu="0",...} 87.3
#         DCGM_FI_DEV_FB_USED{gpu="0",...} 14256
```

---

#### 10. Flannel CNI — The Network Fabric

**Role in LLM deployment:** Creates the overlay network so that:
- The vLLM pod gets its own IP (e.g., `10.42.0.15`)
- The Prometheus pod can reach the vLLM pod IP for scraping
- The ingress controller can reach the vLLM service ClusterIP

**In K3s:** Flannel is built-in (uses VXLAN by default).

```bash
# Check pod network assignment
kubectl get pods -n llm-serving -o wide
# Shows: Pod IP from 10.42.0.0/16 range (K3s default)

# Check flannel interface on the node
ip addr show flannel.1
# Shows the VXLAN tunnel interface

# Test pod-to-pod connectivity
kubectl exec -it <prometheus-pod> -n monitoring -- \
  curl http://10.42.0.15:8000/health
```

---

#### 11. `local-path-provisioner` — The Storage Engine

**Role in LLM deployment:** When you create the `model-cache-pvc` PersistentVolumeClaim, this provisioner automatically creates a directory on the host at `/var/lib/rancher/k3s/storage/` and binds the PVC to it.

```bash
# Check local-path-provisioner
kubectl get pods -n kube-system | grep local-path
# local-path-provisioner pod should be Running

# Check where model weights are stored on disk
kubectl describe pvc model-cache-pvc -n llm-serving
# Shows: Source: /var/lib/rancher/k3s/storage/pvc-xxxxxxx

# Check actual model files on host
ls -lh /var/lib/rancher/k3s/storage/pvc-*/
# Shows: huggingface/ directory with model shards

# WARNING: If you delete the PVC, all downloaded model files are deleted!
# Always back up model weights to S3 before deleting PVCs:
aws s3 sync /var/lib/rancher/k3s/storage/pvc-xxx/ s3://your-bucket/model-cache/
```

---

#### 12. CoreDNS — The Internal DNS

**Role in LLM deployment:** Allows pods to resolve service names. When the Prometheus pod wants to scrape vLLM, it uses the DNS name `vllm-service.llm-serving.svc.cluster.local` instead of a hardcoded IP.

```bash
# Test DNS resolution from inside a pod
kubectl exec -it <any-pod> -n llm-serving -- nslookup vllm-service
# Output: Server: 10.43.0.10 (CoreDNS ClusterIP)
#         vllm-service.llm-serving.svc.cluster.local -> 10.43.x.x

# Check CoreDNS is running
kubectl get pods -n kube-system | grep coredns

# Real production error -- DNS not resolving:
# Error: dial tcp: lookup vllm-service: no such host
kubectl rollout restart deployment/coredns -n kube-system
```

---

#### 13. Nginx Ingress Controller — The External Traffic Gateway

**Role in LLM deployment:** Runs as a Pod and watches for `Ingress` resources. When you create `vllm-ingress`, Nginx:
1. Reads the Ingress rules (host: `llm.your-domain.com` → `vllm-service:8000`)
2. Generates an `nginx.conf` with upstream blocks
3. Reloads Nginx without downtime
4. Terminates TLS (if configured)
5. Forwards HTTP requests to vLLM pods

```bash
# Check ingress controller pod
kubectl get pods -n ingress-nginx

# Check what nginx.conf was generated
NGINX_POD=$(kubectl get pods -n ingress-nginx -l app.kubernetes.io/component=controller -o name | head -1)
kubectl exec -n ingress-nginx $NGINX_POD -- cat /etc/nginx/nginx.conf | grep -A 10 "upstream"

# Check ingress rules
kubectl get ingress -n llm-serving
kubectl describe ingress vllm-ingress -n llm-serving
```

---

#### 14. Prometheus — The Metrics Store

**Role in LLM deployment:** Scrapes metrics from:
- vLLM pod (`/metrics` endpoint) — request counts, token throughput, latency
- DCGM Exporter — GPU utilization, VRAM usage, temperature
- Node Exporter — CPU, RAM, disk I/O
- kube-state-metrics — Pod states, deployment health

```bash
# Check what targets Prometheus is scraping
kubectl port-forward -n monitoring svc/kube-prometheus-stack-prometheus 9090:9090 &
# Open http://localhost:9090/targets
# All targets should be State=UP

# Query vLLM metrics directly
curl 'http://localhost:9090/api/v1/query?query=vllm:num_requests_running'
curl 'http://localhost:9090/api/v1/query?query=DCGM_FI_DEV_GPU_UTIL'
```

---

#### 15. KEDA — The Event-Driven Scaler

**Role in LLM deployment:** Watches Prometheus for `vllm:num_requests_waiting` metric. When it exceeds the threshold (5), it patches the Deployment replicas count upward. When load drops, it scales back down after the cooldown period.

```bash
# Watch KEDA scaling decisions in real time
kubectl get scaledobject vllm-scaler -n llm-serving -w

# See HPA that KEDA manages
kubectl get hpa -n llm-serving
# Shows: MINPODS=1, MAXPODS=3, REPLICAS=<current>

# Check KEDA operator logs
kubectl logs -n keda -l app=keda-operator -f
```

---

## kubectl → API Server → Components: Full Call Flow

This section shows exactly what happens at the API/component level for each `kubectl` command, including the precise HTTP verbs and paths used.

---

### 🔵 Flow 1: `kubectl create namespace llm-serving`

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    kubectl create namespace llm-serving                  │
└─────────────────────────────────────────────────────────────────────────┘
         │
         │ 1. kubectl reads ~/.kube/config
         │    - Finds: server = https://127.0.0.1:6443
         │    - Finds: client cert + key for authentication
         ▼
┌─────────────────────────────────────┐
│         kube-apiserver              │
│  POST /api/v1/namespaces            │  <- HTTP call
│                                     │
│  Body:                              │
│  {                                  │
│    "apiVersion": "v1",              │
│    "kind": "Namespace",             │
│    "metadata": {                    │
│      "name": "llm-serving"          │
│    }                                │
│  }                                  │
│                                     │
│  2. Authentication:                 │
│     Validates client certificate    │
│     -> identity: kubernetes-admin   │
│                                     │
│  3. Authorization (RBAC):           │
│     Can kubernetes-admin CREATE     │
│     namespaces? -> YES (cluster-admin│
│     ClusterRoleBinding)             │
│                                     │
│  4. Admission Controllers:          │
│     - NamespaceLifecycle: OK        │
│     - ResourceQuota: N/A            │
│                                     │
│  5. Writes to etcd:                 │
│     /registry/namespaces/llm-serving│
│                                     │
│  6. Returns HTTP 201 Created        │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│  controller-manager                 │
│  (ServiceAccount Controller)        │
│                                     │
│  7. Watches for new namespaces      │
│  8. Auto-creates "default"          │
│     ServiceAccount in llm-serving   │
└─────────────────────────────────────┘
         │
         ▼
kubectl output: "namespace/llm-serving created"

=== HTTP Calls Made ===
POST   https://127.0.0.1:6443/api/v1/namespaces
GET    https://127.0.0.1:6443/api/v1/namespaces/llm-serving  (verify)
```

---

### 🟢 Flow 2: `kubectl apply -f vllm-deployment.yaml`

This is the most complex flow — creating a Deployment that spawns a GPU Pod.

```
┌─────────────────────────────────────────────────────────────────────────┐
│              kubectl apply -f vllm-deployment.yaml                       │
└─────────────────────────────────────────────────────────────────────────┘
         │
         │ kubectl reads YAML, converts to JSON, computes diff
         │ (apply = server-side diff of desired vs current state)
         ▼
╔═══════════════════════════════════════════════════════════════╗
║                      kube-apiserver                           ║
║  PATCH /apis/apps/v1/namespaces/llm-serving/deployments       ║
║  (or POST if resource does not exist)                         ║
║                                                               ║
║  1. AuthN: Validate client cert -> kubernetes-admin           ║
║  2. AuthZ: RBAC check -> can create Deployments? YES          ║
║  3. Admission: MutatingWebhookConfiguration                   ║
║     - Injects default resource limits if not set              ║
║     - Sets imagePullPolicy defaults                           ║
║     - gpu-operator webhook validates GPU request format       ║
║  4. ValidatingWebhookConfiguration                            ║
║     - Rejects if schema is invalid                            ║
║     - Rejects if resource limits < requests                   ║
║  5. Persist to etcd                                           ║
║     /registry/deployments/llm-serving/vllm-llama3-8b         ║
║  6. Return 200 OK / 201 Created                               ║
╚═══════════════════════════════════════════════════════════════╝
         │
         │ (API server publishes event via Watch API)
         ▼
╔═══════════════════════════════════════════════════════════════╗
║               Deployment Controller                           ║
║         (inside kube-controller-manager)                      ║
║                                                               ║
║  7. GET /apis/apps/v1/namespaces/llm-serving/deployments      ║
║     Sees new Deployment: desired replicas=1, current=0        ║
║                                                               ║
║  8. POST /apis/apps/v1/namespaces/llm-serving/replicasets     ║
║     Creates ReplicaSet (owns the Pods)                        ║
╚═══════════════════════════════════════════════════════════════╝
         │
         ▼
╔═══════════════════════════════════════════════════════════════╗
║               ReplicaSet Controller                           ║
║         (inside kube-controller-manager)                      ║
║                                                               ║
║  9. Sees ReplicaSet: desired=1, current=0                     ║
║  10. POST /api/v1/namespaces/llm-serving/pods                 ║
║      Creates Pod spec in etcd                                 ║
║      Pod status: Pending (no node assigned yet)               ║
╚═══════════════════════════════════════════════════════════════╝
         │
         ▼
╔═══════════════════════════════════════════════════════════════╗
║                   kube-scheduler                              ║
║                                                               ║
║  11. Watches for Pods with spec.nodeName=""                   ║
║  12. Filtering: which nodes have nvidia.com/gpu >= 1?         ║
║      Checks extended resource reported by device plugin       ║
║  13. Scoring: ranks nodes by available resources              ║
║  14. PATCH /api/v1/namespaces/llm-serving/pods/.../binding    ║
║      Sets spec.nodeName="ip-10-0-1-42"                       ║
╚═══════════════════════════════════════════════════════════════╝
         │
         ▼
╔═══════════════════════════════════════════════════════════════╗
║               kubelet (on selected node)                      ║
║                                                               ║
║  15. Watches API server: GET /api/v1/pods?fieldSelector=      ║
║      spec.nodeName=ip-10-0-1-42                               ║
║  16. Sees the new Pod assigned to this node                   ║
║  17. Calls containerd gRPC API:                               ║
║      -> PullImage("vllm/vllm-openai:latest")                  ║
║      -> CreateContainer(...)                                  ║
║      -> StartContainer(...)                                   ║
║  18. Mounts volumes:                                          ║
║      -> PVC: /rancher/k3s/storage/pvc-xxx -> /model-cache     ║
║      -> emptyDir(Memory): tmpfs -> /dev/shm                   ║
║  19. NVIDIA device plugin allocates GPU:                      ║
║      -> /dev/nvidia0 injected into container                  ║
║      -> CUDA libraries bind-mounted                           ║
║  20. Container starts vLLM process:                           ║
║      python -m vllm.entrypoints.openai.api_server             ║
║        --model meta-llama/Meta-Llama-3-8B-Instruct            ║
║  21. vLLM downloads model from HuggingFace (~5-15 min)        ║
║  22. Kubelet runs readiness probe every 10s:                  ║
║      GET http://pod-ip:8000/health                            ║
║      -> 503 (loading)... 503... 200 OK (model ready!)         ║
║  23. kubelet PATCH /api/v1/pods/vllm-xxx/status               ║
║      Sets conditions.Ready=True                               ║
╚═══════════════════════════════════════════════════════════════╝
         │
         ▼
╔═══════════════════════════════════════════════════════════════╗
║            Endpoint Controller (controller-manager)           ║
║                                                               ║
║  24. Detects Pod is Ready and matches vllm-service selector   ║
║  25. PATCH /api/v1/namespaces/llm-serving/endpoints/          ║
║         vllm-service                                          ║
║      Adds pod-ip:8000 to endpoints list                       ║
╚═══════════════════════════════════════════════════════════════╝
         │
         ▼
╔═══════════════════════════════════════════════════════════════╗
║                 kube-proxy / Flannel                          ║
║                                                               ║
║  26. Watches EndpointSlices for changes                       ║
║  27. Updates iptables rules on host:                          ║
║      ClusterIP:8000 -> DNAT -> pod-ip:8000                    ║
╚═══════════════════════════════════════════════════════════════╝
         │
         ▼
kubectl output: "deployment.apps/vllm-llama3-8b created"

=== Total API Calls made by this ONE kubectl apply ===
PATCH  /apis/apps/v1/namespaces/llm-serving/deployments/vllm-llama3-8b
POST   /apis/apps/v1/namespaces/llm-serving/replicasets
POST   /api/v1/namespaces/llm-serving/pods
PATCH  /api/v1/namespaces/llm-serving/pods/{name}/binding
PATCH  /api/v1/namespaces/llm-serving/pods/{name}/status  (many times)
PATCH  /api/v1/namespaces/llm-serving/endpoints/vllm-service
```

---

### 🟡 Flow 3: `kubectl get pods -n llm-serving`

```
kubectl get pods -n llm-serving
     │
     │ GET /api/v1/namespaces/llm-serving/pods
     ▼
kube-apiserver
     │
     ├─ Reads from etcd: /registry/pods/llm-serving/*
     │  (or from API server cache for performance)
     │
     └─ Returns list of Pod objects -> kubectl formats as table

=== What each COLUMN means ===
NAME      -> pod.metadata.name
READY     -> sum of ready containers / total containers
              (from pod.status.containerStatuses[].ready)
STATUS    -> pod.status.phase (Pending/Running/Succeeded/Failed)
RESTARTS  -> sum of pod.status.containerStatuses[].restartCount
AGE       -> now() - pod.metadata.creationTimestamp

=== API Call ===
GET https://127.0.0.1:6443/api/v1/namespaces/llm-serving/pods
Response: PodList JSON object
```

---

### 🔴 Flow 4: `kubectl logs -f deployment/vllm-llama3-8b -n llm-serving`

```
kubectl logs -f deployment/vllm-llama3-8b -n llm-serving
     │
     │ Step 1: Resolve deployment -> pod
     │ GET /apis/apps/v1/namespaces/llm-serving/deployments/vllm-llama3-8b
     │ -> finds replicaset name
     │ GET /apis/apps/v1/namespaces/llm-serving/replicasets/{name}
     │ -> finds pod selector labels
     │ GET /api/v1/namespaces/llm-serving/pods?labelSelector=app=vllm
     │ -> gets pod name: vllm-llama3-8b-abc123
     │
     │ Step 2: Stream logs
     │ GET /api/v1/namespaces/llm-serving/pods/vllm-llama3-8b-abc123/log?follow=true
     │   |
     │ kube-apiserver proxies request to kubelet:
     │ GET https://node-ip:10250/containerLogs/llm-serving/vllm-xxx/vllm?follow=true
     │   |
     │ kubelet reads from containerd:
     │ stdout of PID 1 (vllm python process)
     │   |
     │ Streamed back to kubectl terminal
     ▼
Output: Real-time vLLM startup logs
```

---

### 🟣 Flow 5: `kubectl exec -it pod/vllm-xxx -- nvidia-smi`

```
kubectl exec -it pod/vllm-xxx -n llm-serving -- nvidia-smi
     │
     │ POST /api/v1/namespaces/llm-serving/pods/vllm-xxx/exec
     │ Query params: command=nvidia-smi, stdin=true, stdout=true, tty=true
     ▼
kube-apiserver
     │
     │ Upgrades HTTP connection to WebSocket (SPDY protocol)
     │ Proxies WebSocket to kubelet:
     │ POST https://node-ip:10250/exec/llm-serving/vllm-xxx/vllm
     ▼
kubelet
     │
     │ Calls containerd exec API
     │ -> creates new process in existing container namespace
     │ -> nvidia-smi has access to /dev/nvidia0 (same as container)
     ▼
nvidia-smi output streams back through:
kubelet -> kube-apiserver (WebSocket) -> kubectl -> your terminal
```

---

### 🌐 Complete Kubernetes Component Mesh Diagram

```
╔══════════════════════════════════════════════════════════════════════════╗
║                         AWS EC2 GPU NODE                                 ║
║                                                                          ║
║  ┌─────────────────────────────────────────────────────────────────┐    ║
║  │                    CONTROL PLANE (K3s binary)                    │    ║
║  │                                                                  │    ║
║  │  ┌───────────────┐   ┌────────────────┐   ┌──────────────────┐  │    ║
║  │  │ kube-apiserver│<──┤    etcd/SQLite │   │ controller-mgr   │  │    ║
║  │  │ :6443 (HTTPS) │──>│  (state store) │   │ (reconcile loops)│  │    ║
║  │  └───────┬───────┘   └────────────────┘   └─────────┬────────┘  │    ║
║  │          │                                            │           │    ║
║  │          │<──────────── watch/notify ────────────────┘           │    ║
║  │          │                                                        │    ║
║  │  ┌───────▼───────┐   ┌────────────────────────────────────────┐  │    ║
║  │  │  kube-scheduler│  │  kube-proxy / Flannel CNI              │  │    ║
║  │  │ (place pods)  │  │  (iptables rules for Service routing)   │  │    ║
║  │  └───────────────┘  └────────────────────────────────────────┘  │    ║
║  └─────────────────────────────────────────────────────────────────┘    ║
║                                                                          ║
║  ┌─────────────────────────────────────────────────────────────────┐    ║
║  │                      NODE COMPONENTS                             │    ║
║  │                                                                  │    ║
║  │  ┌─────────┐   gRPC   ┌────────────┐  OCI spec  ┌───────────┐  │    ║
║  │  │ kubelet │─────────>│ containerd │───────────>│ container │  │    ║
║  │  │ :10250  │          │ runtime    │             │  vLLM     │  │    ║
║  │  └─────────┘          └────────────┘             └─────┬─────┘  │    ║
║  │       ^                      │                         │        │    ║
║  │       │               nvidia-container-runtime-hook    │        │    ║
║  │       │                      v                         │        │    ║
║  │  ┌────┴──────────┐   ┌───────────────┐        ┌───────▼──────┐ │    ║
║  │  │ NVIDIA Device │   │  /dev/nvidia0 │        │ GPU VRAM     │ │    ║
║  │  │ Plugin        │   │  CUDA libs    │        │ 16GB (T4)    │ │    ║
║  │  │ DaemonSet     │   │  (injected)   │        │ LLM Weights  │ │    ║
║  │  └───────────────┘   └───────────────┘        └──────────────┘ │    ║
║  └─────────────────────────────────────────────────────────────────┘    ║
║                                                                          ║
║  ┌─────────────────────────────────────────────────────────────────┐    ║
║  │                   LLM SERVING WORKLOADS                          │    ║
║  │                                                                  │    ║
║  │  ┌─────────────────────┐     ┌──────────────────────────────┐   │    ║
║  │  │   vLLM Pod          │     │  Nginx Ingress Pod           │   │    ║
║  │  │   10.42.0.15:8000   │<────│  :80 / :443                  │   │    ║
║  │  │   (LLM inference)   │     │  Routes: llm.domain.com      │   │    ║
║  │  └──────────┬──────────┘     └──────────────────────────────┘   │    ║
║  │             │                                                    │    ║
║  │             │ /model-cache (PVC)                                 │    ║
║  │  ┌──────────▼──────────┐     ┌──────────────────────────────┐   │    ║
║  │  │ local-path-storage  │     │  CoreDNS Pod                 │   │    ║
║  │  │ /rancher/k3s/storage│     │  Resolves service names      │   │    ║
║  │  │ (model weights)     │     │  vllm-service -> 10.43.x.x   │   │    ║
║  │  └─────────────────────┘     └──────────────────────────────┘   │    ║
║  └─────────────────────────────────────────────────────────────────┘    ║
║                                                                          ║
║  ┌─────────────────────────────────────────────────────────────────┐    ║
║  │                   OBSERVABILITY STACK                            │    ║
║  │                                                                  │    ║
║  │  ┌───────────────┐  scrape  ┌─────────────────┐  dashboard     │    ║
║  │  │ DCGM Exporter │─────────>│   Prometheus     │───────────────>│    ║
║  │  │ GPU metrics   │          │   :9090          │  Grafana :3000 │    ║
║  │  └───────────────┘          └────────┬─────────┘               │    ║
║  │  ┌───────────────┐  scrape           │ query                   │    ║
║  │  │ Node Exporter │─────────>         │                         │    ║
║  │  └───────────────┘          ┌────────▼─────────┐              │    ║
║  │  ┌───────────────┐          │      KEDA         │              │    ║
║  │  │ vLLM /metrics │─────────>│  (auto-scaler)    │              │    ║
║  │  └───────────────┘  scrape  └──────────────────┘              │    ║
║  └─────────────────────────────────────────────────────────────────┘    ║
╚══════════════════════════════════════════════════════════════════════════╝
              ^                            ^
    kubectl (your laptop)          Browser / Client App
    Port 6443 (K8s API)            Port 30800 (NodePort)
                                   Port 80/443 (Ingress)
```

---

### 🔍 How to Observe API Calls in Real-Time

```bash
# Enable verbose kubectl to see every HTTP call
kubectl get pods -n llm-serving -v=8
# Output shows:
# I1216 GET https://127.0.0.1:6443/api/v1/namespaces/llm-serving/pods
# I1216 Response Status: 200 OK in 12ms
# I1216 Response Body: {"kind":"PodList","items":[...]}

# Maximum verbosity - shows request AND response body
kubectl apply -f vllm-deployment.yaml -v=10

# Watch etcd changes in real-time
export ETCDCTL_API=3
ETCDCTL_ENDPOINTS="https://127.0.0.1:2379" \
  etcdctl watch /registry/pods/llm-serving --prefix
# Shows raw key-value changes as pods are created/updated/deleted

# K3s audit log (every API call logged)
sudo journalctl -u k3s | grep '"verb"'
```

---

## Production Error Encyclopedia

Every real production error encountered when deploying LLMs on K3s/GPU — with root causes, diagnostics, and step-by-step fixes.

---

### 🔴 ERROR CLASS 1: GPU & Driver Errors

#### Error 1.1 — CUDA Driver Version Mismatch
```
CUDA driver version is insufficient for CUDA runtime version
CUDA error: no kernel image is available for execution on the device
```

**Root Cause:** CUDA runtime in the Docker image (e.g., CUDA 12.1) is newer than the host driver (e.g., CUDA 11.x).

**Diagnosis:**
```bash
# Check host CUDA version (driver-supported max)
nvidia-smi
# Top-right shows: CUDA Version: 11.8

# Check what CUDA version is inside the container
kubectl exec -it <vllm-pod> -- nvcc --version
# Shows: Cuda compilation tools, release 12.1
# MISMATCH: 12.1 > 11.8 -> ERROR
```

**Fix:**
```bash
# Option A: Upgrade NVIDIA driver on EC2 host
sudo apt-get install -y nvidia-driver-535
sudo reboot

# Option B: Pin to older vLLM image matching your CUDA version
image: vllm/vllm-openai:v0.3.3   # Built with CUDA 11.8

# Compatibility matrix:
# NVIDIA Driver 450.x -> CUDA 11.0
# NVIDIA Driver 520.x -> CUDA 11.8
# NVIDIA Driver 535.x -> CUDA 12.1
# NVIDIA Driver 545.x -> CUDA 12.3
```

---

#### Error 1.2 — CUDA Out of Memory During Inference
```
RuntimeError: CUDA out of memory. Tried to allocate 2.34 GiB
(GPU 0; 15.78 GiB total capacity; 13.42 GiB already allocated;
1.23 GiB free; 13.91 GiB reserved in total by PyTorch)
```

**Root Cause:** Model + KV cache + activation memory exceeds VRAM.

**Diagnosis & Fix Sequence:**
```bash
# Step 1: Check GPU memory
watch -n 0.5 nvidia-smi --query-gpu=memory.used,memory.free --format=csv

# Step 2: Calculate if model fits
# 8B model x 2 bytes (FP16) x 1.2 safety = ~19.2 GB -> EXCEEDS 16GB T4!

# Fix 1: Reduce max context length
- --max-model-len
- "2048"   # was 4096, halving frees ~25% KV cache VRAM

# Fix 2: Reduce GPU memory utilization target
- --gpu-memory-utilization
- "0.80"   # was 0.90

# Fix 3: Use a quantized model (massive VRAM savings)
- --model
- TheBloke/Llama-2-7b-chat-AWQ
- --quantization
- awq

# Fix 4: Upgrade to larger GPU instance
# g4dn.xlarge (16GB T4) -> g5.xlarge (24GB A10G)
aws ec2 modify-instance-attribute --instance-id <id> --instance-type g5.xlarge
```

---

#### Error 1.3 — NVML Driver/Library Version Mismatch
```
Failed to initialize NVML: Driver/library version mismatch
nvidia-smi: error: nvml_init(): NVML shared library not found!
```

**Root Cause:** NVIDIA kernel module version does not match the userspace NVML library. Usually happens after a kernel update.

**Fix:**
```bash
# Check kernel module version vs nvidia-smi
cat /proc/driver/nvidia/version

# Unload and reload the NVIDIA kernel module
sudo rmmod nvidia_uvm nvidia_drm nvidia_modeset nvidia
sudo modprobe nvidia

# If that fails, reboot is required
sudo reboot

# Prevention: Lock the kernel version
sudo apt-mark hold linux-generic linux-image-generic linux-headers-generic
```

---

#### Error 1.4 — GPU Not Visible in Pod
```
Error: failed to create containerd container:
       OCI runtime exec failed: cannot allocate GPU
```

**Diagnosis:**
```bash
# Check device plugin
kubectl get pods -n gpu-operator | grep device-plugin

# Check containerd NVIDIA runtime config
grep -A 5 'nvidia' /etc/containerd/config.toml

# Re-configure if missing
sudo apt-get install -y nvidia-container-toolkit
sudo nvidia-ctk runtime configure --runtime=containerd
sudo systemctl restart containerd
sudo systemctl restart k3s
```

---

### 🟠 ERROR CLASS 2: Kubernetes Scheduling Errors

#### Error 2.1 — Pod Pending: Insufficient nvidia.com/gpu
```
Events:
  Warning  FailedScheduling  0/1 nodes are available:
  1 Insufficient nvidia.com/gpu.
```

**Diagnosis Tree:**
```bash
# Is the device plugin running?
kubectl get pods -n gpu-operator | grep device-plugin

# Is the GPU resource advertised?
kubectl describe node | grep -A 10 'Allocatable'
# Should show: nvidia.com/gpu: 1

# Is the GPU already fully allocated?
kubectl describe node | grep -A 20 'Allocated resources'
# Check if nvidia.com/gpu 1/1 (100% used)

# Find which pod holds the GPU
kubectl get pods -A -o custom-columns='NS:.metadata.namespace,\
NAME:.metadata.name,\
GPU:.spec.containers[*].resources.limits.nvidia\.com/gpu'

# Node taints?
kubectl describe node | grep Taints
# If nvidia.com/gpu=present:NoSchedule -> add toleration to pod
```

---

#### Error 2.2 — Pod Pending: PVC Not Bound
```
Events:
  Warning  FailedScheduling  pod has unbound immediate PersistentVolumeClaims
```

**Fix:**
```bash
# Check PVC status
kubectl get pvc -n llm-serving
# STATUS = Pending -> not bound

# Check local-path-provisioner
kubectl get pods -n kube-system | grep local-path
kubectl rollout restart deployment/local-path-provisioner -n kube-system

# Delete and recreate PVC
kubectl delete pvc model-cache-pvc -n llm-serving
kubectl apply -f model-cache-pvc.yaml
```

---

#### Error 2.3 — ImagePullBackOff
```
Events:
  Warning  Failed  Back-off pulling image "vllm/vllm-openai:latest"
  Warning  Failed  Error: ImagePullBackOff
```

**Root Cause Options:**
1. Docker Hub rate limit (unauthenticated = 100 pulls/6hr)
2. No internet access from EC2 (missing NAT gateway)
3. Image tag does not exist

**Fix:**
```bash
# Test internet from inside cluster
kubectl run test --rm -it --image=curlimages/curl -- curl -I https://hub.docker.com

# Fix rate limit -- authenticated pulls
kubectl create secret docker-registry dockerhub-secret \
  --docker-username=<your-username> \
  --docker-password=<your-token> \
  --namespace llm-serving
# Add imagePullSecrets to deployment spec

# Best fix: Cache image in AWS ECR
docker pull vllm/vllm-openai:latest
docker tag vllm/vllm-openai:latest <account-id>.dkr.ecr.us-east-1.amazonaws.com/vllm:latest
aws ecr get-login-password | docker login --username AWS --password-stdin <ecr-url>
docker push <ecr-url>/vllm:latest
```

---

### 🟡 ERROR CLASS 3: vLLM Runtime Errors

#### Error 3.1 — GatedRepoError (HuggingFace Access Denied)
```
huggingface_hub.utils._errors.GatedRepoError:
Access to model meta-llama/Meta-Llama-3-8B-Instruct is restricted
```

**Fix:**
```bash
# Step 1: Accept license on HuggingFace website
# Visit: https://huggingface.co/meta-llama/Meta-Llama-3-8B-Instruct
# Click "Agree and access repository"

# Step 2: Verify token is valid
curl https://huggingface.co/api/whoami \
  -H "Authorization: Bearer hf_xxxxxxxxxxxx"
# Should return your username, not 401

# Step 3: Check secret in Kubernetes
kubectl get secret hf-token -n llm-serving \
  -o jsonpath='{.data.token}' | base64 -d

# Step 4: Update secret if wrong
kubectl delete secret hf-token -n llm-serving
kubectl create secret generic hf-token \
  --from-literal=token=hf_<correct-token> \
  --namespace llm-serving
kubectl rollout restart deployment/vllm-llama3-8b -n llm-serving

# Alternative: Use non-gated model (no token required)
# mistralai/Mistral-7B-Instruct-v0.3
# Qwen/Qwen2-7B-Instruct
# microsoft/Phi-3-mini-4k-instruct
```

---

#### Error 3.2 — KV Cache Too Small for max-model-len
```
ValueError: The model's max seq len (8192) is larger than
the maximum number of tokens that can be stored in KV cache (3072).
Try increasing gpu_memory_utilization or decreasing max_model_len.
```

**Fix:**
```bash
# Option A: Increase GPU memory utilization
- --gpu-memory-utilization
- "0.95"   # Use 95% of VRAM

# Option B: Decrease max-model-len
- --max-model-len
- "3072"   # Match what fits

# Option C: Use a larger instance
# g5.xlarge (24GB) can fit 8192 context for 8B model
```

---

#### Error 3.3 — Extreme Cold Start Latency (60–120 seconds)
```
# First request takes 60-120 seconds, subsequent requests are fast
# CUDA graph warming up on first inference
```

**Fix:**
```bash
# Option 1: Disable CUDA graphs (faster startup, ~5% slower throughput)
- --enforce-eager

# Option 2: Pre-warm after pod starts via init container
# Add initContainer to the deployment:
initContainers:
- name: warmup
  image: curlimages/curl
  command: ["/bin/sh", "-c"]
  args:
  - |
    sleep 300  # Wait for model to load
    curl -s http://localhost:8000/v1/chat/completions \
      -H 'Content-Type: application/json' \
      -d '{"model":"meta-llama/Meta-Llama-3-8B-Instruct",
           "messages":[{"role":"user","content":"hi"}],"max_tokens":1}'
```

---

#### Error 3.4 — CrashLoopBackOff with Exit Code 137
```
NAME               READY   STATUS             RESTARTS
vllm-llama3-8b     0/1     CrashLoopBackOff   8
Exit Code: 137  (SIGKILL from kernel OOM killer)
```

**Fix:**
```bash
# Confirm kernel OOM killed the process
dmesg | grep 'Out of memory'
# Output: "Out of memory: Kill process <pid> (python3) score"

# Fix: Increase pod memory limits in deployment
resources:
  limits:
    memory: "32Gi"   # was 16Gi -- model loading needs more CPU RAM

# Also check: vLLM loads model into CPU RAM first, then transfers to GPU
# Peak CPU RAM during load = GPU model size x 2
# 8B FP16 = ~16GB GPU = ~32GB CPU RAM peak during load
```

---

### 🔵 ERROR CLASS 4: Networking Errors

#### Error 4.1 — Connection Refused to LLM API
```
curl: (7) Failed to connect to EC2-IP port 30800: Connection refused
```

**Diagnosis Tree:**
```bash
# 1. Is the pod Running?
kubectl get pods -n llm-serving

# 2. Is the NodePort service created?
kubectl get svc vllm-nodeport -n llm-serving
# Check: PORT(S) = 8000:30800/TCP

# 3. Is port 30800 open in EC2 Security Group?
aws ec2 describe-security-groups --group-ids $SG_ID \
  --query 'SecurityGroups[0].IpPermissions' | grep 30800

# 4. Can you reach the pod from inside the cluster?
kubectl run test --rm -it --image=curlimages/curl -- \
  curl http://vllm-service.llm-serving.svc.cluster.local:8000/health

# 5. Is iptables rule created for NodePort?
sudo iptables -t nat -L KUBE-NODEPORTS | grep 30800
```

---

#### Error 4.2 — Nginx Ingress Returns 502 Bad Gateway
```
HTTP/1.1 502 Bad Gateway
<html><body><h1>502 Bad Gateway</h1></body></html>
```

**Root Cause:** Nginx cannot reach the upstream vLLM service.

**Fix:**
```bash
# Check ingress controller logs
NGINX_POD=$(kubectl get pods -n ingress-nginx -l \
  app.kubernetes.io/component=controller -o name | head -1)
kubectl logs $NGINX_POD -n ingress-nginx | tail -50
# Look for: connect() failed, upstream, error

# Check endpoints are populated
kubectl get endpoints vllm-service -n llm-serving
# Should show: ENDPOINTS = pod-ip:8000
# If empty: pod is not Ready (still loading model)

# Increase proxy timeout for LLM (responses can take 60+ seconds)
# Add to Ingress annotations:
nginx.ingress.kubernetes.io/proxy-read-timeout: "300"
nginx.ingress.kubernetes.io/proxy-send-timeout: "300"
```

---

### 🟤 ERROR CLASS 5: Storage Errors

#### Error 5.1 — No Space Left on Device During Model Download
```
OSError: [Errno 28] No space left on device
Failed to download model: no space left on device
```

**Fix:**
```bash
# Check disk usage
df -h /var/lib/rancher/k3s/storage/

# Option A: Expand EBS volume (no downtime needed)
aws ec2 modify-volume \
  --volume-id <vol-id> \
  --size 400   # Expand from 200GB to 400GB
# Then expand filesystem (no reboot needed):
sudo growpart /dev/nvme0n1 1
sudo resize2fs /dev/nvme0n1p1
# Verify:
df -h /

# Option B: Delete old cached model versions
PVC_PATH=$(kubectl describe pvc model-cache-pvc -n llm-serving \
  | grep 'Volume:' | awk '{print $2}')
ls -lh /var/lib/rancher/k3s/storage/$PVC_PATH/hub/models--*/

# Remove specific model versions you no longer need
rm -rf /var/lib/rancher/k3s/storage/$PVC_PATH/hub/models--mistralai*/

# Option C: Backup to S3, clear cache, re-download
aws s3 sync /var/lib/rancher/k3s/storage/pvc-xxx/ s3://your-bucket/model-backup/
```

---

### 🟣 ERROR CLASS 6: K3s System Errors

#### Error 6.1 — K3s Fails to Start: etcd Context Deadline Exceeded
```
FATA[0000] starting kubernetes: preparing server:
failed to initialize etcd: context deadline exceeded
```

**Fix:**
```bash
# Check disk space (etcd needs room to write WAL)
df -h /var/lib/rancher/

# Check I/O performance (etcd needs consistent low latency)
iostat -dx 1 5

# If database corrupt, reset K3s (WARNING: loses all cluster state!)
sudo systemctl stop k3s
sudo rm -rf /var/lib/rancher/k3s/server/db/
sudo systemctl start k3s
# Redeploy all workloads after restart

# Prevention: Use gp3 EBS with provisioned IOPS
aws ec2 modify-volume --volume-id vol-xxx --volume-type gp3 --iops 3000
```

---

#### Error 6.2 — too many open files
```
Get https://127.0.0.1:6443/api/v1/pods?...: dial tcp
too many open files
```

**Fix:**
```bash
echo "* soft nofile 1048576" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 1048576" | sudo tee -a /etc/security/limits.conf
echo "fs.file-max = 2097152" | sudo tee -a /etc/sysctl.conf
echo "fs.inotify.max_user_instances = 8192" | sudo tee -a /etc/sysctl.conf
echo "fs.inotify.max_user_watches = 524288" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
sudo systemctl restart k3s
```

---

#### Error 6.3 — CrashLoopBackOff Diagnosis by Exit Code

| Exit Code | Meaning | Common Cause | Fix |
|---|---|---|---|
| **1** | Python exception | OOM, import error, model load fail | Check `kubectl logs --previous` |
| **137** | SIGKILL (OOM) | Kernel killed process (no RAM) | Increase memory limits |
| **139** | Segfault | CUDA/driver bug | Update NVIDIA driver, try different CUDA |
| **143** | SIGTERM | Pod was gracefully stopped | Normal during rolling update |
| **255** | Undefined | Container runtime error | Check containerd logs |

```bash
# Get exit code of last crash
kubectl describe pod <pod-name> -n llm-serving \
  | grep -A 5 "Last State:"

# Get logs from PREVIOUS crash (not the current attempt)
kubectl logs <pod-name> -n llm-serving --previous
```

---

## Real Production Scenarios

Four complete production use cases with different constraints, architectures, common errors encountered, and how they were solved.

---

### 🏢 Scenario A: Startup — Internal AI Assistant (Low Budget)

**Team:** 3-person startup, 1 ML engineer
**Goal:** Run Mistral-7B as internal Slack bot + code assistant
**Budget:** $300/month max
**Instance:** `g4dn.xlarge` (T4, 16GB VRAM, $0.53/hr on-demand)

**Strategy: Spot instances during business hours, stop at night**

```bash
# 1. Launch Spot instance for 70% savings
aws ec2 run-instances \
  --instance-type g4dn.xlarge \
  --instance-market-options '{
    "MarketType":"spot",
    "SpotOptions":{
      "MaxPrice":"0.20",
      "SpotInstanceType":"persistent",
      "InstanceInterruptionBehavior":"stop"
    }
  }' \
  --image-id ami-xxxxxxxxx \
  --key-name llm-key
# $0.53/hr on-demand vs ~$0.16/hr spot = 70% savings

# 2. Deploy lightweight Mistral-7B (no HF token required)
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vllm-mistral
  namespace: llm-serving
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vllm-mistral
  template:
    metadata:
      labels:
        app: vllm-mistral
    spec:
      containers:
      - name: vllm
        image: vllm/vllm-openai:v0.4.3   # Pin version for stability
        args:
        - --model
        - mistralai/Mistral-7B-Instruct-v0.3  # No token required!
        - --dtype
        - float16
        - --max-model-len
        - "8192"
        - --max-num-seqs
        - "4"              # Limit concurrency for budget
        resources:
          limits:
            nvidia.com/gpu: "1"
            memory: "14Gi"
EOF

# 3. Schedule auto-shutdown to save ~$120/month
# Add to crontab on the EC2 instance:
crontab -e
# 0 9  * * 1-5  aws ec2 start-instances --instance-ids i-xxx
# 0 19 * * 1-5  aws ec2 stop-instances  --instance-ids i-xxx
# 0 8  * * 6-7  aws ec2 stop-instances  --instance-ids i-xxx

# 4. Handle Spot interruption gracefully
# Install AWS Node Termination Handler
kubectl apply -f https://github.com/aws/aws-node-termination-handler/releases/latest/download/all-resources.yaml
# This drains the node when AWS sends a 2-minute spot interruption notice
```

**Monthly Cost Breakdown:**
```
Spot instance (g4dn.xlarge) x 10 hrs/day x 22 work-days = $35.20
EBS storage (200GB gp3)                                   = $16.00
Data transfer (egress)                                    = ~$5.00
Elastic IP (when stopped)                                 = $3.60
Total                                                     ~= $60/month
```

**Errors Encountered:**
```
Error 1: "Mistral-7B is slow — 8 tokens/sec with 4 concurrent users"
Root cause: --max-num-seqs 4 causing too many parallel KV caches
Fix: Reduce to --max-num-seqs 2 for faster single-user responses

Error 2: "Pod restarts every morning when instance starts"
Root cause: Spot instance gets different IP; iptables rules stale after resume
Fix: Assign Elastic IP so the address never changes
aws ec2 allocate-address --domain vpc
aws ec2 associate-address --instance-id i-xxx --allocation-id eipalloc-xxx

Error 3: "Model re-downloads on every restart (takes 15 minutes)"
Root cause: PVC data persists, but instance gets wiped on spot termination
Fix: Use EBS volume with "DeleteOnTermination: false"
     Then re-attach volume on new spot instance startup
```

---

### 🏭 Scenario B: Enterprise — Multi-Model Serving Platform

**Team:** 10-person ML team at mid-size company
**Goal:** Llama-3-70B for flagship product + Phi-3-mini for classification
**Constraints:** 99.9% uptime, no spot, data must not leave VPC
**Instance:** `g5.12xlarge` (4x A10G, 96GB total VRAM, $5.67/hr)

**Strategy: Reserved Instance + tensor parallelism + CPU fallback for small models**

```bash
# 1. Purchase Reserved Instance for 40% discount
aws ec2 purchase-reserved-instances-offering \
  --instance-type g5.12xlarge \
  --availability-zone us-east-1a \
  --instance-count 1 \
  --offering-type "No Upfront"
# Saves ~$2.27/hr = ~$1,640/year

# 2. Deploy Llama-3-70B with 4-GPU tensor parallelism
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vllm-llama3-70b
  namespace: llm-serving
spec:
  replicas: 1
  template:
    spec:
      containers:
      - name: vllm
        image: vllm/vllm-openai:latest
        args:
        - --model
        - meta-llama/Meta-Llama-3-70B-Instruct
        - --tensor-parallel-size
        - "4"           # Split across 4 GPUs (24GB each = 96GB total)
        - --quantization
        - awq           # AWQ: 70B x 0.5 bytes = ~35GB fits in 96GB
        - --max-model-len
        - "8192"
        resources:
          limits:
            nvidia.com/gpu: "4"   # ALL 4 GPUs on the node
            memory: "160Gi"
      env:
      - name: NCCL_P2P_DISABLE
        value: "1"   # Disable peer-to-peer for non-NVLink A10G GPUs
EOF

# 3. Deploy Phi-3-mini on CPU for fast classification (saves GPU for 70B)
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: phi3-mini-cpu
  namespace: llm-serving
spec:
  replicas: 2    # 2 replicas for HA
  template:
    spec:
      containers:
      - name: vllm
        image: vllm/vllm-openai:latest
        args:
        - --model
        - microsoft/Phi-3-mini-4k-instruct
        - --device
        - cpu          # Run on CPU -- fine for small models
        - --dtype
        - float32
        - --max-model-len
        - "2048"
        resources:
          requests:
            cpu: "8"
            memory: "16Gi"
          limits:
            cpu: "16"
            memory: "24Gi"  # No GPU requested!
EOF
```

**Errors Encountered:**
```
Error 1: "70B model takes 18 minutes to load"
Root cause: Loading 35GB AWQ weights from standard EBS sequentially
Fix: Switch EBS to io2 with 10,000 IOPS
aws ec2 modify-volume --volume-id vol-xxx --volume-type io2 --iops 10000
Result: Load time dropped from 18 min to 4 min

Error 2: "Tensor parallel hangs during startup — NCCL timeout"
Root cause: NCCL trying NVLink peer-to-peer between A10G GPUs (not supported)
Fix: Disable P2P in environment variables:
  - name: NCCL_P2P_DISABLE
    value: "1"
  - name: NCCL_IB_DISABLE
    value: "1"
Result: Startup works correctly in ~4 minutes

Error 3: "GPU 4x not showing as allocated in Kubernetes"
Root cause: nvidia.com/gpu: 4 request but device plugin only sees individual GPUs
Fix: Verify node has 4 GPUs:
kubectl exec -it <vllm-pod> -- python3 -c "import torch; print(torch.cuda.device_count())"
# Should print: 4
```

---

### 🏥 Scenario C: Healthcare — HIPAA-Compliant LLM

**Team:** Healthcare AI company
**Goal:** Medical note summarization with sensitive patient data
**Constraints:** HIPAA compliance, no public IPs, encrypted at rest, audit logs
**Instance:** `g5.2xlarge` in a private subnet

```bash
# 1. Launch with SSM access (no SSH, no public IP)
aws ec2 run-instances \
  --instance-type g5.2xlarge \
  --subnet-id subnet-private-xxxx \
  --no-associate-public-ip-address \
  --iam-instance-profile Arn=arn:aws:iam::xxx:instance-profile/SSMInstanceProfile
# Why SSM: HIPAA requires no internet-facing management ports

# Access instance securely via SSM (no port 22 needed)
aws ssm start-session --target i-xxxxxxxxxxxxxxxxx

# 2. Create encrypted EBS volumes for model storage
aws ec2 create-volume \
  --availability-zone us-east-1a \
  --size 500 \
  --volume-type gp3 \
  --encrypted \
  --kms-key-id arn:aws:kms:us-east-1:xxx:key/xxx
# Why encrypted EBS: HIPAA requires encryption at rest for PHI

# 3. Enable K3s audit logging (required for HIPAA)
cat > /etc/rancher/k3s/audit-policy.yaml <<'EOF'
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: RequestResponse
  namespaces: ["llm-serving"]
  resources:
  - group: ""
    resources: ["pods", "secrets"]
EOF
# Add to K3s install:
# --kube-apiserver-arg=audit-log-path=/var/log/k3s-audit.log
# --kube-apiserver-arg=audit-policy-file=/etc/rancher/k3s/audit-policy.yaml

# 4. Deploy with strict security context
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vllm-medical
  namespace: llm-serving
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: vllm
        image: <private-ecr-url>/vllm:latest  # From private ECR, not DockerHub
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop: ["ALL"]
        args:
        - --model
        - mistralai/Mistral-7B-Instruct-v0.3
        - --api-key
        - $(VLLM_API_KEY)          # Require auth on every request
        - --disable-log-requests   # CRITICAL: Never log PHI in request logs!
EOF
```

**Errors Encountered:**
```
Error 1: "runAsNonRoot: image will run as root"
Root cause: Official vllm/vllm-openai image uses root user
Fix: Build custom image:
  FROM vllm/vllm-openai:latest
  RUN useradd -u 1000 -m vllmuser && chown -R vllmuser /workspace
  USER vllmuser

Error 2: "readOnlyRootFilesystem blocks model cache writes"
Root cause: vLLM writes to /tmp and /root/.cache at runtime
Fix: Add writable emptyDir volumes for these paths:
  volumeMounts:
  - name: tmp-dir
    mountPath: /tmp
  - name: cache-dir
    mountPath: /root/.cache
  volumes:
  - name: tmp-dir
    emptyDir: {}
  - name: cache-dir
    emptyDir: {}

Error 3: "Audit logs filling up disk quickly"
Root cause: RequestResponse level logs every token in every response
Fix: Change audit level to Metadata for routine reads:
  - level: Metadata
    verbs: ["get", "list", "watch"]
  - level: RequestResponse
    verbs: ["create", "update", "delete"]
```

---

### 🎮 Scenario D: AI API Service — Multi-Tenant Production

**Team:** AI API startup serving 1000+ customers
**Goal:** Multiple models, per-customer rate limiting, usage billing
**Instance:** Auto-scaling group of `g5.xlarge` instances

```bash
# 1. Deploy LiteLLM as API proxy in front of vLLM
# LiteLLM handles: routing, rate limiting, cost tracking, billing
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: litellm-proxy
  namespace: llm-serving
spec:
  replicas: 2
  template:
    spec:
      containers:
      - name: litellm
        image: ghcr.io/berriai/litellm:main-stable
        args:
        - --config
        - /config/litellm-config.yaml
        - --port
        - "4000"
        - --num-workers
        - "4"
EOF

# 2. Create per-customer API keys with rate limits
curl -X POST http://litellm-proxy:4000/key/generate \
  -H "Authorization: Bearer $MASTER_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "key_alias": "customer-acme-corp",
    "duration": "30d",
    "max_budget": 50.00,
    "tpm_limit": 100000,
    "rpm_limit": 60,
    "models": ["llama-3-8b", "mistral-7b"]
  }'
# Why LiteLLM: Adds multi-tenancy, billing, rate limiting on top of raw vLLM

# 3. Use EFS for shared model cache (critical for scale-out!)
# Standard PVCs are ReadWriteOnce -- only 1 pod can mount
# EFS supports ReadWriteMany -- all replicas share the same cache

# Install EFS CSI driver
helm install aws-efs-csi-driver aws-efs-csi-driver/aws-efs-csi-driver \
  --namespace kube-system

# Create EFS StorageClass and PVC
kubectl apply -f - <<EOF
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: efs-sc
provisioner: efs.csi.aws.com
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: model-cache-efs
  namespace: llm-serving
spec:
  accessModes:
    - ReadWriteMany   # Multiple pods can mount simultaneously!
  storageClassName: efs-sc
  resources:
    requests:
      storage: 500Gi
EOF
# With EFS: when KEDA scales vLLM from 1 to 3 pods,
# all 3 pods use the same cached model -- no re-download!
```

**Errors Encountered:**
```
Error 1: "Some customers get 429 Too Many Requests unexpectedly"
Root cause: Multiple customers sharing same underlying API key to vLLM
            Rate limit applied at vLLM level, not per-customer
Fix: LiteLLM enforces per-key limits -- verify LITELLM_MASTER_KEY is set
     and each customer has their own generated key (not master key)

Error 2: "vLLM scale-up too slow -- 5 minutes per new replica"
Root cause: Each new pod downloads model from HuggingFace (ReadWriteOnce PVC)
            New pod cannot mount PVC already mounted by existing pod!
Fix: Switch from local-path PVC to EFS PVC (ReadWriteMany)
     All pods share same EFS mount -> instant scale-up, no re-download

Error 3: "Load balancer sends all traffic to one vLLM pod"
Root cause: K8s Service uses round-robin but slow LLM requests block pod
            for 10-30 seconds, causing all new requests to pile up
Fix: Use LiteLLM router with "least-busy" strategy:
     router_settings:
       routing_strategy: least-busy
     LiteLLM tracks in-flight requests and routes to least loaded backend

Error 4: "Billing shows 0 tokens for some requests"
Root cause: Streaming responses bypass token counting in LiteLLM
Fix: Enable callback for streaming token counting:
  general_settings:
    callbacks: ["prometheus"]
  litellm_settings:
    success_callback: ["langfuse"]
    # Langfuse counts tokens correctly even for streaming
```

---

*Last updated: June 2026 | Author: Hamza*
