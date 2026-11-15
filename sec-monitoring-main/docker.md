# 🐳 Docker Production Cheatsheet
> Real-world issues, battle-tested solutions, and 100+ commands with examples

---

## 📦 Table of Contents
1. [Image Management](#1-image-management)
2. [Container Lifecycle](#2-container-lifecycle)
3. [Networking](#3-networking)
4. [Volumes & Storage](#4-volumes--storage)
5. [Docker Compose](#5-docker-compose)
6. [Logging & Monitoring](#6-logging--monitoring)
7. [Security](#7-security)
8. [Resource Management](#8-resource-management)
9. [Registry & Image Distribution](#9-registry--image-distribution)
10. [Production Issues & Solutions](#10-production-issues--solutions)
11. [Dockerfile Best Practices](#11-dockerfile-best-practices)
12. [Docker Swarm / Orchestration](#12-docker-swarm--orchestration)
13. [Debugging & Troubleshooting](#13-debugging--troubleshooting)

---

## 1. Image Management

### Build Images
```bash
# Basic build
docker build -t myapp:1.0 .

# Build with specific Dockerfile
docker build -f Dockerfile.prod -t myapp:prod .

# Build with build args
docker build --build-arg NODE_ENV=production --build-arg PORT=8080 -t myapp:prod .

# Build with no cache (force fresh build)
docker build --no-cache -t myapp:latest .

# Multi-platform build (requires buildx)
docker buildx build --platform linux/amd64,linux/arm64 -t myapp:latest --push .

# Build and squash layers (reduces image size)
docker build --squash -t myapp:slim .

# Build with target stage (multi-stage builds)
docker build --target builder -t myapp:builder .
docker build --target production -t myapp:prod .

# Build with labels
docker build --label "maintainer=devops@company.com" --label "version=1.0" -t myapp .

# Build with secrets (BuildKit)
DOCKER_BUILDKIT=1 docker build --secret id=mysecret,src=./secret.txt -t myapp .
```

### Inspect & Manage Images
```bash
# List all images
docker images
docker image ls

# List with filters
docker images --filter "dangling=true"          # Untagged images
docker images --filter "label=env=production"    # By label
docker images --filter "since=ubuntu:20.04"      # Images built after

# Inspect image layers
docker history myapp:latest
docker history --no-trunc myapp:latest           # Full command details

# Inspect image metadata
docker inspect myapp:latest
docker inspect --format='{{.Config.Env}}' myapp:latest     # Get env vars
docker inspect --format='{{.Config.ExposedPorts}}' myapp   # Get ports
docker inspect --format='{{.RootFS.Layers}}' myapp         # Layer hashes

# Image size details
docker image ls --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"

# Save and load images (for air-gapped environments)
docker save myapp:latest | gzip > myapp_latest.tar.gz
docker load < myapp_latest.tar.gz
docker save -o images.tar myapp:latest nginx:alpine        # Multiple images

# Tag images
docker tag myapp:latest registry.company.com/myapp:1.0.0
docker tag myapp:latest myapp:stable

# Remove images
docker rmi myapp:old
docker image prune                                  # Remove dangling images
docker image prune -a                               # Remove ALL unused images
docker image prune -a --filter "until=72h"          # Remove images older than 72h

# Pull with digest (immutable reference — use in production!)
docker pull nginx@sha256:abc123def456...
```

---

## 2. Container Lifecycle

### Run Containers
```bash
# Basic run
docker run nginx

# Detached mode with name and port mapping
docker run -d --name webserver -p 80:80 nginx

# Run with environment variables
docker run -d \
  -e DB_HOST=postgres \
  -e DB_PORT=5432 \
  -e DB_PASS=secret \
  --name app myapp:latest

# Run with env file
docker run -d --env-file .env.production --name app myapp:latest

# Run interactively
docker run -it --rm ubuntu:22.04 bash

# Run as specific user (security best practice)
docker run -u 1001:1001 myapp:latest

# Run with resource limits
docker run -d \
  --memory="512m" \
  --cpus="1.5" \
  --memory-swap="1g" \
  --name app myapp:latest

# Run with restart policy
docker run -d --restart=always --name app myapp:latest
docker run -d --restart=on-failure:5 --name app myapp:latest   # Max 5 retries
docker run -d --restart=unless-stopped --name app myapp:latest

# Run with health check
docker run -d \
  --health-cmd="curl -f http://localhost/health || exit 1" \
  --health-interval=30s \
  --health-timeout=10s \
  --health-retries=3 \
  --health-start-period=60s \
  --name app myapp:latest

# Run with custom DNS
docker run -d --dns=8.8.8.8 --dns=8.8.4.4 --name app myapp

# Run with hostname
docker run -d --hostname=app-server-01 --name app myapp

# Run with extra hosts (/etc/hosts)
docker run -d --add-host=db.internal:192.168.1.50 myapp

# Run with capabilities (security)
docker run -d --cap-drop=ALL --cap-add=NET_BIND_SERVICE myapp
docker run -d --security-opt=no-new-privileges myapp

# Run with read-only filesystem
docker run -d --read-only \
  --tmpfs /tmp \
  --tmpfs /var/run \
  myapp:latest

# Run with init process (prevents zombie processes)
docker run -d --init myapp:latest

# Override entrypoint
docker run --entrypoint /bin/sh myapp -c "echo hello"
```

### Manage Running Containers
```bash
# List containers
docker ps                          # Running only
docker ps -a                       # All containers
docker ps -q                       # Quiet (IDs only)
docker ps --filter "status=exited"
docker ps --filter "name=app"
docker ps --filter "ancestor=nginx"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# Start / stop / restart
docker start myapp
docker stop myapp                  # Graceful (SIGTERM → SIGKILL after 10s)
docker stop -t 30 myapp            # Custom grace period (30s)
docker restart myapp
docker kill myapp                  # Immediate SIGKILL
docker kill -s SIGUSR1 myapp       # Send custom signal

# Pause / unpause (freeze without stopping)
docker pause myapp
docker unpause myapp

# Remove containers
docker rm myapp
docker rm -f myapp                 # Force remove running container
docker rm $(docker ps -aq)         # Remove ALL stopped containers
docker container prune             # Remove all stopped containers
docker container prune --filter "until=24h"

# Execute commands in running containers
docker exec -it myapp bash
docker exec -it myapp sh           # For alpine-based
docker exec myapp cat /etc/nginx/nginx.conf
docker exec -u root myapp bash     # Execute as root
docker exec -e DEBUG=true myapp node script.js

# Copy files to/from containers
docker cp myapp:/etc/nginx/nginx.conf ./nginx.conf   # Container → Host
docker cp ./config.json myapp:/app/config.json        # Host → Container

# Rename a container
docker rename old_name new_name

# Attach to container stdout
docker attach myapp                # CTRL+C will stop the container!

# Wait for container to stop
docker wait myapp
```

---

## 3. Networking

### Network Management
```bash
# List networks
docker network ls

# Create networks
docker network create mynetwork                            # Bridge (default)
docker network create --driver overlay swarm-net           # Swarm overlay
docker network create --driver host host-net               # Host networking
docker network create \
  --subnet=172.20.0.0/16 \
  --ip-range=172.20.240.0/20 \
  --gateway=172.20.0.1 \
  --driver bridge \
  custom-net

# Inspect network
docker network inspect mynetwork
docker network inspect --format='{{range .Containers}}{{.Name}}: {{.IPv4Address}}{{"\n"}}{{end}}' mynetwork

# Connect/disconnect containers
docker network connect mynetwork myapp
docker network connect --ip 172.20.0.50 mynetwork myapp    # Static IP
docker network disconnect mynetwork myapp

# Remove networks
docker network rm mynetwork
docker network prune               # Remove all unused networks

# Run container with specific network
docker run -d --network=mynetwork --name app myapp

# Run with host networking (no isolation — use carefully)
docker run -d --network=host --name app myapp

# Run with no networking
docker run -d --network=none --name app myapp
```

---

## 4. Volumes & Storage

### Volume Management
```bash
# Create volumes
docker volume create mydata
docker volume create --driver local \
  --opt type=nfs \
  --opt o=addr=192.168.1.100,rw \
  --opt device=:/nfs/data \
  nfs-vol

# List volumes
docker volume ls
docker volume ls --filter "dangling=true"

# Inspect volume
docker volume inspect mydata
docker volume inspect --format='{{.Mountpoint}}' mydata

# Remove volumes
docker volume rm mydata
docker volume prune               # Remove all unused volumes
docker volume prune --filter "label!=keep=true"

# Mount volumes in containers
docker run -d -v mydata:/app/data myapp              # Named volume
docker run -d -v /host/path:/container/path myapp    # Bind mount
docker run -d -v /host/path:/container/path:ro myapp # Read-only bind
docker run -d --mount type=volume,src=mydata,dst=/app/data myapp    # Explicit
docker run -d --mount type=bind,src=/host/path,dst=/app/data myapp  # Bind
docker run -d --mount type=tmpfs,dst=/tmp,tmpfs-size=100m myapp     # tmpfs

# Backup a volume
docker run --rm \
  -v mydata:/data \
  -v $(pwd):/backup \
  ubuntu tar czf /backup/mydata_backup.tar.gz -C /data .

# Restore a volume
docker run --rm \
  -v mydata:/data \
  -v $(pwd):/backup \
  ubuntu tar xzf /backup/mydata_backup.tar.gz -C /data
```

---

## 5. Docker Compose

### Essential Compose Commands
```bash
# Start services
docker compose up -d                          # Detached
docker compose up --build                     # Force rebuild
docker compose up --build --no-cache          # No cache rebuild
docker compose up --scale app=3               # Scale service
docker compose up --remove-orphans            # Remove orphan containers

# Stop services
docker compose down                           # Stop and remove containers
docker compose down -v                        # Also remove volumes
docker compose down --rmi all                 # Also remove images
docker compose stop                           # Stop without removing

# Service management
docker compose ps
docker compose logs -f                        # Follow all logs
docker compose logs -f --tail=100 app         # Last 100 lines of service
docker compose exec app bash                  # Shell into service
docker compose run --rm app python manage.py migrate   # One-off command
docker compose restart app

# Scaling
docker compose up -d --scale worker=5

# Config validation
docker compose config                         # Validate and view merged config
docker compose config --services              # List service names

# Pull latest images
docker compose pull

# Build only
docker compose build
docker compose build --parallel               # Parallel build

# Specific environment file
docker compose --env-file .env.production up -d
```

### Production-Ready docker-compose.yml
```yaml
version: '3.9'

services:
  app:
    image: myapp:${APP_VERSION:-latest}
    build:
      context: .
      dockerfile: Dockerfile.prod
      args:
        - NODE_ENV=production
    restart: unless-stopped
    environment:
      - NODE_ENV=production
      - DB_HOST=postgres
    env_file:
      - .env.production
    ports:
      - "8080:8080"
    volumes:
      - app_logs:/app/logs
    networks:
      - frontend
      - backend
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 1G
        reservations:
          cpus: '0.5'
          memory: 256M
    logging:
      driver: "json-file"
      options:
        max-size: "100m"
        max-file: "5"
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
      - /var/run

  postgres:
    image: postgres:15-alpine
    restart: unless-stopped
    environment:
      POSTGRES_DB: ${DB_NAME}
      POSTGRES_USER: ${DB_USER}
      POSTGRES_PASSWORD: ${DB_PASS}
    volumes:
      - pg_data:/var/lib/postgresql/data
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql:ro
    networks:
      - backend
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${DB_USER} -d ${DB_NAME}"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    restart: unless-stopped
    command: redis-server --requirepass ${REDIS_PASS} --maxmemory 256mb --maxmemory-policy allkeys-lru
    volumes:
      - redis_data:/data
    networks:
      - backend
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 3s
      retries: 5

volumes:
  pg_data:
  redis_data:
  app_logs:

networks:
  frontend:
    driver: bridge
  backend:
    driver: bridge
    internal: true          # No external internet access
```

---

## 6. Logging & Monitoring

### Log Management
```bash
# View logs
docker logs myapp
docker logs -f myapp                        # Follow/tail
docker logs --tail=100 myapp                # Last 100 lines
docker logs --since=1h myapp                # Last 1 hour
docker logs --since="2024-01-15T10:00:00" myapp
docker logs --until="2024-01-15T11:00:00" myapp
docker logs --since=30m --until=10m myapp   # Between 30min and 10min ago
docker logs -t myapp                        # Include timestamps
docker logs 2>&1 myapp | grep ERROR         # Filter errors

# Logging drivers
docker run -d \
  --log-driver=json-file \
  --log-opt max-size=50m \
  --log-opt max-file=10 \
  --name app myapp

docker run -d \
  --log-driver=syslog \
  --log-opt syslog-address=udp://192.168.1.100:514 \
  --log-opt tag="myapp" \
  --name app myapp

docker run -d \
  --log-driver=fluentd \
  --log-opt fluentd-address=localhost:24224 \
  --log-opt tag="docker.{{.Name}}" \
  --name app myapp

docker run -d \
  --log-driver=awslogs \
  --log-opt awslogs-group=/production/myapp \
  --log-opt awslogs-region=us-east-1 \
  --name app myapp

# Get log file location
docker inspect --format='{{.LogPath}}' myapp
```

### Stats & Monitoring
```bash
# Real-time stats
docker stats                               # All containers
docker stats myapp                         # Specific container
docker stats --no-stream                   # One-shot snapshot
docker stats --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}"

# System-wide info
docker system df                           # Disk usage
docker system df -v                        # Verbose disk usage
docker system info                         # Docker engine info
docker system events                       # Real-time events
docker system events --filter "type=container"
docker system events --filter "event=die"  # Watch for crashes

# Events (useful for alerting)
docker events --since=1h --filter "event=oom"     # OOM kills
docker events --filter "event=health_status"       # Health changes
```

---

## 7. Security

### Security Scanning & Hardening
```bash
# Scan image for vulnerabilities (Docker Scout)
docker scout cves myapp:latest
docker scout recommendations myapp:latest
docker scout quickview myapp:latest

# Run as non-root user
docker run -u 1000:1000 myapp:latest

# Drop all capabilities, add only what's needed
docker run \
  --cap-drop=ALL \
  --cap-add=NET_BIND_SERVICE \
  --cap-add=CHOWN \
  myapp

# Read-only filesystem
docker run --read-only --tmpfs /tmp myapp

# Prevent privilege escalation
docker run --security-opt=no-new-privileges myapp

# Use seccomp profile
docker run --security-opt seccomp=/path/to/seccomp.json myapp

# Use AppArmor profile
docker run --security-opt apparmor=docker-default myapp

# Inspect container capabilities
docker inspect --format='{{.HostConfig.CapAdd}}' myapp
docker inspect --format='{{.HostConfig.CapDrop}}' myapp

# Namespace isolation
docker run --userns=host myapp    # Use host user namespace (avoid!)
docker run --pid=host myapp       # Share host PID namespace (debugging only)

# Check Docker daemon security
docker info | grep -i security
```

### Secrets Management
```bash
# Docker secrets (Swarm mode)
echo "mysecretpassword" | docker secret create db_password -
docker secret create ssl_cert ./certificate.pem
docker secret ls
docker secret inspect db_password
docker secret rm db_password

# Use secret in service
docker service create \
  --secret db_password \
  --name app myapp

# BuildKit secrets (never baked into image)
# In Dockerfile:
# RUN --mount=type=secret,id=npm_token npm install

DOCKER_BUILDKIT=1 docker build \
  --secret id=npm_token,env=NPM_TOKEN \
  -t myapp .
```

---

## 8. Resource Management

### CPU & Memory Limits
```bash
# Memory limits
docker run -d --memory=512m myapp              # Hard limit
docker run -d --memory=512m --memory-swap=1g myapp  # Swap = total - memory
docker run -d --memory-reservation=256m myapp  # Soft limit (guidance)
docker run -d --memory-swappiness=10 myapp     # Reduce swap usage (0-100)
docker run -d --oom-kill-disable myapp         # Disable OOM killer (dangerous!)
docker run -d --oom-score-adj=-500 myapp       # Lower OOM kill priority

# CPU limits
docker run -d --cpus="2.5" myapp               # 2.5 CPU cores
docker run -d --cpu-shares=512 myapp           # Relative weight (default 1024)
docker run -d --cpuset-cpus="0,2" myapp        # Pin to CPU cores 0 and 2
docker run -d --cpu-period=100000 --cpu-quota=50000 myapp  # 50% of 1 CPU

# I/O limits
docker run -d \
  --device-read-bps /dev/sda:100mb \
  --device-write-bps /dev/sda:100mb \
  --device-read-iops /dev/sda:1000 \
  --device-write-iops /dev/sda:1000 \
  myapp

# Update resource limits on running container
docker update --memory=1g --cpus=2 myapp
docker update --restart=always myapp
docker update --memory=1g myapp app1 app2      # Update multiple containers

# Ulimits
docker run -d \
  --ulimit nofile=65536:65536 \
  --ulimit nproc=4096:4096 \
  myapp
```

---

## 9. Registry & Image Distribution

### Registry Operations
```bash
# Login / logout
docker login
docker login registry.company.com
docker login -u myuser -p mypass registry.company.com
docker logout

# Push images
docker push myimage:latest
docker push registry.company.com/myteam/myapp:1.0.0

# Search Docker Hub
docker search nginx
docker search --filter "is-official=true" nginx
docker search --filter "stars=100" nodejs

# Pull images
docker pull nginx:latest
docker pull nginx:1.25.3-alpine
docker pull --platform linux/amd64 nginx       # Specific platform

# Run local registry
docker run -d \
  -p 5000:5000 \
  --restart=always \
  --name registry \
  -v /data/registry:/var/lib/registry \
  registry:2

# Tag and push to local registry
docker tag myapp:latest localhost:5000/myapp:latest
docker push localhost:5000/myapp:latest
docker pull localhost:5000/myapp:latest

# List images in local registry
curl http://localhost:5000/v2/_catalog
curl http://localhost:5000/v2/myapp/tags/list
```

---

## 10. Production Issues & Solutions

---

### 🔴 ISSUE 1: Container Keeps Restarting / Crash Loop

**Symptoms:** Container exits immediately, restart count climbing, `docker ps` shows `Restarting`

**Diagnosis:**
```bash
# Check exit code (non-zero = error)
docker inspect myapp --format='{{.State.ExitCode}}'

# Check last logs before crash
docker logs --tail=50 myapp

# Check OOM kill
docker inspect myapp --format='{{.State.OOMKilled}}'

# Watch restart events live
docker events --filter "container=myapp" --filter "event=die"
```

**Solutions:**
```bash
# If OOMKilled=true → increase memory
docker update --memory=2g myapp

# If exit code 1 → application error, check logs
docker logs myapp 2>&1 | tail -100

# If exit code 137 → SIGKILL (likely OOM or forced stop)
# Increase memory limit or optimize app memory usage

# If exit code 143 → SIGTERM timeout → app too slow to shutdown
docker stop -t 60 myapp  # Give more shutdown time
# In compose: stop_grace_period: 60s

# Inspect with shell before crash
docker run -it --entrypoint /bin/sh myapp
# or override command
docker run -it myapp /bin/sh

# Debugging: start with sleep to inspect filesystem
docker run -d --entrypoint sleep myapp infinity
docker exec -it myapp sh
```

---

### 🔴 ISSUE 2: Container OOM (Out of Memory) Killed

**Symptoms:** Container stops unexpectedly, `OOMKilled: true`, system logs show memory kill

**Diagnosis:**
```bash
docker inspect myapp | grep -i oom
docker stats --no-stream myapp
dmesg | grep -i "out of memory"   # On host
```

**Solutions:**
```bash
# Increase memory limit
docker update --memory=2g --memory-swap=3g myapp

# For compose:
# deploy:
#   resources:
#     limits:
#       memory: 2G

# Add swap space on host
sudo fallocate -l 4G /swapfile
sudo mkswap /swapfile && sudo swapon /swapfile

# Configure soft limit to trigger GC before hard limit kills
docker run -d \
  --memory=2g \
  --memory-reservation=1g \
  myapp

# For JVM apps: set heap limits
docker run -e JAVA_OPTS="-Xmx1g -Xms512m" myapp

# For Node.js: set max-old-space-size
docker run myapp node --max-old-space-size=1024 app.js
```

---

### 🔴 ISSUE 3: Cannot Pull Image / Registry Authentication

**Symptoms:** `unauthorized: authentication required`, `no basic auth credentials`

**Solutions:**
```bash
# Re-authenticate
docker logout
docker login registry.company.com

# For Kubernetes/CI: store credentials as secret
docker login -u user -p pass registry.company.com
cat ~/.docker/config.json  # Contains base64 encoded credentials

# For GCR (Google Container Registry)
gcloud auth configure-docker
docker pull gcr.io/my-project/myapp:latest

# For ECR (AWS)
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin \
  123456789.dkr.ecr.us-east-1.amazonaws.com

# For self-signed certificate errors
# Option 1: Add insecure registry (dev only!)
# /etc/docker/daemon.json:
# { "insecure-registries": ["registry.internal:5000"] }

# Option 2: Add CA cert (production)
sudo mkdir -p /etc/docker/certs.d/registry.internal:5000
sudo cp ca.crt /etc/docker/certs.d/registry.internal:5000/ca.crt
sudo systemctl restart docker
```

---

### 🔴 ISSUE 4: Container Networking Issues (Cannot Connect to Service)

**Symptoms:** Service A cannot reach Service B, `connection refused`, DNS resolution failure

**Diagnosis:**
```bash
# Check if containers are on same network
docker network inspect mynetwork
docker inspect app --format='{{json .NetworkSettings.Networks}}'

# Test DNS resolution from inside container
docker exec app nslookup postgres
docker exec app ping postgres
docker exec app curl http://postgres:5432

# Check what ports are actually exposed
docker port myapp
docker inspect myapp --format='{{json .NetworkSettings.Ports}}'

# Check firewall rules
sudo iptables -L -n | grep DOCKER
```

**Solutions:**
```bash
# Put containers on same user-defined network (use container name as DNS)
docker network create appnet
docker run -d --network=appnet --name postgres postgres:15
docker run -d --network=appnet --name app myapp

# If using compose, services auto-discover each other by service name
# Check compose network config
docker compose config | grep -A5 networks

# Port is bound to 127.0.0.1 (not reachable externally)
# Wrong:  -p 127.0.0.1:8080:8080
# Correct: -p 8080:8080  or  -p 0.0.0.0:8080:8080

# MTU mismatch (common in cloud/VPN environments)
docker network create --opt com.docker.network.driver.mtu=1450 appnet

# Docker daemon MTU setting
# /etc/docker/daemon.json
# { "mtu": 1450 }
```

---

### 🔴 ISSUE 5: Docker Disk Full / No Space Left on Device

**Symptoms:** `no space left on device`, containers fail to start, builds fail

**Diagnosis:**
```bash
docker system df             # Docker space usage summary
docker system df -v          # Detailed breakdown
du -sh /var/lib/docker/*     # Raw disk usage

# Find large log files
find /var/lib/docker/containers -name "*.log" -size +100M
```

**Solutions:**
```bash
# Nuclear option: clean everything unused
docker system prune -a --volumes

# Targeted cleanup
docker container prune         # Stopped containers
docker image prune -a          # Unused images
docker volume prune            # Unused volumes
docker network prune           # Unused networks

# Truncate log file for running container (emergency)
truncate -s 0 $(docker inspect --format='{{.LogPath}}' myapp)

# Permanently fix: configure log rotation in daemon.json
# /etc/docker/daemon.json:
# {
#   "log-driver": "json-file",
#   "log-opts": {
#     "max-size": "50m",
#     "max-file": "5"
#   }
# }
sudo systemctl restart docker

# Move Docker data directory to larger disk
sudo systemctl stop docker
sudo mv /var/lib/docker /mnt/large-disk/docker
sudo ln -s /mnt/large-disk/docker /var/lib/docker
sudo systemctl start docker
```

---

### 🔴 ISSUE 6: Container Health Check Failing

**Symptoms:** Container is `unhealthy`, traffic stops being sent to it, service restarts

**Diagnosis:**
```bash
# Check health status and last 5 results
docker inspect --format='{{json .State.Health}}' myapp | python3 -m json.tool

# Run health check manually
docker exec myapp curl -f http://localhost:8080/health

# Watch health events
docker events --filter "event=health_status" --filter "container=myapp"
```

**Solutions:**
```bash
# Common fix: increase start_period for slow-starting apps
docker run -d \
  --health-cmd="curl -f http://localhost:8080/health || exit 1" \
  --health-interval=30s \
  --health-timeout=10s \
  --health-retries=3 \
  --health-start-period=120s \
  myapp

# Dockerfile health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

# For apps without curl, use wget or custom script
HEALTHCHECK CMD wget -q --spider http://localhost:8080/health || exit 1
HEALTHCHECK CMD /app/healthcheck.sh || exit 1
```

---

### 🔴 ISSUE 7: Zombie Processes / PID 1 Problem

**Symptoms:** App doesn't respond to SIGTERM, graceful shutdown takes too long, zombie processes accumulate

**Root Cause:** App process is PID 1 but doesn't handle signals properly

**Solutions:**
```bash
# Option 1: Use --init flag (adds tini as PID 1)
docker run -d --init myapp

# Option 2: Add tini in Dockerfile
# RUN apk add --no-cache tini
# ENTRYPOINT ["/sbin/tini", "--"]
# CMD ["node", "server.js"]

# Option 3: Use exec form in Dockerfile (not shell form)
# WRONG (shell form - shell becomes PID 1, app doesn't get signals):
# CMD node server.js

# RIGHT (exec form - app IS PID 1):
# CMD ["node", "server.js"]

# Check what PID 1 is
docker exec myapp ps aux | grep "PID\|1 "
docker exec myapp cat /proc/1/cmdline | tr '\0' ' '

# Test graceful shutdown
docker stop -t 30 myapp && docker logs --tail=20 myapp
```

---

### 🔴 ISSUE 8: Image Build Cache Invalidation Issues

**Symptoms:** Builds are slow, or changes aren't picked up, or cache used when it shouldn't be

**Solutions:**
```bash
# Force completely fresh build
docker build --no-cache -t myapp .

# Selective cache busting with ARG trick
# In Dockerfile:
# ARG CACHEBUST=1
# RUN git clone ...
docker build --build-arg CACHEBUST=$(date +%s) -t myapp .

# Order Dockerfile commands: least-changing → most-changing
# BAD: copies code first (invalidates everything on every code change)
# COPY . .
# RUN npm install

# GOOD: install dependencies first (cached unless package.json changes)
# COPY package*.json ./
# RUN npm install
# COPY . .

# Check what's in build context (large context = slow builds)
# Create .dockerignore
cat .dockerignore
# node_modules, .git, *.log, dist, coverage

# Measure build context size
du -sh . && docker build -t myapp . 2>&1 | head -5
```

---

### 🔴 ISSUE 9: Container Time/Timezone Issues

**Symptoms:** Logs show wrong times, scheduled jobs run at wrong times, certificate errors

**Solutions:**
```bash
# Pass host timezone
docker run -d \
  -v /etc/localtime:/etc/localtime:ro \
  -v /etc/timezone:/etc/timezone:ro \
  myapp

# Set timezone via environment variable
docker run -d -e TZ=America/New_York myapp
docker run -d -e TZ=Asia/Karachi myapp

# In Dockerfile
ENV TZ=UTC
RUN apk add --no-cache tzdata  # Alpine
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Verify container time
docker exec myapp date
docker exec myapp cat /etc/timezone
```

---

### 🔴 ISSUE 10: High CPU Runaway Container

**Symptoms:** One container consuming 100%+ CPU, host degraded, other services affected

**Diagnosis:**
```bash
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"

# Find the runaway container
docker stats --no-stream | sort -k3 -rh | head -5

# Check what's running inside
docker exec myapp top -b -n1
docker exec myapp ps aux --sort=-%cpu | head
```

**Solutions:**
```bash
# Immediately throttle without stopping
docker update --cpus=0.5 myapp

# Set CPU limits permanently
docker update --cpus=2 --cpu-shares=512 myapp

# Pin to specific CPUs to isolate from critical services
docker update --cpuset-cpus="4,5,6,7" myapp  # Use cores 4-7 only

# For compose, add limits:
# deploy:
#   resources:
#     limits:
#       cpus: '2.0'
```

---

### 🔴 ISSUE 11: Data Loss After Container Restart

**Root Cause:** Writing data to container's writable layer instead of a volume

**Solutions:**
```bash
# WRONG: Data lost when container is removed
docker run -d postgres

# RIGHT: Use named volume
docker run -d -v pgdata:/var/lib/postgresql/data postgres

# Check what volumes a container uses
docker inspect --format='{{json .Mounts}}' myapp | python3 -m json.tool

# For critical data: use bind mount for easy backup
docker run -d \
  -v /data/postgres:/var/lib/postgresql/data \
  -v /backups/postgres:/backups \
  postgres

# Backup running database without stopping
docker exec postgres pg_dumpall -U postgres | gzip > /backups/dump_$(date +%Y%m%d).sql.gz
```

---

### 🔴 ISSUE 12: Docker Compose Environment Variable Issues

**Symptoms:** Variables not being passed, wrong values, "variable not set" warnings

**Solutions:**
```bash
# Check what variables are resolved
docker compose config

# Variable substitution order (highest to lowest priority):
# 1. Shell environment variables
# 2. .env file
# 3. compose file defaults

# Specify env file explicitly
docker compose --env-file .env.production up

# Verify vars inside container
docker exec myapp env | sort
docker exec myapp printenv DB_HOST

# Debug: print compose config with resolved vars
docker compose --env-file .env.prod config | grep -A5 environment

# Required variable with error if missing
# In compose.yml: PORT: ${PORT:?PORT must be set}

# Variable with default
# In compose.yml: PORT: ${PORT:-8080}
```

---

### 🔴 ISSUE 13: Slow Docker Builds in CI/CD

**Solutions:**
```bash
# Use BuildKit (much faster, parallel builds)
DOCKER_BUILDKIT=1 docker build -t myapp .
# Or set in daemon.json: { "features": { "buildkit": true } }

# Cache from registry (pull cache layers before build)
docker pull myapp:latest || true
docker build --cache-from myapp:latest -t myapp:${BUILD_ID} -t myapp:latest .
docker push myapp:latest  # Push for next build's cache

# Inline cache with BuildKit
docker buildx build \
  --cache-from type=registry,ref=myregistry.com/myapp:cache \
  --cache-to type=registry,ref=myregistry.com/myapp:cache,mode=max \
  -t myapp:latest \
  --push .

# Multi-stage builds: minimize final image
# Stage 1: builder (has all build tools)
# Stage 2: production (only runtime)

# .dockerignore: exclude everything not needed
echo "node_modules\n.git\n*.md\ndocs\ntests\n.env*\nCoverage" > .dockerignore
```

---

### 🔴 ISSUE 14: Cannot Access Container Service from Host

**Symptoms:** `curl localhost:8080` fails but container is running

**Diagnosis:**
```bash
docker ps | grep 8080                    # Check port mapping
docker port myapp                        # View port mappings
netstat -tlnp | grep 8080               # Check host listener
ss -tlnp | grep 8080
docker inspect myapp | grep -A10 Ports
```

**Solutions:**
```bash
# Must expose port at run time (EXPOSE in Dockerfile is just documentation)
docker run -d -p 8080:8080 myapp         # Map all interfaces
docker run -d -p 127.0.0.1:8080:8080 myapp  # Localhost only
docker run -d -p 0.0.0.0:8080:8080 myapp    # Explicit all

# Expose all declared ports
docker run -d -P myapp                   # Random host ports

# App must listen on 0.0.0.0, NOT 127.0.0.1
# Wrong: app.listen(3000, '127.0.0.1')
# Right: app.listen(3000, '0.0.0.0')

# Check what the app is actually listening on
docker exec myapp netstat -tlnp
docker exec myapp ss -tlnp
```

---

### 🔴 ISSUE 15: Image Too Large (Bloated Images)

**Solutions:**
```bash
# Multi-stage builds (most effective)
# Stage 1: build
FROM node:18 AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN npm run build

# Stage 2: production (minimal)
FROM node:18-alpine AS production
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
EXPOSE 8080
CMD ["node", "dist/server.js"]

# Use slim/alpine variants
# ubuntu → ubuntu:22.04-slim  (~77MB)
# node:18 → node:18-alpine    (~120MB vs 1GB)
# python:3.11 → python:3.11-slim

# Remove build caches in same RUN command
RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential && \
    make build && \
    apt-get purge -y build-essential && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# Use dive to analyze layers
docker run --rm -it \
  -v /var/run/docker.sock:/var/run/docker.sock \
  wagoodman/dive:latest myapp:latest

# Analyze image size
docker history myapp:latest | sort -k5 -rh | head -20
```

---

## 11. Dockerfile Best Practices

### Production-Hardened Multi-Stage Dockerfile
```dockerfile
# ──────────────────────────────────────────
# Stage 1: Dependencies
# ──────────────────────────────────────────
FROM node:18-alpine AS deps
WORKDIR /app

# Install only production deps
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

# ──────────────────────────────────────────
# Stage 2: Builder
# ──────────────────────────────────────────
FROM node:18-alpine AS builder
WORKDIR /app

COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# ──────────────────────────────────────────
# Stage 3: Production
# ──────────────────────────────────────────
FROM node:18-alpine AS production

# Security: add non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodeapp -u 1001 -G nodejs

WORKDIR /app

# Copy only what's needed
COPY --from=deps --chown=nodeapp:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nodeapp:nodejs /app/dist ./dist

# Security labels
LABEL maintainer="devops@company.com"
LABEL version="1.0.0"
LABEL org.opencontainers.image.source="https://github.com/company/myapp"

# Set secure defaults
ENV NODE_ENV=production
ENV PORT=8080

# Don't run as root
USER nodeapp

EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD wget -q --spider http://localhost:8080/health || exit 1

# Use exec form (signals handled correctly)
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "dist/server.js"]
```

---

## 12. Docker Swarm / Orchestration

```bash
# Initialize swarm
docker swarm init --advertise-addr 192.168.1.100

# Join as worker
docker swarm join --token SWMTKN-xxx 192.168.1.100:2377

# Join as manager
docker swarm join-token manager

# Deploy stack
docker stack deploy -c docker-compose.prod.yml myapp

# List stacks and services
docker stack ls
docker stack services myapp
docker stack ps myapp

# Scale service
docker service scale myapp_web=5

# Rolling update
docker service update \
  --image myapp:2.0 \
  --update-parallelism 2 \
  --update-delay 30s \
  --update-failure-action rollback \
  myapp_web

# Rollback service
docker service rollback myapp_web

# Service logs
docker service logs -f myapp_web

# Node management
docker node ls
docker node inspect worker-01
docker node update --availability drain worker-01   # Drain before maintenance
docker node update --availability active worker-01  # Bring back

# Secrets in swarm
echo "dbpassword" | docker secret create db_pass -
docker service create \
  --secret db_pass \
  --name app myapp
# Secret available at /run/secrets/db_pass inside container
```

---

## 13. Debugging & Troubleshooting

### Essential Debug Commands
```bash
# Get full container details
docker inspect myapp

# Check resource usage
docker stats --no-stream myapp

# Check running processes
docker exec myapp ps auxf
docker exec myapp top -b -n1

# Check open files and connections
docker exec myapp lsof -i
docker exec myapp netstat -tlnp

# Check disk usage inside container
docker exec myapp df -h
docker exec myapp du -sh /app/*

# Check environment variables
docker exec myapp env | sort

# Check open file descriptors
docker exec myapp ls -la /proc/1/fd | wc -l

# Trace system calls (advanced)
docker run --cap-add=SYS_PTRACE myapp strace -p 1

# Debug networking
docker exec myapp curl -v http://other-service:8080/health
docker exec myapp nslookup other-service
docker exec myapp traceroute other-service

# Check container filesystem changes
docker diff myapp         # A=added, C=changed, D=deleted

# Export container filesystem
docker export myapp | tar -tv | head -50

# Create image from running container (debugging)
docker commit myapp myapp:debug
docker run -it myapp:debug bash

# Run debug sidecar alongside production container
docker run -it --network=container:myapp --pid=container:myapp \
  nicolaka/netshoot  # Packed with network debugging tools

# Get container's cgroup info
docker inspect --format='{{.HostConfig.CgroupParent}}' myapp

# Check Docker daemon logs
journalctl -u docker.service -f
journalctl -u docker.service --since="1 hour ago"

# Verify Docker daemon config
docker info
cat /etc/docker/daemon.json

# Docker system events (all events for last hour)
docker events --since=1h

# Clean slate troubleshooting
docker run --rm -it --network=host \
  nicolaka/netshoot bash
```

---

## 🔧 Quick Reference Card

| Task | Command |
|------|---------|
| Build image | `docker build -t name:tag .` |
| Run container | `docker run -d -p host:container --name x image` |
| Shell into container | `docker exec -it name bash` |
| View logs | `docker logs -f --tail=100 name` |
| Resource stats | `docker stats --no-stream` |
| Stop gracefully | `docker stop -t 30 name` |
| Remove all unused | `docker system prune -a` |
| Inspect container | `docker inspect name` |
| Copy files | `docker cp name:/path ./local` |
| Check health | `docker inspect --format='{{.State.Health.Status}}' name` |
| Update limits | `docker update --memory=1g --cpus=2 name` |
| Check disk use | `docker system df -v` |
| Port mappings | `docker port name` |
| Network inspect | `docker network inspect netname` |
| Follow events | `docker events --filter "container=name"` |
| Image layers | `docker history --no-trunc name` |

---

## 🚀 daemon.json Production Template

```json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "50m",
    "max-file": "5"
  },
  "storage-driver": "overlay2",
  "features": {
    "buildkit": true
  },
  "default-ulimits": {
    "nofile": {
      "Hard": 65536,
      "Name": "nofile",
      "Soft": 65536
    }
  },
  "live-restore": true,
  "max-concurrent-downloads": 10,
  "max-concurrent-uploads": 5,
  "mtu": 1450,
  "userland-proxy": false,
  "metrics-addr": "0.0.0.0:9323",
  "experimental": false
}
```

> **Apply changes:** `sudo systemctl restart docker`
> With `live-restore: true`, running containers won't stop on daemon restart!

---

*Last updated: June 2025 | Docker Engine 26.x*
