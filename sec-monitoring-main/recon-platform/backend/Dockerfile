FROM node:20-alpine

# Install security recon tools
RUN apk add --no-cache \
    nmap \
    nmap-scripts \
    bind-tools \
    curl \
    wget \
    git \
    go \
    bash

# Install Go-based tools (subfinder, httpx, dnsx)
ENV GOPATH=/go
ENV PATH=$PATH:/go/bin

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || true
RUN go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest 2>/dev/null || true

WORKDIR /app
COPY package*.json ./
RUN npm install --production

COPY . .

EXPOSE 3001
CMD ["node", "server.js"]
