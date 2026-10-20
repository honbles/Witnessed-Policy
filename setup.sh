#!/bin/bash
# One-time setup on Ubuntu/Debian (run as root or with sudo).  Needs ~2 GB disk.
set -e
cd "$(dirname "$0")"
apt-get update
apt-get install -y python3 python3-pip python3-venv default-jre-headless iproute2 nftables wireguard-tools wireguard-go apparmor-utils strace iputils-ping curl zip unzip texlive-latex-recommended texlive-latex-extra texlive-publishers texlive-science texlive-fonts-recommended
pip3 install --break-system-packages -r requirements.txt 2>/dev/null || pip3 install -r requirements.txt
[ -f tla2tools.jar ] || curl -L -o tla2tools.jar https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar
python3 -c "import cryptography, matplotlib; print('python deps ok')"
java -version 2>&1 | head -1; which wireguard-go nft ip wg; . ./wg_unconfine.sh
echo "kernel: $(uname -r); netem: $(modprobe sch_netem 2>&1 && echo yes || echo 'no (application-level delay is used)')"
echo "setup done"
