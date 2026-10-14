#!/bin/sh
# Build an isolated scanner runtime. Its loader and libraries travel together,
# so native nodes do not need distro-specific YARA/ClamAV package installation.
set -eu
mkdir -p /native/tools/lib /native/tools/bin /native/licenses
cp /usr/local/bin/webscan /native/webscan
for tool in yara clamdscan; do
  source=$(command -v "$tool")
  cp -L "$source" "/native/tools/lib/$tool"
  ldd "$source" | awk '$3 ~ /^\// {print $3} $1 ~ /^\// {print $1}' | while read -r library; do cp -L "$library" /native/tools/lib/; done
  cat > "/native/tools/bin/$tool" <<WRAPPER
#!/bin/sh
set -eu
TASK_TOOLS=\$(CDPATH= cd -- "\$(dirname -- "\$0")/.." && pwd)
exec "\$TASK_TOOLS/lib/ld-linux-x86-64.so.2" --library-path "\$TASK_TOOLS/lib" "\$TASK_TOOLS/lib/$tool" "\$@"
WRAPPER
  chmod 700 "/native/tools/bin/$tool"
done
# Preserve licensing for all bundled Debian dependencies.
for copyright in /usr/share/doc/*/copyright; do package=$(basename "$(dirname "$copyright")"); cp "$copyright" "/native/licenses/$package.txt"; done
chmod 700 /native/webscan
cd /native
./webscan version > VERSION
find . -type f ! -name SHA256SUMS -exec sha256sum '{}' \; | sort > SHA256SUMS
mkdir -p /usr/local/lib/webscan
tar -czf /usr/local/lib/webscan/agent-native.tar.gz .
