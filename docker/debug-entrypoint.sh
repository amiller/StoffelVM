#!/bin/bash
# Run the node, capture everything, then keep serving the captured log on the
# one proxied port so a crash is readable from outside the CVM.
mkdir -p /tmp/www
/bin/bash /app/entrypoint.sh > /tmp/www/node.log 2>&1
echo "PROCESS-EXIT=$?" >> /tmp/www/node.log
exec /bin/busybox httpd -f -p 8090 -h /tmp/www
