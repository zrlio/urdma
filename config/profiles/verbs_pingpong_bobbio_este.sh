# Top source directory on local system---assumed to be git clone
TOP_SRCDIR=${HOME}/src/usiw

# Directory to deploy to
DEPLOY_DIR=usiw

# App executable
SERVER_APP=verbs_pingpong
CLIENT_APP=verbs_pingpong

# Management IP addresses
SERVER_NODE=bobbio
CLIENT_NODE=este

# DPDK IP address
SERVER_DPDK_IP=10.0.0.2
SERVER_DPDK_IP_PREFIX=24
CLIENT_DPDK_IP=10.0.0.1
CLIENT_DPDK_IP_PREFIX=24

# Show only INFO or higher priority log messages
DPDK_LOG_LEVEL=7
SERVER_LCORE_LAYOUT="0,1,2"
CLIENT_LCORE_LAYOUT="0,1,2"
SERVER_PORT="01:00.0"
CLIENT_PORT="01:00.0"

# Other arguments --- passed to client, *not* to EAL
SERVER_EXTRA_ARGS="-s 1024 -b 16 -c 5000000"
CLIENT_EXTRA_ARGS="-s 1024 -b 16 -c 5000000"
