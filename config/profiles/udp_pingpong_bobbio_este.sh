# Top source directory on local system---assumed to be git clone
TOP_SRCDIR=${HOME}/src/usiw

# Directory to deploy to
DEPLOY_DIR=src/usiw

# App executable
SERVER_APP=udp_pingpong
CLIENT_APP=udp_pingpong

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
SERVER_LCORE_LAYOUT="0,1"
CLIENT_LCORE_LAYOUT="0,1"
SERVER_PORT="01:00.0"
CLIENT_PORT="01:00.0"

# Other arguments
SERVER_EXTRA_ARGS="-w ${SERVER_PORT} -l ${SERVER_LCORE_LAYOUT} --log-level ${DPDK_LOG_LEVEL} -d /usr/lib64/librte_pmd_i40e.so -- --disable-checksum-offload -s 1024 -b 16 -c 25000000 ${SERVER_DPDK_IP}/${SERVER_DPDK_IP_PREFIX}"
CLIENT_EXTRA_ARGS="-w ${CLIENT_PORT} -l ${CLIENT_LCORE_LAYOUT} --log-level ${DPDK_LOG_LEVEL} -d /usr/lib64/librte_pmd_i40e.so -- --disable-checksum-offload -s 1024 -b 16 -c 25000000 ${CLIENT_DPDK_IP}/${CLIENT_DPDK_IP_PREFIX}"
