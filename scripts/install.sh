#!/bin/bash
set -e

APP_NAME="udp_custom"
GITHUB_REPO="NNdroid/${APP_NAME}"
# Optional: pin to a release tag, e.g. v1.0.20260904-1a2b3c4.
# Leave empty to fetch the latest GitHub Release.
APP_VERSION="${APP_VERSION:-}"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/${APP_NAME}"
SYSTEMD_DIR="/etc/systemd/system"
SERVICE_FILE="${SYSTEMD_DIR}/${APP_NAME}.service"

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
CYAN="\033[36m"
PLAIN="\033[0m"

check_root() {
  if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Please run as root (sudo)!${PLAIN}" >&2
    exit 1
  fi
}

get_arch() {
  local arch
  arch=$(uname -m)
  case "${arch}" in
    x86_64)  echo "amd64" ;;
    aarch64) echo "arm64" ;;
    armv7l)  echo "arm" ;;
    i386|i686) echo "386" ;;
    *)
      echo -e "${RED}Unsupported CPU architecture: ${arch}${PLAIN}" >&2
      return 1
      ;;
  esac
}

validate_app_version() {
  if [ -n "${APP_VERSION}" ] && ! [[ "${APP_VERSION}" =~ ^v1\.0\.[0-9]{8}-[0-9a-f]{7}$ ]]; then
    echo -e "${RED}APP_VERSION must be v1.0.yyyyMMdd-<7-character-git-hash>.${PLAIN}" >&2
    exit 1
  fi
}

# 生成分享 URI 时的额外参数：
#   GEN_URI_PIN   —— 指定固定的 6 位分享 PIN（默认留空=每次随机生成，需在输出中抄下）。
#   GEN_URI_HOST  —— 覆盖分享 URI 中的服务器公网 IP/域名（server 配置通常只有 listen 端口，
#                     不包含公网地址；不设置时占位为 your-server-ip，客户端无法连接）。
gen_uri_extra_args() {
  local args=""
  if [ -n "${GEN_URI_PIN:-}" ]; then
    args="${args} -pin ${GEN_URI_PIN}"
  fi
  if [ -n "${GEN_URI_HOST:-}" ]; then
    args="${args} -host ${GEN_URI_HOST}"
  fi
  echo "${args}"
}

install_binary() {
  local goarch
  validate_app_version
  goarch=$(get_arch)
  mkdir -p "${INSTALL_DIR}"

  if [ -f "./bin/${APP_NAME}_linux_${goarch}" ]; then
    echo -e "${CYAN}--> Using local prebuilt binary (linux/${goarch})...${PLAIN}"
    cp "./bin/${APP_NAME}_linux_${goarch}" "${INSTALL_DIR}/${APP_NAME}"
  elif [ -f "./${APP_NAME}" ]; then
    echo -e "${CYAN}--> Using local binary...${PLAIN}"
    cp "./${APP_NAME}" "${INSTALL_DIR}/${APP_NAME}"
  elif command -v go >/dev/null 2>&1 && [ -f "./main.go" ]; then
    echo -e "${CYAN}--> Building from source with Go...${PLAIN}"
    local source_version
    source_version="v1.0.$(date -u +%Y%m%d)-$(git rev-parse --short=7 HEAD 2>/dev/null || printf 'local')"
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.Version=${source_version}" -o "${INSTALL_DIR}/${APP_NAME}" .
  else
    echo -e "${CYAN}--> Downloading release binary (${goarch})...${PLAIN}"
    local download_url
    if [ -n "${APP_VERSION}" ]; then
      download_url="https://github.com/${GITHUB_REPO}/releases/download/${APP_VERSION}/${APP_NAME}_linux_${goarch}"
    else
      download_url="https://github.com/${GITHUB_REPO}/releases/latest/download/${APP_NAME}_linux_${goarch}"
    fi
    if ! curl -fsSL "${download_url}" -o "${INSTALL_DIR}/${APP_NAME}"; then
      echo -e "${RED}Failed to download release binary from GitHub!${PLAIN}"
      exit 1
    fi
  fi

  chmod +x "${INSTALL_DIR}/${APP_NAME}"
  echo -e "${GREEN}--> Binary installed to ${INSTALL_DIR}/${APP_NAME}${PLAIN}"
  "${INSTALL_DIR}/${APP_NAME}" version 2>/dev/null || true
}

get_config_file() {
  local mode="$1"
  if [ "${mode}" == "client" ]; then
    echo "${CONFIG_DIR}/config.client.json"
  else
    echo "${CONFIG_DIR}/config.server.json"
  fi
}

install_config() {
  local mode="$1"
  local config_file
  config_file=$(get_config_file "${mode}")
  mkdir -p "${CONFIG_DIR}"

  if [ ! -f "${config_file}" ]; then
    if [ "${mode}" == "client" ]; then
      if [ -f "./config.client.json" ]; then
        cp "./config.client.json" "${config_file}"
      else
        echo -e "${CYAN}--> Fetching config.client.json from GitHub...${PLAIN}"
        curl -fsSL "https://raw.githubusercontent.com/${GITHUB_REPO}/master/config.client.json" -o "${config_file}" || true
      fi
    else
      if [ -f "./config.server.json" ]; then
        cp "./config.server.json" "${config_file}"
      else
        echo -e "${CYAN}--> Fetching config.server.json from GitHub...${PLAIN}"
        curl -fsSL "https://raw.githubusercontent.com/${GITHUB_REPO}/master/config.server.json" -o "${config_file}" || true
      fi
    fi
    echo -e "${GREEN}--> Created ${mode} configuration at ${config_file}${PLAIN}"
  else
    echo -e "${YELLOW}--> Existing configuration preserved at ${config_file}${PLAIN}"
  fi
}

install_systemd() {
  local mode="$1"
  local config_file
  config_file=$(get_config_file "${mode}")
  local desc="UDPCustom Stream Tunnel Server"
  if [ "${mode}" == "client" ]; then
    desc="UDPCustom Stream Tunnel Client"
  fi

  cat <<EOF > "${SERVICE_FILE}"
[Unit]
Description=${APP_NAME} ${desc}
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${CONFIG_DIR}
ExecStart=${INSTALL_DIR}/${APP_NAME} -c ${config_file}
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=3s
LimitNOFILE=1048576
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "${APP_NAME}" >/dev/null 2>&1 || true
  echo -e "${GREEN}--> Systemd service registered: ${APP_NAME}.service (${mode} mode)${PLAIN}"
}

do_install() {
  local mode="${1:-server}"
  local config_file
  config_file=$(get_config_file "${mode}")

  check_root
  echo -e "${GREEN}========================================${PLAIN}"
  echo -e "${GREEN}  Installing ${APP_NAME} (${mode} mode)...${PLAIN}"
  echo -e "${GREEN}========================================${PLAIN}"

  install_binary
  install_config "${mode}"
  install_systemd "${mode}"

  systemctl restart "${APP_NAME}" || true

  echo ""
  echo -e "${GREEN}=== Installation Complete (${mode} mode)! ===${PLAIN}"
  echo -e "Configuration: ${CYAN}${config_file}${PLAIN}"
  echo -e "Service Name:  ${CYAN}${APP_NAME}${PLAIN}"
  echo -e "Start:         ${CYAN}systemctl start ${APP_NAME}${PLAIN}"
  echo -e "Status:        ${CYAN}systemctl status ${APP_NAME}${PLAIN}"
  echo -e "View Logs:     ${CYAN}journalctl -u ${APP_NAME} -f${PLAIN}"
  echo ""

  if [ "${mode}" != "client" ]; then
    echo -e "${GREEN}=== Stun Node Sharing URI & QR ===${PLAIN}"
    "${INSTALL_DIR}/${APP_NAME}" gen-uri -c "${config_file}" $(gen_uri_extra_args) || true
    if [ -n "${GEN_URI_PIN:-}" ]; then
      echo -e "${YELLOW}    Share PIN (via GEN_URI_PIN): ${GEN_URI_PIN}${PLAIN}"
    else
      echo -e "${YELLOW}    A random PIN was printed above — note it to import the URI.${PLAIN}"
    fi
  fi
}

do_upgrade() {
  check_root
  echo -e "${YELLOW}========================================${PLAIN}"
  echo -e "${YELLOW}  Upgrading ${APP_NAME}...${PLAIN}"
  echo -e "${YELLOW}========================================${PLAIN}"

  install_binary
  systemctl daemon-reload
  systemctl restart "${APP_NAME}" || true

  echo -e "${GREEN}=== Upgrade Completed! Service restarted. ===${PLAIN}"
  "${INSTALL_DIR}/${APP_NAME}" version || true
}

do_uninstall() {
  check_root
  echo -e "${RED}========================================${PLAIN}"
  echo -e "${RED}  Uninstalling ${APP_NAME}...${PLAIN}"
  echo -e "${RED}========================================${PLAIN}"

  systemctl stop "${APP_NAME}" >/dev/null 2>&1 || true
  systemctl disable "${APP_NAME}" >/dev/null 2>&1 || true
  rm -f "${SERVICE_FILE}"
  systemctl daemon-reload

  rm -f "${INSTALL_DIR}/${APP_NAME}"

  echo -e "${GREEN}--> Binary and service removed.${PLAIN}"
  echo -e "${YELLOW}Note: Configuration directory (${CONFIG_DIR}) was kept for safety.${PLAIN}"
  echo -e "To delete configuration permanently: ${CYAN}rm -rf ${CONFIG_DIR}${PLAIN}"
  echo -e "${GREEN}=== ${APP_NAME} Uninstalled Successfully! ===${PLAIN}"
}

do_start() {
  check_root
  systemctl start "${APP_NAME}"
  echo -e "${GREEN}${APP_NAME} started.${PLAIN}"
}

do_stop() {
  check_root
  systemctl stop "${APP_NAME}"
  echo -e "${YELLOW}${APP_NAME} stopped.${PLAIN}"
}

do_restart() {
  check_root
  systemctl restart "${APP_NAME}"
  echo -e "${GREEN}${APP_NAME} restarted.${PLAIN}"
}

do_status() {
  systemctl status "${APP_NAME}"
}

do_logs() {
  journalctl -u "${APP_NAME}" -f -n 50
}

do_uri() {
  local config_file="${CONFIG_DIR}/config.server.json"
  if [ ! -f "${config_file}" ]; then
    config_file="${CONFIG_DIR}/config.json"
  fi
  "${INSTALL_DIR}/${APP_NAME}" gen-uri -c "${config_file}" $(gen_uri_extra_args)
}

action="${1:-install}"
target_mode="${2:-server}"

case "${action}" in
  server)
    action="install"
    target_mode="server"
    ;;
  client)
    action="install"
    target_mode="client"
    ;;
  install-server)
    action="install"
    target_mode="server"
    ;;
  install-client)
    action="install"
    target_mode="client"
    ;;
esac

case "${action}" in
  install)
    do_install "${target_mode}"
    ;;
  upgrade|update)
    do_upgrade
    ;;
  uninstall|remove)
    do_uninstall
    ;;
  start)
    do_start
    ;;
  stop)
    do_stop
    ;;
  restart)
    do_restart
    ;;
  status)
    do_status
    ;;
  logs|log)
    do_logs
    ;;
  uri|qr)
    do_uri
    ;;
  *)
    echo "Usage: $0 {install [server|client]|upgrade|uninstall|start|stop|restart|status|logs|uri}"
    exit 1
    ;;
esac
