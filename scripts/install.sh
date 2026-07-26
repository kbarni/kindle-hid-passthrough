#!/bin/sh

INSTALL_DIR="/mnt/us/kindle_hid_passthrough"

# True when the script is running from the install dir itself, so the
# cp commands below would be a no-op (source == destination).
in_install_dir()
{
  [ "$(cd "$(dirname "$0")/.." && pwd)" = "$INSTALL_DIR" ] || \
    [ "$(pwd)" = "$INSTALL_DIR" ]
}

installUdevRules()
{
  echo " -> Installing udev rules"
  /usr/sbin/mntroot rw
  cp assets/99-hid-keyboard.rules /etc/udev/rules.d
  /usr/sbin/udevadm control --reload-rules
  /usr/sbin/mntroot ro
  echo " -> Ready."
}

installUpstart()
{
  echo " -> Installing upstart service"
  /usr/sbin/mntroot rw
  cp assets/hid-passthrough.upstart /etc/upstart/hid-passthrough.conf
  /usr/sbin/mntroot ro
  echo " -> Ready."
}

pairDevice()
{
  ./kindle-hid-passthrough --pair 2>&1 | grep -v "libenvload.so"
}

listDevices()
{
  cat devices.conf
}

uninstallAll()
{
  echo ""
  echo "=== Uninstall ==="
  printf "This will stop the daemon, remove udev/upstart/WAF app, and delete the install directory.\n"
  printf "Continue? [y/N]: "
  read confirm
  case "$confirm" in
    y|Y|yes|YES) ;;
    *) echo "Aborted."; return ;;
  esac

  APP_ID="com.lzampier.btmanager"
  INSTALL_DIR="/mnt/us/kindle_hid_passthrough"
  SCRIPTLET_DEST="/mnt/us/documents/BTManager.sh"
  APPREG_DB="/var/local/appreg.db"

  echo " -> Stopping daemon"
  /sbin/stop hid-passthrough 2>/dev/null
  pkill -f "kindle-hid-passthrough" 2>/dev/null
  pkill -f "main.py --daemon" 2>/dev/null
  pkill -f "ld-linux-armhf." 2>/dev/null

  /usr/sbin/mntroot rw

  echo " -> Removing upstart config"
  rm -f /etc/upstart/hid-passthrough.conf

  echo " -> Removing udev rules"
  rm -f /etc/udev/rules.d/99-hid-keyboard.rules
  if [ -f /usr/local/bin/dev_is_keyboard.sh ]; then
    rm -f /usr/local/bin/dev_is_keyboard.sh
  fi
  /usr/sbin/udevadm control --reload-rules 2>/dev/null

  echo " -> Unregistering WAF app"
  if [ -f "$APPREG_DB" ]; then
    sqlite3 "$APPREG_DB" <<EOF 2>/dev/null
DELETE FROM properties WHERE handlerId='$APP_ID';
DELETE FROM associations WHERE handlerId='$APP_ID';
DELETE FROM handlerIds WHERE handlerId='$APP_ID';
EOF
  fi
  rm -f "$SCRIPTLET_DEST"

  /usr/sbin/mntroot ro

  echo " -> Removing install directory $INSTALL_DIR"
  cd /tmp
  rm -rf "$INSTALL_DIR"

  echo ""
  echo "Uninstall complete. Reboot recommended."
}

print_menu()
{
  printf "\nSelect an option:\n"
  printf " 1) Pair Bluetooth keyboard\n"
  printf " 2) List paired devices\n"
  printf " 3) Install udev rules (keyboard service)\n"
  printf " 4) Install upstart (auto-start on boot)\n"
  printf " 5) Uninstall everything\n"
  printf " 6) Quit\n"
}

# Non-interactive entry point: `sh install.sh <action>` runs one action and exits.
if [ $# -gt 0 ]; then
  case "$1" in
    installUdevRules)   installUdevRules; exit 0 ;;
    installUpstart)     installUpstart; exit 0 ;;
    uninstallAll)       uninstallAll; exit 0 ;;
    *) echo "Unknown action: $1" >&2; exit 1 ;;
  esac
fi

while :; do
  print_menu
  printf "Enter choice [1-6]: "
  read choice
  case "$choice" in
    1)
      pairDevice
      ;;
    2)
      listDevices
      ;;
    3)
      installUdevRules
      ;;
    4)
      installUpstart
      ;;
    5)
      uninstallAll
      ;;
    6)
      echo "Exiting."
      break
      ;;
    *)
      printf "Invalid option: %s\n" "$choice"
      ;;
  esac
done
