#!/bin/sh

installDaemon()
{
  echo " -> Installing daemon"
  mntroot rw
  echo "    * Copying udev rules"
  cp assets/dev_is_keyboard.sh /usr/local/bin/
  cp assets/99-hid-keyboard.rules /etc/udev/rules.d
  echo "    * Enabling udev rules"
  udevadm control --reload-rules
  mntroot ro
  echo " -> Ready."
}

installUpstart()
{
  echo " -> Installing upstart service"
  mntroot rw
  cp assets/hid-passthrough-dev.upstart  /etc/upstart/hid-passthrough.conf
  mntroot ro
  echo " -> Ready."
}

installKUAL()
{
  echo " -> Installing KUAL menu"
  mkdir -p ../extensions/BT_Keyboard
  cp assets/config.xml ../extensions/BT_Keyboard/
  cp assets/menu.json ../extensions/BT_Keyboard/
  echo " -> Ready."
}

pairDevice()
{
  lipc-set-prop -s com.lab126.btfd BTenable 0:1
  ./kindle-hid-passthrough --pair
}

listDevices()
{
  cat devices.conf
}

setLayout()
{
  echo "This option will install a KUAL menu to switch to a custom keyboard layout"
  mkdir -p ../extensions/BT_Keyboard
  cp assets/menu_setlayout.json ../extensions/BT_Keyboard/menu.json
  printf "Enter layout code (e.g. fr, de, 'fr(oss)'): "
  read layout
  sed -i "s/CUSTOMLAYOUT/$layout/g" ../extensions/BT_Keyboard/menu.json
}

print_menu()
{
  printf "\nSelect an option:\n"
  printf " 1) Pair Bluetooth keyboard\n"
  printf " 2) List paired devices\n"
  printf " 3) Install service\n"
  printf " 4) Install upstart - installs a service running continuously\n"
  printf " 5) Install KUAL menu\n"
  printf " 6) Set custom keyboard layout\n"
  printf " 7) Quit\n"
}

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
      installUpstart
      ;;
    4)
      installDaemon
      ;;
    5)
      installKUAL
      ;;
    6)
      setLayout
      ;;
    7)
      echo "Exiting."
      break
      ;;
    *)
      printf "Invalid option: %s\n" "$choice"
      ;;
  esac
done
