# Justfile for Kindle HID Passthrough
# Usage: just <recipe>

src_dir := justfile_directory()
remote_dir := "/mnt/us/kindle_hid_passthrough"
init_script := "/etc/init.d/hid-passthrough"
log_file := "/var/log/hid_passthrough.log"
python := "/mnt/us/python3.10-kindle/python3-wrapper.sh"

default:
    @just --list

# Deploy to Kindle over SSH
deploy:
    @echo "Deploying to Kindle..."
    @echo "Stopping daemon..."
    -ssh kindle "{{init_script}} stop" 2>/dev/null || true
    @echo "Remounting filesystems as writable..."
    ssh kindle "/usr/sbin/mntroot rw && mount -o remount,rw /mnt/base-us"
    @echo "Copying files..."
    scp {{src_dir}}/kindle_hid_passthrough/*.py kindle:{{remote_dir}}/
    scp {{src_dir}}/kindle_hid_passthrough/config.ini kindle:{{remote_dir}}/
    scp {{src_dir}}/kindle_hid_passthrough/hid-passthrough.init kindle:{{init_script}}
    ssh kindle "chmod +x {{init_script}}"
    @echo "Clearing Python bytecode cache..."
    ssh kindle "rm -rf {{remote_dir}}/__pycache__"
    @echo "Creating cache directory..."
    ssh kindle "mkdir -p {{remote_dir}}/cache"
    @echo "Deployment complete!"
    @echo ""
    @echo "Start daemon with: just start"
    -ssh kindle "{{init_script}} start" 2>/dev/null || true
    @echo "View logs with: just logs"

# Check daemon status
status:
    ssh kindle "{{init_script}} status"

# View daemon logs
logs:
    ssh kindle "tail -f {{log_file}}"

# View recent logs
logs-recent:
    ssh kindle "tail -n 50 {{log_file}}"

# Restart daemon
restart:
    ssh kindle "{{init_script}} restart"

# Stop daemon
stop:
    ssh kindle "{{init_script}} stop"

# Start daemon
start:
    ssh kindle "{{init_script}} start"

# Clear cache
clear-cache:
    ssh kindle "rm -rf {{remote_dir}}/cache/*.json"
    @echo "Cache cleared!"

# Show cache
show-cache:
    ssh kindle "ls -lh {{remote_dir}}/cache/ 2>/dev/null || echo 'Empty'"

# Show configured devices
devices:
    @ssh kindle "cat {{remote_dir}}/devices.conf 2>/dev/null || echo 'No devices configured'"

# Edit devices.conf
edit-devices:
    ssh kindle "vi {{remote_dir}}/devices.conf"

# Show pairing keys
keys:
    @ssh kindle "cat {{remote_dir}}/cache/pairing_keys.json 2>/dev/null | python3 -m json.tool || echo 'No pairing keys'"

# SSH into Kindle
ssh:
    ssh kindle

# Check Python syntax
check:
    python3 -m py_compile {{src_dir}}/kindle_hid_passthrough/*.py
    @echo "All files compile OK!"

# Deploy and follow logs
deploy-watch: deploy
    @just logs

# Pair a new device (Classic)
pair-classic:
    ssh kindle "{{python}} {{remote_dir}}/main.py --pair --protocol classic"

# Pair a new device (BLE)
pair-ble:
    ssh kindle "{{python}} {{remote_dir}}/main.py --pair --protocol ble"

# Run manually (for debugging)
run:
    ssh kindle "{{python}} {{remote_dir}}/main.py"

# Remount root filesystem as read-write
[private]
remount-rw:
    @ssh kindle "mount -o remount,rw /"

# Remount root filesystem as read-only
[private]
remount-ro:
    @ssh kindle "mount -o remount,ro /"

# Setup autostart via Upstart
setup-autostart: remount-rw
    @echo "Setting up autostart..."
    scp {{src_dir}}/kindle_hid_passthrough/hid-passthrough.upstart kindle:/etc/upstart/hid-passthrough.conf
    @just remount-ro
    @echo "Autostart configured! Service will start on next boot."

# Remove autostart
remove-autostart: remount-rw
    @echo "Removing autostart..."
    ssh kindle "rm -f /etc/upstart/hid-passthrough.conf"
    @just remount-ro
    @echo "Autostart removed."
