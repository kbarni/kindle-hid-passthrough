# Justfile for Kindle HID Passthrough
# Usage: just <recipe>

src_dir := justfile_directory()
remote_dir := "/mnt/us/kindle_hid_passthrough"
upstart_conf := "/etc/upstart/hid-passthrough.conf"
log_file := "/var/log/hid_passthrough.log"
python := "/mnt/us/python3.10-kindle/python3-wrapper.sh"

default:
    @just --list

# Deploy to Kindle over SSH
deploy:
    @echo "Deploying to Kindle..."
    @echo "Stopping daemon..."
    -ssh kindle "initctl stop hid-passthrough" 2>/dev/null || true
    @echo "Remounting filesystems as writable..."
    ssh kindle "/usr/sbin/mntroot rw && mount -o remount,rw /mnt/base-us"
    @echo "Copying files..."
    scp {{src_dir}}/kindle_hid_passthrough/*.py kindle:{{remote_dir}}/
    scp {{src_dir}}/kindle_hid_passthrough/config.ini kindle:{{remote_dir}}/
    scp {{src_dir}}/kindle_hid_passthrough/hid-passthrough-dev.upstart kindle:{{upstart_conf}}
    @echo "Clearing Python bytecode cache..."
    ssh kindle "rm -rf {{remote_dir}}/__pycache__"
    @echo "Creating cache directory..."
    ssh kindle "mkdir -p {{remote_dir}}/cache"
    @echo "Deployment complete!"
    @echo ""
    @echo "Start daemon with: just start"
    -ssh kindle "initctl start hid-passthrough" 2>/dev/null || true
    @echo "View logs with: just logs"

# Check daemon status
status:
    ssh kindle "initctl status hid-passthrough"

# View daemon logs
logs:
    ssh kindle "tail -f {{log_file}}"

# View recent logs
logs-recent:
    ssh kindle "tail -n 50 {{log_file}}"

# Restart daemon
restart:
    ssh kindle "initctl restart hid-passthrough"

# Stop daemon
stop:
    ssh kindle "initctl stop hid-passthrough"

# Start daemon
start:
    ssh kindle "initctl start hid-passthrough"

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

# Remove autostart (removes upstart config)
remove-autostart:
    @echo "Removing autostart..."
    ssh kindle "/usr/sbin/mntroot rw"
    ssh kindle "rm -f {{upstart_conf}}"
    @echo "Autostart removed."
