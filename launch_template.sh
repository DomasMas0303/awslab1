#!/bin/bash -xe
exec > >(tee /var/log/cloud-init-output.log | logger -t user-data -s 2>/dev/console) 2>&1

# Update this to match your ALB DNS name
LB_DNS_NAME='ghost-alb-377763628.eu-central-1.elb.amazonaws.com'

# Get the region from the instance metadata
REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone | sed 's/[a-z]$//')

# Set your EFS ID 
EFS_ID=$(aws efs describe-file-systems --query 'FileSystems[?Name==`ghost_content`].FileSystemId' --region $REGION --output text)

# Log the values for debugging
echo "REGION: $REGION"
echo "EFS_ID: $EFS_ID"

# Install pre-reqs
curl -sL https://rpm.nodesource.com/setup_14.x | sudo bash -
yum install -y nodejs amazon-efs-utils
npm install ghost-cli@latest -g

# Create ghost user and set up directory
adduser ghost_user
usermod -aG wheel ghost_user

# Create a unique directory for this installation
INSTALL_DIR="/home/ghost_user/ghost-install-$(date +%Y%m%d%H%M%S)"
mkdir -p $INSTALL_DIR
chown ghost_user:ghost_user $INSTALL_DIR

# Adjust permissions to make /home/ghost_user readable by others
chmod -R o+rx /home/ghost_user/

# Mount EFS
EFS_MOUNT_DIR="/mnt/efs"
mkdir -p $EFS_MOUNT_DIR
echo "${EFS_ID}:/ $EFS_MOUNT_DIR efs _netdev,tls,iam 0 0" >> /etc/fstab
mount -a

# Check if mount was successful
if ! mount | grep -q "$EFS_MOUNT_DIR"; then
    echo "EFS mount failed. Exiting."
    exit 1
fi

# Create content directory in EFS only if it doesn't exist
if [ ! -d "$EFS_MOUNT_DIR/content" ]; then
    mkdir -p $EFS_MOUNT_DIR/content
    chown -R ghost_user:ghost_user $EFS_MOUNT_DIR/content
    echo "Created content directory in EFS"
else
    echo "Content directory already exists in EFS"
fi

# Check if logs directory exists, create if it doesn't
if [ ! -d "$EFS_MOUNT_DIR/content/logs" ]; then
    mkdir -p $EFS_MOUNT_DIR/content/logs
    echo "Created logs directory"
else
    echo "Logs directory already exists"
fi

# Ensure correct permissions for the logs directory
chown ghost_user:ghost_user $EFS_MOUNT_DIR/content/logs
chmod 755 $EFS_MOUNT_DIR/content/logs

# Install Ghost
cd /home/ghost_user
sudo -u ghost_user ghost install 4.12.1 local --dir $INSTALL_DIR --no-setup-linux-user --no-setup-nginx --db sqlite3 --dbpath $EFS_MOUNT_DIR/content/ghost.db --url http://$LB_DNS_NAME

# Copy the Casper theme to EFS if it doesn't exist
if [ ! -d "$EFS_MOUNT_DIR/content/themes/casper" ]; then
    cp -R $INSTALL_DIR/content/themes/casper $EFS_MOUNT_DIR/content/themes/
    chown -R ghost_user:ghost_user $EFS_MOUNT_DIR/content/themes/casper
    echo "Copied Casper theme to EFS"
else
    echo "Casper theme already exists in EFS"
fi

# Create Ghost config
cat << EOF > $INSTALL_DIR/config.production.json
{
  "url": "http://${LB_DNS_NAME}",
  "server": {
    "port": 2368,
    "host": "0.0.0.0"
  },
  "database": {
    "client": "sqlite3",
    "connection": {
      "filename": "$EFS_MOUNT_DIR/content/ghost.db"
    }
  },
  "mail": {
    "transport": "Direct"
  },
  "logging": {
    "transports": [
      "file",
      "stdout"
    ]
  },
  "process": "systemd",
  "paths": {
    "contentPath": "$EFS_MOUNT_DIR/content"
  }
}
EOF

# Ensure correct ownership of the config file
chown ghost_user:ghost_user $INSTALL_DIR/config.production.json

# Create and configure the Ghost service file
cat << EOF > /etc/systemd/system/ghost.service
[Unit]
Description=Ghost Blog
After=network.target
[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
User=ghost_user
Environment=NODE_ENV=production
ExecStart=/usr/bin/ghost run
Restart=always
[Install]
WantedBy=multi-user.target
EOF

# Reload systemd to recognize the new service file
systemctl daemon-reload

# Stop any running Ghost service to free the port
if systemctl is-active --quiet ghost; then
    systemctl stop ghost
fi

# Ensure port 2368 is free
if lsof -i:2368; then
    echo "Port 2368 is already in use. Killing process..."
    fuser -k 2368/tcp
fi

# Enable and start the Ghost service
systemctl enable ghost
systemctl start ghost

echo "Ghost installation and setup completed successfully."
