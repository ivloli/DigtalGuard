#!/bin/bash

# The command you want to add
workDir=$(cd $(dirname $0); pwd)
command="$workDir/DigitalGuardD"

# The user who should be able to run the command without a password
user="$(whoami)"

# Create a temporary file to hold the new sudoers rule
echo "$user ALL=(ALL) NOPASSWD: $command" > /tmp/sudoers_tmp

# Add the new rule to the sudoers file
sudo visudo -cf /tmp/sudoers_tmp
if [ $? -eq 0 ]; then
    sudo cp /tmp/sudoers_tmp /etc/sudoers.d/
else
    echo "Failed to validate sudoers file. Not making changes."
fi

# Clean up the temporary file
rm /tmp/sudoers_tmp
