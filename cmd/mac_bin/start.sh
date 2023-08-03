#!/bin/bash

# The command you want to add
workDir=$(cd $(dirname $0); pwd)
command="$workDir/DigitalGuardD"

# The user who should be able to run the command without a password
user="$(whoami)"

# Create a new sudoers rule
sudoline="$user ALL=(ALL) NOPASSWD: $command"

if grep -qe "^$sudoline$" "/private/etc/sudoers.d/sudoers_tmp";then
    sudo ./core -uname $(whoami)
    exit 0
fi

# Create a temporary file to hold the new sudoers rule
echo "$user ALL=(ALL) NOPASSWD: $command" > /tmp/sudoers_tmp

# Add the new rule to the sudoers file
osascript -e "do shell script \"visudo -cf /tmp/sudoers_tmp\" with administrator privileges"
if [ $? -eq 0 ]; then
    #sudo cp /tmp/sudoers_tmp /etc/sudoers.d/
    osascript -e "do shell script \"cp /tmp/sudoers_tmp /etc/sudoers.d/\" with administrator privileges"
else
    echo "Failed to validate sudoers file. Not making changes."
fi

# Clean up the temporary file
rm /tmp/sudoers_tmp

sudo ./DigitalGuardD -uname $(whoami)
