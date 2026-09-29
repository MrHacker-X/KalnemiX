# !/bin/bash
# https://github.com/MrHacker-X
# Created By MrHacker-X

clear
cat core/banr.txt
# Detect the operating system
if [ -d "/data/data/com.termux/files/" ]; then
  echo
  echo -e "\033[1;31m[+]\033[1;32m Installing for Termux..."
  echo
  apt update -y
  apt upgrade -y
  apt update -y
  apt upgrade -y
  apt update -y
  apt upgrade -y
  apt install python -y
  apt install python-pip -y
  apt install whois -y
  apt install nmap -y
  apt install openssl -y
  apt install sslscan -y
  apt install dnsutils -y
  apt install traceroute -y
  apt install exiftool -y
  apt install libcap -y
  pip install bs4
  pip install requests
  pip install python-nmap
  pip install dnspython
  pip install html5lib
  echo 
  echo -e "\033[1;31m[+]\033[1;32m Setting up envirenment..."
  echo
  rm /data/data/com.termux/files/usr/lib/python3.11/site-packages/dns/resolver.py
  cp core/resolver.py /data/data/com.termux/files/usr/lib/python3.11/site-packages/dns
  termux-setup-storage
  echo -e "\033[1;31m[+]\033[1;32m Installation is completed."
  echo -e "\033[1;31m[+]\033[1;32m type command \033[1;31mpython kalnemix.py\033[1;32m to launch the tool."
  echo
else
  echo
  echo -e "\033[1;31m[+]\033[1;32m Installing for Linux..."
  echo
  sudo apt-get update -y
  sudo apt-get upgrade -y
  sudo apt-get install python3 -y
  sudo apt-get install python3-pip -y
  sudo apt-get install whois -y
  sudo apt-get install openssl -y
  sudo apt-get install sslscan -y
  sudo apt-get install nmap -y
  sudo apt-get install traceroute -y
  sudo apt-get install libimage-exiftool-perl -y
  sudo apt-get install exiftool -y
  sudo apt-get install dnsutils -y
  pip3 install bs4
  pip3 install python-nmap
  pip3 install requests
  pip3 install html5lib
  pip3 install dnspython
  echo 
  echo -e "\033[1;31m[+]\033[1;32m Installation is completed."
  echo -e "\033[1;31m[+]\033[1;32m type command \033[1;31msudo python kalnemix.py\033[1;32m to launch the tool."
  echo

fi