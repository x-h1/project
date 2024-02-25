#!/bin/bash
clear
sysctl -w net.ipv6.conf.all.disable_ipv6=1 
sysctl -w net.ipv6.conf.default.disable_ipv6=1 && apt update 
date=$(date -R | cut -d " " -f -5)
wget -q https://raw.githubusercontent.com/x-h1/project/master/github -O /root/.gh
date=$(date +"%Y-%m-%d")
red='\e[1;31m'
green='\e[1;32m'
yell='\e[1;33m'
tyblue='\e[1;36m'
Blue="\033[1;36"
NC='\e[0m'
purple() { echo -e "\\033[35;1m${*}\\033[0m"; }
tyblue() { echo -e "\\033[36;1m${*}\\033[0m"; }
yellow() { echo -e "\\033[33;1m${*}\\033[0m"; }
green() { echo -e "\\033[32;1m${*}\\033[0m"; }
redd() { echo -e "\\033[31;1m${*}\\033[0m"; }
function checking_vps() {
if [ "${EUID}" -ne 0 ]; then
print_error "You need to run this script as root"
exit 1
fi
if [ "$(systemd-detect-virt)" == "openvz" ]; then
print_error "OpenVZ is not supported"
exit 1
fi
if [ -f "/etc/xray/domain" ]; then
print_error "Script Already Installed"
exit 1
fi
if [[ $( uname -m | awk '{print $1}' ) == "x86_64" ]]; then
echo -e ""
else
echo -e "${EROR} Your Architecture Is Not Supported ( ${YELLOW}$( uname -m )${NC} )"
exit 1
fi
# // Checking OS
if [[ $( cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g' ) == "ubuntu" ]]; then
echo -e ""
elif [[ $( cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g' ) == "debian" ]]; then
echo -e ""
else
print_error "${EROR} Your OS Is Not Supported ( ${YELLOW}$( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g' )${NC} )"
exit 1
fi
if [ ! -d /root/.info ]; then
mkdir -p /root/.info
curl "ipinfo.io/org?token=7a814b6263b02c" > /root/.info/.isp
curl "ipinfo.io/city?token=7a814b6263b02c" > /root/.info/.city
curl "ipinfo.io/region?token=7a814b6263b02c" > /root/.info/.region
curl "ipinfo.io/timezone?token=7a814b6263b02c" > /root/.info/.timezone
fi
}
checking_vps
source /root/.gh
localip=$(hostname -I | cut -d\  -f1)
hst=( `hostname` )
dart=$(cat /etc/hosts | grep -w `hostname` | awk '{print $2}')
if [[ "$hst" != "$dart" ]]; then
echo "$localip $(hostname)" >> /etc/hosts
fi
secs_to_human() {
    echo "Installation time : $(( ${1} / 3600 )) hours $(( (${1} / 60) % 60 )) minute's $(( ${1} % 60 )) seconds"
}
start=$(date +%s)
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1
# Membuat Dictory 
mkdir -p /etc/xray
mkdir -p /etc/xray/trojan
mkdir -p /etc/xray/vless
mkdir -p /etc/xray/vmess
mkdir -p /etc/xray/limit
mkdir -p /etc/xray/limit/trojan
mkdir -p /etc/xray/limit/vless
mkdir -p /etc/xray/limit/vmess
mkdir -p /etc/xray/limit/ssh
mkdir -p /etc/xray/limit/ssh/ip
mkdir -p /etc/xray/limit/trojan/ip
mkdir -p /etc/xray/limit/trojan/quota
mkdir -p /etc/xray/limit/vless/ip
mkdir -p /etc/xray/limit/vless/quota
mkdir -p /etc/xray/limit/vmess/ip
mkdir -p /etc/xray/limit/vmess/quota
mkdir -p /var/lib/xdxl >/dev/null 2>&1
echo "IP=" >> /var/lib/xdxl/ipvps.conf
touch /etc/xray/domain
# Install Paket Yg Dibutuhkan
apt update -y
apt upgrade -y
apt dist-upgrade -y
apt install sudo -y
sudo apt-get clean all
sudo apt-get install -y debconf-utils
apt-get remove --purge ufw firewalld -y
apt-get remove --purge exim4 -y
apt-get autoremove -y
apt install haproxy -y

apt-get remove --purge ufw firewalld -y
apt-get remove --purge exim4 -y
sudo apt-get install -y --no-install-recommends software-properties-common
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
sudo apt-get install -y iptables iptables-persistent netfilter-persistent figlet ruby php php-fpm php-cli php-mysql libxml-parser-perl squid nmap screen jq bzip2 gzip coreutils rsyslog iftop htop zip unzip net-tools sed gnupg gnupg1 bc apt-transport-https build-essential dirmngr libxml-parser-perl screenfetch lsof openssl openvpn easy-rsa fail2ban tmux stunnel4 squid3 dropbear socat cron bash-completion ntpdate xz-utils apt-transport-https gnupg2 dnsutils lsb-release chrony libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison make libnss3-tools libevent-dev xl2tpd pptpd apt git speedtest-cli p7zip-full
sudo apt-get install -y libjpeg-dev zlib1g-dev python python3 python3-pip shc build-essential speedtest-cli p7zip-full nodejs nginx
gem install lolcat
sudo apt-get autoclean -y >/dev/null 2>&1
audo apt-get -y --purge removd unscd >/dev/null 2>&1
sudo apt-get -y --purge remove samba* >/dev/null 2>&1
sudo apt-get -y --purge remove apache2* >/dev/null 2>&1
sudo apt-get -y --purge remove bind9* >/dev/null 2>&1
sudo apt-get -y remove sendmail* >/dev/null 2>&1
apt autoremove -y >/dev/null 2>&1
# Install Vnstat
sudo apt-get -y install vnstat
/etc/init.d/vnstat restart
apt -y install libsqlite3-dev
wget https://humdi.net/vnstat/vnstat-2.6.tar.gz
tar zxvf vnstat-2.6.tar.gz
cd vnstat-2.6
./configure --prefix=/usr --sysconfdir=/etc && make && make install
cd
vnstat -u -i $NET
sed -i 's/Interface "'""eth0""'"/Interface "'""$NET""'"/g' /etc/vnstat.conf
chown vnstat:vnstat /var/lib/vnstat -R
systemctl enable vnstat
/etc/init.d/vnstat restart
rm -f /root/vnstat-2.6.tar.gz
rm -rf /root/vnstat-2.6
# Installasi Monitor Gotop
curl https://raw.githubusercontent.com/xxxserxxx/gotop/master/scripts/download.sh | bash && chmod +x gotop && sudo mv gotop /usr/local/bin/
# > Buat swap sebesar 1GB
dd if=/dev/zero of=/swapfile bs=1024 count=1048576
mkswap /swapfile
chown root:root /swapfile
chmod 0600 /swapfile >/dev/null 2>&1
swapon /swapfile >/dev/null 2>&1
sed -i '$ i\/swapfile      swap swap   defaults    0 0' /etc/fstab
# > Singkronisasi jam
chronyd -q 'server 0.id.pool.ntp.org iburst'
chronyc sourcestats -v
chronyc tracking -v
wget ${GITHUB_REPO}/bbr.sh
chmod +x bbr.sh ; ./bbr.sh
rm -rf bbr.sh
clear
# Setup Domain
echo -e "$yell----------------------------------------------------------$NC"
echo -e "$Blue                     SETUP DOMAIN VPS     $NC"
echo -e "$yell----------------------------------------------------------$NC"
echo -e "$green 1. Use Domain Random / Menggunakan Domain Random $NC"
echo -e "$green 2. Choose Your Own Domain / Menggunakan Domain Sendiri $NC"
echo -e "$yell----------------------------------------------------------$NC"
read -rp " Pilih Opsi Dari ( 1 - 2 ) : " dns
if test $dns -eq 1; then
clear
wget -q -O cf "${GITHUB_REPO}/cf" >/dev/null 2>&1
chmod 777 cf && ./cf
elif test $dns -eq 2; then
clear
echo -e "\e[1;33mSEBELUM MEMASUKAN DOMAIN, HARAP POINTING DULU IP VPS KAMU !\e[0m"
echo ""
read -rp "Masukan Domain Kamu : " pp
echo "$pp" > /etc/xray/domain
echo "$pp" > /root/domain
echo "IP=$pp" > /var/lib/xdxl/ipvps.conf
fi
clear 
echo -e "─────────────────────────────────────────"
echo -e " \E[41;1;97m            Install SSH WS             $NC"
echo -e "─────────────────────────────────────────"
sleep 2
wget -q ${GITHUB_REPO}/ins-ssh ; chmod +x ins-ssh ; ./ins-ssh
clear
echo -e "─────────────────────────────────────────"
echo -e " \E[41;1;97m              Install Xray             $NC"
echo -e "─────────────────────────────────────────"
sleep 2
wget -q ${GITHUB_REPO}/ins-xray ; chmod +x ins-xray ; ./ins-xray
clear
echo -e "─────────────────────────────────────────"
echo -e " \E[41;1;97m              Install Menu             $NC"
echo -e "─────────────────────────────────────────"
sleep 2
cd
wget ${GITHUB_REPO}/project.zip
unzip project.zip
chmod 777 project/*
mv project/* /usr/local/sbin
cd
cd /usr/local/bin
wget ${GITHUB_REPO}/ws.zip
unzip ws.zip
chmod 777 /usr/local/bin/ws-dropbear
chmod 777 /usr/local/bin/ws-stunnel
rm -rf /root/project
rm -rf project.zip
rm -rf ws.zip
cd
#rm -rf /tmp/menu
#wget -O /tmp/menu.zip "${GITHUB_REPO}/project.zip" >/dev/null 2>&1
#mkdir /tmp/menu
#7z e -pFadlyvpnprojek213 /tmp/menu.zip -o/tmp/menu/ >/dev/null 2>&1
#chmod +x /tmp/menu/*
#mv /tmp/menu/* /usr/local/sbin/
clear
echo -e "─────────────────────────────────────────"
echo -e " \E[41;1;97m              Install BACKUP           $NC"
echo -e "─────────────────────────────────────────"
sleep 2
apt install rclone -y > /dev/null 2>&1
printf "q\n" | rclone config
wget -O /root/.config/rclone/rclone.conf "${GITHUB_REPO}/rclone.conf"
git clone  https://github.com/magnific0/wondershaper.git
cd wondershaper
make install
cd
rm -rf wondershaper
echo > /home/limit
apt install msmtp-mta ca-certificates bsd-mailx -y
cat<<EOF>>/etc/msmtprc
defaults
tls on
tls_starttls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt

account default
host smtp.gmail.com
port 587
auth on
user hanskorbackup9@gmail.com
from hanskorbackup9@gmail.com
password wbgqpokjbkkjjiet
logfile ~/.msmtp.log
EOF
chown -R www-data:www-data /etc/msmtprc
cd
clear
echo -e "─────────────────────────────────────────"
echo -e " \E[41;1;97m            Install SSH WS             $NC"
echo -e "─────────────────────────────────────────"
sleep 2

cat > /etc/systemd/system/ws-dropbear.service <<-END
[Unit]
Description=SSH Websocket Python
Documentation=https://google.com
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
Restart=on-failure
ExecStart=/usr/bin/python -O /usr/local/bin/ws-stunnel

[Install]
WantedBy=multi-user.target

END

cat > /etc/systemd/system/ws-stunnel.service <<-END
[Unit]
Description=SSH Websocket Python
Documentation=https://google.com
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
Restart=on-failure
ExecStart=/usr/bin/python -O /usr/local/bin/ws-stunnel

[Install]
WantedBy=multi-user.target

END

sleep 2
echo "0 0 * * * root xp" >> /etc/crontab
echo "0 3 * * * root clearlog && reboot" >> /etc/crontab

echo -e "$yell[SERVICE]$NC Restart All Service"
systemctl daemon-reload
sleep 1
echo -e "$yell[SERVICE]$NC Restart All service SSH & OVPN"
/etc/init.d/nginx restart >/dev/null 2>&1
/etc/init.d/openvpn restart >/dev/null 2>&1
/etc/init.d/ssh restart >/dev/null 2>&1
/etc/init.d/dropbear restart >/dev/null 2>&1
/etc/init.d/fail2ban restart >/dev/null 2>&1
/etc/init.d/stunnel4 restart >/dev/null 2>&1
/etc/init.d/vnstat restart >/dev/null 2>&1
/etc/init.d/squid restart >/dev/null 2>&1
systemctl disable badvpn1 
systemctl stop badvpn1 
systemctl enable badvpn1
systemctl start badvpn1 
systemctl disable badvpn2 
systemctl stop badvpn2 
systemctl enable badvpn2
systemctl start badvpn2 
systemctl disable badvpn3 
systemctl stop badvpn3 
systemctl enable badvpn3
systemctl start badvpn3 
echo -e "[ ${green}ok${NC} ] Enable & Restart All Service Websocket "
systemctl enable ws-dropbear
systemctl restart ws-dropbear
systemctl enable ws-stunnel
systemctl restart ws-stunnel
echo -e "[ ${green}ok${NC} ] Enable & Restart All Service Xray "
systemctl enable xray
systemctl restart xray
systemctl restart nginx
systemctl enable runn
systemctl restart runn
systemctl stop trojan-go
systemctl start trojan-go
systemctl enable trojan-go
systemctl restart trojan-go
systemctl enable haproxy
systemctl restart haproxy
cat > /home/re_otm <<-END
0
END

clear
cat> /root/.profile << END
# ~/.profile: executed by Bourne-compatible login shells.

if [ "$BASH" ]; then
  if [ -f ~/.bashrc ]; then
    . ~/.bashrc
  fi
fi

mesg n || true
clear
menu
END
chmod 644 /root/.profile

service cron restart >/dev/null 2>&1
service cron reload >/dev/null 2>&1
/etc/init.d/cron restart
systemctl restart cron

if [ -f "/root/log-install.txt" ]; then
rm /root/log-install.txt > /dev/null 2>&1
fi
if [ -f "/etc/afak.conf" ]; then
rm /etc/afak.conf > /dev/null 2>&1
fi
if [ ! -f "/etc/log-create-user.log" ]; then
echo "Log All Account " > /etc/log-create-user.log
fi
history -c
aureb=$(cat /home/re_otm)
b=11
if [ $aureb -gt $b ]
then
gg="PM"
else
gg="AM"
fi
clear
echo ""
rm /root/limit >/dev/null 2>&1
rm /root/setup.sh >/dev/null 2>&1
rm /root/setup.sh >/dev/null 2>&1
rm /root/ins-xray.sh >/dev/null 2>&1
rm /root/insshws.sh >/dev/null 2>&1
rm /root/ins-udp.sh >/dev/null 2>&1
rm /root/cf >/dev/null 2>&1
rm /root/.gh
touch /root/.system 
secs_to_human "$(($(date +%s) - ${start}))" | tee -a log-install.txt
echo -e ""
echo -e "Installasi Berjalan Dengan Sukses"
echo -e "Silahkan ganti port login vps dari 22 menjadi 2222"
history -c
echo -e ""
