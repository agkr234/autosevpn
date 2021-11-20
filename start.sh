#!/bin/bash

set -x

ip2int(){
 IFS=. read -r a b c d <<EOF
$1
EOF
 echo "$(((a<<24)+(b<<16)+(c<<8)+d))"
}
int2ip(){
 echo "$(( ($1 >> 24) % 256 )).$(( ($1 >> 16) % 256 )).$(( ($1 >> 8) % 256 )).$(( $1 % 256 ))"
}


#DEST_ADDR=${DEST_ADDR:-"103.151.65.25"}

VIRTUAL_HUB=${VIRTUAL_HUB:-"VPNGATE"}
NIC_NAME=${NIC_NAME:-"default"}
ACCOUNT_NIC_NAME=${ACCOUNT_NIC_NAME:-"myadapter"}
VPN_SERVER=${VPN_SERVER:-"localhost"}
VPN_PORT=${VPN_PORT:-"443"}
TAP_IPADDR=${TAP_IPADDR:-""}
ACCOUNT_NAME=${ACCOUNT_NAME:-"myconnection"}
#NET_MASK=${NET_MASK:-"255.255.255.255"}
IP_REQ_ADDR=${IP_REQ_ADDR:-""}

ACCOUNT_PASS_TYPE=standard
VPNCMD="/usr/vpncmd/vpncmd localhost /CLIENT /CMD"

DEFAULT_GATEWAY=$(ip r | grep -E "^default" | grep -Ev "vpn" | grep -oE '((1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])\.){3}(1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])')

route add -host $VPN_SERVER gw $DEFAULT_GATEWAY

/usr/vpnclient/vpnclient start

#sleep 2

#$VPNCMD NicList $NIC_NAME
$VPNCMD NicCreate $NIC_NAME
$VPNCMD NicEnable $NIC_NAME
$VPNCMD AccountCreate $ACCOUNT_NAME /SERVER:$VPN_SERVER:$VPN_PORT /HUB:$VIRTUAL_HUB /USERNAME:vpn /NICNAME:$ACCOUNT_NIC_NAME
$VPNCMD AccountAnonymousSet $ACCOUNT_NAME
$VPNCMD AccountConnect $ACCOUNT_NAME

LOWER_NIC_NAME=$(echo $NIC_NAME | tr '[:upper:]' '[:lower:]')

#TAP_DEVICE=$(cd /sys/class/net; echo vpn_*)
case ${TAP_IPADDR} in
	dhclient)
		dhclient vpn_$LOWER_NIC_NAME
		;;
	none)
		;;
	*)
		ip addr add $TAP_IPADDR dev $TAP_DEVICE
		;;
esac

VPN_DEFAULT_GATEWAY=$(ip r | grep -E "^default" | grep -E "vpn_$LOWER_NIC_NAME" | grep -oE '((1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])\.){3}(1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])')
while [ -z "$VPN_DEFAULT_GATEWAY" ]
do
	sleep 1
	VPN_DEFAULT_GATEWAY=$(ip r | grep -E "^default" | grep -E "vpn_$LOWER_NIC_NAME" | grep -oE '((1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])\.){3}(1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])')
done

route del default gw $VPN_DEFAULT_GATEWAY
route add default gw $VPN_DEFAULT_GATEWAY metric 1 vpn_$LOWER_NIC_NAME

for (( i=0; i<${#NET_MASK[@]}; i++ )); do
	if [ "${NET_MASK[$i]}" != "255.255.255.255" ]; then
		route add -net ${DEST_ADDR[$i]} netmask ${NET_MASK[$i]} gw $VPN_DEFAULT_GATEWAY vpn_$LOWER_NIC_NAME
	else
		route add -host ${DEST_ADDR[$i]} gw $VPN_DEFAULT_GATEWAY vpn_$LOWER_NIC_NAME
	fi;
done

route add -host $(getent hosts $IP_REQ_ADDR | awk '{ print $1 }') gw $VPN_DEFAULT_GATEWAY vpn_$LOWER_NIC_NAME

route -n

exit 0
