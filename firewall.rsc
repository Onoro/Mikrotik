*********************************************************
*               Mikrotik L2TP protection.               *
*         https://github.com/Onoro/Mikrotik/            *
*                                                       *
*********************************************************
/ip firewall filter
add action=drop chain=input comment="L2TP brutforce IP IPSec drop" connection-state=new log=yes protocol=ipsec-esp src-address-list=\
    l2tp-brutforce
add action=drop chain=input comment="L2TP brutforce IP drop" connection-state=new dst-port=1701,500,4500 log=yes protocol=udp src-address-list=\
    l2tp-brutforce
add action=add-src-to-address-list address-list=l2tp-brutforce address-list-timeout=2w chain=input comment="L2TP brutforce IP to list" \
    connection-state=new dst-port=1701 protocol=udp src-address-list=probe2
add action=add-src-to-address-list address-list=probe2 address-list-timeout=1m chain=input comment="L2TP brutforce protection stage 2" \
    connection-state=new dst-port=1701 protocol=udp src-address-list=probe1
add action=add-src-to-address-list address-list=probe1 address-list-timeout=1m chain=input comment="L2TP brutforce protection stage 1" \
    connection-state=new dst-port=1701 protocol=udp
add action=add-dst-to-address-list address-list=l2tp-brutforce address-list-timeout=1m chain=output comment="L2TP-brutforce protection stage 3 v2" \
    content="M=bad" dst-address-list=l2tp-brutforce-level2
add action=add-dst-to-address-list address-list=l2tp-brutforce-level2 address-list-timeout=1m chain=output comment=\
    "L2TP-brutforce protection stage 2  v2" content="M=bad" dst-address-list=l2tp-brutforce-level1
add action=add-dst-to-address-list address-list=l2tp-brutforce-level1 address-list-timeout=1m chain=output comment=\
    "L2TP-brutforce protection stage 1  v2" content="M=bad"
add action=accept chain=input comment="L2TP allow only with IPsec" dst-port=1701 in-interface=ether1-WAN ipsec-policy=in,ipsec protocol=udp
add action=drop chain=input comment="Drop L2TP without IPsec" dst-port=1701 in-interface=ether1-WAN protocol=udp
add action=accept chain=input comment="L2TP allow" dst-port=500,4500 in-interface=ether1-WAN protocol=udp
add action=accept chain=input comment="IPSec enable" in-interface=ether1-WAN protocol=ipsec-esp
