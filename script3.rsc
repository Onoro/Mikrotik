*********************************************************
*               Mikrotik L2TP protection.               *
*         https://github.com/Onoro/Mikrotik/            *
*                                                       *
*********************************************************
#variables
:local pop 3
:local ipaddr
#searching for "failed to get valid proposal." string in log.
:local l2tp [/log find message~"failed to get valid proposal."]
#walking through array
foreach i in=$l2tp do={
	#searching IP address of remote host
	:set ipaddr [:pick [/log get $i message ] 0 ([:len [/log get $i message ]]-30)]
                #execute if quantity of "failed to get valid proposal." records more than pop variable
				if ([:len [/log find message~"failed to get valid proposal."]]>=$pop) do={
					#execute if IP address isn't in firewall adress-list
					if ([:len [/ip firewall address-list find address=$ipaddr]]=0 ) do={
						#supplementation IP to address-list		
						/ip firewall address-list add list=l2tp-brutforce address=[:toip $ipaddr]
						/tool e-mail send to="alerts@mail.my" start-tls=tls-only subject="L2TP allert" body="$ipaddr was blocked because of L2TP brutforce"  server=[:resolve mail.my]
					}
               }
}
