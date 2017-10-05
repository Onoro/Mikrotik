#variables
:local pop 3
:local ipaddr
#searching for "parsing packet failed, possible cause: wrong password" string in log.
:local l2tp [/log find message~"parsing packet failed, possible cause: wrong password"]
#walking through array
foreach i in=$l2tp do={
	#searching IP address of remote host
	:set ipaddr [:pick [/log get $i message ] 0 ([:len [/log get $i message ]]-54)]
                #execute if quantity of "parsing packet failed" records more than pop variable
				if ([:len [/log find message~"parsing packet failed, possible cause: wrong password"]]>=$pop) do={
					#execute if IP address isn't in firewall adress-list
					if ([:len [/ip firewall address-list find address=$ipaddr]]=0 ) do={
						#supplementation IP to address-list		
						/ip firewall address-list add list=l2tp-brutforce address=[:toip $ipaddr]
						/tool e-mail send to="alerts@mail.srv" start-tls=tls-only subject="L2TP allert" body="$ipaddr was blocked because of L2TP brutforce"  server=[:resolve mail.srv]
					}
               }
}

#you have to change mail.srv to your valid smtp server and alerts@mail.srv to your valid mail address.
#second step is to configure Tools>Email tool in Mikrotik menu via Winbox, ssh or web interface.
