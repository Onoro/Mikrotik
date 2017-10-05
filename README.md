# Mikrotik
Scripts for L2TP protection

-------------------------------------------------------------------------------------------------------------------------------------------------

Part 1

I spent a lot of time in search of information about L2TP protection. I found couple posts which helped me to write first part of that instruction.
The first third of the protection of L2TP is firewall rules. They are monitoring and blocking connections from blacklist and preventing password brutforce. 

I think that there is no need to explain them, but one thing I have to admit, that you will be forced to change interface name from ether1-WAN to your WAN interface.
 


I will try to reproduce attackers actions and connect to my L2TP network.
Server (Mikrotik) runs l2tp+ipsec server. So you need such information: hostname or IP, proposal, IPSec Secret, user and password.
You can using various port scanners for searching IP address, but for other items you have to use brutforce. 
First I've created new VPN connection on Windows 7 and used such parameters: l2tp+ipsec encryption (valid), proposal (valid), IPSec Secret ( valid) and invalid user+password combination. Image yourself that cracker picked up proposal and IPSec Secret.
On Mikrotik side our counters (firewall rules) were working and after several attempts with various user+pass combs my IP was blocked.
In additional the record "<192.168.1.15> user user authentification failed." was appearing in Mikrotik logs every time when I tried to connect. 
My test user+pass combination was user user ))

I was getting Error #691 on Windows every time when I tried to connect with invalid user+password. After I was banned it became impossible to connect to vpn at all.


-------------------------------------------------------------------------------------------------------------------------------------------------
Part 2

Now I changed configuration on Windows side and it’s become to such form:
l2tp+ipsec encription (valid), proposal (valid), IPSec Secret (invalid) and user+password combination (invalid). 

In such situation previous rules can't help, but next records were appearing in Mikrotik's logs.
Five strings with:
192.168.1.15 parsing packet failed, possible couse: wrong password
and one string with:
phase1 negotiation failed due to time up 11.32.86.22[500]<=>192.168.1.15[500]

So I decided to write script to process first string and that's what I got:


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
-------------------------------------------------------------------------------------------------------------------------------------------------
Part 3

In the third time I changed VPN connection on Windows again and that's what I got:
l2tp+ipsec encription (valid), proposal (invalid), IPSec Secret (valid) and user+password combination (invalid). 

After that I tried to connect to server and an error was appeared.
I found such records in Mikrotik log:

no suitable proposal found
192.168.1.15 failed to pre-process ph2 packet

So I changed couple strings in initial script and got second one. 
As a result, I solved a problem with Mikrotik L2TP server protection. 


#variables
:local pop 3
:local ipaddr
#searching for "failed to pre-process ph2 packet" string in log.
:local l2tp [/log find message~"failed to pre-process ph2 packet"]
#walking through array
foreach i in=$l2tp do={
	#searching IP address of remote host
	:set ipaddr [:pick [/log get $i message ] 0 ([:len [/log get $i message ]]-34)]
                #execute if quantity of "failed to pre-process ph2 packet" records more than pop variable
				if ([:len [/log find message~"failed to pre-process ph2 packet"]]>=$pop) do={
					#execute if IP address isn't in firewall adress-list
					if ([:len [/ip firewall address-list find address=$ipaddr]]=0 ) do={
						#supplementation IP to address-list		
						/ip firewall address-list add list=l2tp-brutforce address=[:toip $ipaddr]
						/tool e-mail send to="alerts@mail.srv" start-tls=tls-only subject="L2TP allert" body="$ipaddr was blocked because of L2TP brutforce"  server=[:resolve mail.srv]
					}
               }
}

-------------------------------------------------------------------------------------------------------------------------------------------------

And the last steaps you have to do it's to add that scripts to sheduller and move firewall rules upper in the list.
