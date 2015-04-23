
#!/bin/bash
ip=$1
type=$2
plr=$3
#check module
lsmod | grep -q drop
if test 1 -eq  $?
then
    insmod ./drop.ko

fi
setip(){
        echo "ip>>>>>$ip"
        tip=$(transfer_ip ${ip})
	#tip=$?
                echo "$tip"

		 echo "$tip">/sys/module/drop/parameters/tarip
        }
setplr(){
                echo "packet loss rate>>>>>$plr"
		 echo "$plr">/sys/module/drop/parameters/plr
        }
settype(){
                echo "$type">/sys/module/drop/parameters/type
        }
transfer_ip(){
        temp=$1
        a=$(echo $1 | cut -d "." -f 1)
        b=$(echo $temp | cut -d "." -f 2)
        c=$(echo $temp | cut -d "." -f 3)
        d=$(echo $temp | cut -d "." -f 4)
 	let result=d*16777216+c*65536+b*256+a
     	#result=$a
        echo $result
}
setip $ip

setplr 

settype





