#!/bin/bash
# You are NOT allowed to change the files' names!
domainNames="domainNames.txt"
domainNames2="domainNames2.txt"
IPAddressesSame="IPAddressesSame.txt"
IPAddressesDifferent="IPAddressesDifferent.txt"
adblockRules="adblockRules"

function adBlock() {
    if [ "$EUID" -ne 0 ];then
        printf "Please run as root.\n"
        exit 1
    fi
    if [ "$1" = "-domains"  ]; then
        # Find different and same domains in ‘domainNames.txt’ and ‘domainsNames2.txt’ files 
	# and write them in “IPAddressesDifferent.txt and IPAddressesSame.txt" respectively
        # Write your code here...
        # ...
        # ...
        # Find common domain names
        grep -f $domainNames -x $domainNames2 > $IPAddressesSame

        # Find unique domain names in domainNames.txt (comparing domainNames with domainNames2)
        grep -f $domainNames -vx $domainNames2 > $IPAddressesDifferent

        # Find unique domain names in domainNames2.txt (comparing domainNames2 with domainNames)
        grep -f $domainNames2 -vx $domainNames > $IPAddressesDifferent
            
    elif [ "$1" = "-ipssame"  ]; then
        # Configure the DROP adblock rule based on the IP addresses of $IPAddressesSame file.
        # Write your code here...
        # ...
        # ...
        echo "$(cat IPAddressesSame.txt)" | while read -r domain; do

            ip=$(host "$domain" | awk '/has address/ {print $4}')
            ip6=$(host "$domain" | awk '/has IPv6 address/ {print $5}')

            #If IP or IPv6 exist continue processing
            if [ "$ip" != "" ] || [ "$ip6" != "" ]; then
                # Delete the domain from IPAddressesSame.txt
                sed -i "/$domain/d" $IPAddressesSame

                #If only IPv6 exists
                if [ "$ip" = "" ]; then
                    # Append file with IPv6 of deleted domain
                    # Print them to file with prefix v6
                    for num in $ip6; do
                        echo "v6 $num" >> $IPAddressesSame
                    done
                #If only IP exists
                elif [ "$ip6" = "" ]; then
                    # Append file with IP of deleted domain
                    echo "$ip" >> $IPAddressesSame
                else
                    #Both IP and IPv6 exist
                    echo "$ip" >> $IPAddressesSame
                    for num in $ip6; do
                        echo "v6 $num" >> $IPAddressesSame
                    done
                fi
            #If IP or IPv6 do not exist then just delete domain from file
            else
               sed -i "/$domain/d" $IPAddressesSame 
            fi
             
        done &&
        wait &&
        while read -r ips; do
            ip6=$(echo "$ips" | awk '/v6/ {print $2}')
        
            if [ "$ip6" != "" ]; then
                ip6tables -A INPUT -s "$ip6" -j DROP
            else
                iptables -A INPUT -s "$ips" -j DROP
            fi
            
        done < $IPAddressesSame &
        

    elif [ "$1" = "-ipsdiff"  ]; then
        # Configure the REJECT adblock rule based on the IP addresses of $IPAddressesDifferent file.
        # Write your code here...
        # ...
        # ...
        echo "$(cat IPAddressesDifferent.txt)" | while read -r domain; do

            ip=$(host "$domain" | awk '/has address/ {print $4}')
            ip6=$(host "$domain" | awk '/has IPv6 address/ {print $5}')

            # If IP or IPv6 exist continue processing
            if [ "$ip" != "" ] || [ "$ip6" != "" ]; then
                # Delete the domain from IPAddressesDifferent.txt
                sed -i "/$domain/d" $IPAddressesDifferent

                # If only IPv6 exists
                if [ "$ip" = "" ]; then
                    # Append file with IPv6 of deleted domain
                    # Print them to file with prefix v6
                    for num in $ip6; do
                        echo "v6 $num" >> $IPAddressesDifferent
                    done
                # If only IP exists
                elif [ "$ip6" = "" ]; then
                    # Append file with IP of deleted domain
                    echo "$ip" >> $IPAddressesDifferent
                else
                    #Both IP and IPv6 exist
                    echo "$ip" >> $IPAddressesDifferent
                    for num in $ip6; do
                        echo "v6 $num" >> $IPAddressesDifferent
                    done
                fi
            # If IP or IPv6 do not exist then just delete domain from file 
            else
               sed -i "/$domain/d" $IPAddressesDifferent 
            fi
             
        done &&
        wait &&
        while read -r ips; do
            ip6=$(echo "$ips" | awk '/v6/ {print $2}')
            if [ "$ip6" != "" ]; then
                ip6tables -A INPUT -s "$ip6" -j REJECT
            else
                iptables -A INPUT -s "$ips" -j REJECT
            fi
            
        done < $IPAddressesDifferent &
        
    elif [ "$1" = "-save"  ]; then
        # Save rules to $adblockRules file.
        # Write your code here...
        # ...
        # ...
        iptables-save > $adblockRules
        ip6tables-save >> $adblockRules
        
    elif [ "$1" = "-load"  ]; then
        # Load rules from $adblockRules file.
        # Write your code here...
        # ...
        # ...
        # Splitting file contents to ip rules and ip6 rules, by finding the line that ip6 rules start
        splitter="ip6"

        split_line=$(grep -n "$splitter" $adblockRules | cut -d ":" -f 1)

        if [ -n "$split_line" ]; then
            # Split the file into two halves using the ip6 as a splitter
            ip_rules=$(head -n $(expr $split_line - 1) $adblockRules)
            ip6_rules=$(tail -n +$split_line $adblockRules)

            # Load the ip rules
            echo "$ip_rules" | iptables-restore

            # Load the ip6 rules
            echo "$ip6_rules" | ip6tables-restore
        fi
       

        
    elif [ "$1" = "-reset"  ]; then
        # Reset rules to default settings (i.e. accept all).
        # Write your code here...
        # ...
        # ...
        iptables -F
        ip6tables -F

        
    elif [ "$1" = "-list"  ]; then
        # List current rules.
        # Write your code here...
        # ...
        # ...
        iptables -L
        ip6tables -L
        
    elif [ "$1" = "-help"  ]; then
        printf "This script is responsible for creating a simple adblock mechanism. It rejects connections from specific domain names or IP addresses using iptables.\n\n"
        printf "Usage: $0  [OPTION]\n\n"
        printf "Options:\n\n"
        printf "  -domains\t  Configure adblock rules based on the domain names of '$domainNames' file.\n"
        printf "  -ipssame\t\t  Configure the DROP adblock rule based on the IP addresses of $IPAddressesSame file.\n"
	    printf "  -ipsdiff\t\t  Configure the DROP adblock rule based on the IP addresses of $IPAddressesDifferent file.\n"
        printf "  -save\t\t  Save rules to '$adblockRules' file.\n"
        printf "  -load\t\t  Load rules from '$adblockRules' file.\n"
        printf "  -list\t\t  List current rules.\n"
        printf "  -reset\t  Reset rules to default settings (i.e. accept all).\n"
        printf "  -help\t\t  Display this help and exit.\n"
        exit 0
    else
        printf "Wrong argument. Exiting...\n"
        exit 1
    fi
}

adBlock $1
exit 0
