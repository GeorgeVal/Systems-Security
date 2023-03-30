Georgios Valavanis AM: 2019030065

This an implementation of an adblocker.

-domains option: It reads domain names from domainNames.txt and domainNames2.txt and finds unique and shared domain names in those two files using grep command with -f (File comparison) and -x to find shared domain names or -vx to find unique domain names comparing those files.

The -ipssame and -ipsdiff options read the domains listed in the IPAddressesSame.txt and IPAddressesDifferent.txt files respectively (those files have the results of the -domains option).
For every domain read, host command is used to get the IP of the domain. IP and IPv6 for each 
domain are stored in seperate variables. If they exist they are appended to IPAddressesSame
or IPAddressessDifferent , after deleting the line containing the domain name using sed command.
IPv6 addresses are stored with v6 prefix, so their identification as IPv6 is possible.

After all IPs and IPV6s are resolved (now IP files contain only IPs), iptables and ip6tables are
updated respectfully, by reading IPAddressesSame and IPAddressesDifferent files.
All packets received from IPs listed in IPAddressesSame are dropped  using iptables and ip6tables
command with -A INPUT and -j DROP prefixes. All packets received from
IPs listed in IPAddressesDifferent are Rejected using iptables and ip6tables commands with -A INPUT
and -j REJECT prefixes.

-ipssame and -ipsdiff operations are run in the background without blocking the terminal.
sed command creates temporary files that are visible if you have a files tab open during 
execution. Refreshing files after execution resolves the problem.

The -save option saves current rules to the adblockRules file using iptables-save and 
ip6tables-save commands.

The -load option loads rules from adblockRules file. In order to decypher which rules are for the
iptable and which for the ip6table, file is splitted into two using the line containing ip6 as 
delimiter. This is accomplished by finding the ip6 line using grep and cut. Then the 2 halves
are stored to variables using head and tail commands.

Then iptables and ip6tables are updated with the saved rules using iptables-restore and ip6tables-
restore.

The -reset option resets iptables and ip6tables settings to default (no restrictions) using 
iptables -F and ip6tables -F commands.

The -load option loads current rules using iptables -L and ip6tables -L commands.

Testing the adblocker I found out the following:

Visiting www.news247.gr, ads can be seen. Using inspect tool and adding their urls such as
 track.adform.net we can temporarily block them. Unfortunately if we refresh the page a couple of
 times the ad is shown again under the same url. That is, because the urls IP has changed
 
executing host track.adform.net for the first time outputs:

track.adform.net is an alias for track-eu.adformnet.akadns.net.
track-eu.adformnet.akadns.net has address 37.157.4.40
track-eu.adformnet.akadns.net has address 37.157.4.41
track-eu.adformnet.akadns.net has address 37.157.4.39

executing host track.adform.net after some minutes outputs:

track.adform.net is an alias for track-eu.adformnet.akadns.net.
track-eu.adformnet.akadns.net has address 37.157.6.247
track-eu.adformnet.akadns.net has address 37.157.6.246
track-eu.adformnet.akadns.net has address 37.157.6.245
track-eu.adformnet.akadns.net has address 37.157.6.248
track-eu.adformnet.akadns.net has address 37.157.6.253
track-eu.adformnet.akadns.net has address 37.157.6.252

Clearly, the IPs have changed !


The ads may also be served through JavaScript: If the ads are served through JavaScript, iptables 
will not be able to block the ads, as iptables operates at the IP level and does not have 
visibility into the content of the web pages. Those ads wont be blocked even if you add their url
to the adblocker.

Checking if an ad is served through JavaScript can be done using the inspect tool of the browser.
If you right click the ad and choose inspect ,the web page's source code will show up. If a script
element is used for loading the ad then it is served through JavaScript.

If the ads domain is not contained in the domain file then the ad will not be blocked or if its 
IP changes.

Second test done to site : tomati.gr

Adding googleads.g.doubleclick.net to the domains and executing the adblock, results in
blocking all visible ads of the site.

Until googleads.g.doubleclick.net IP changes... Every time IP changes adblock needs to be
executed again.
