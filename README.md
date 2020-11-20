# TokTok
Script to finding hidden virtualhost (after DNS gathering), protected with WAFs such as Cloudflare, Akamai, Incapsula and wrong config in the original server.

1.- Enumerate domains and subdomains of the enterprise (with other tools like dnsenum, fierce, etc.)

2.- Save the ip addresses found in a file

3.- Use TokTok to find the original server hosting the hidden virtual host

![Screenshot](toktok.png) 
