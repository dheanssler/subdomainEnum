#!/bin/bash
#Dependencies include assetfinder, httprobe, gowitness, and subjack

domain=$1
outputDir=~/SubdomainEnum/$domain

if [ ! -d $outputDir ]; then
	mkdir -p $outputDir
fi

printf "[+] Collecting subdomains for '$domain' with assetfinder...\n"
printf "[+] Assetfinder by tomnomnom: https://github.com/tomnomnom/assetfinder\n"
assetfinder $domain | sort -u > $outputDir/allDomains
cat $outputDir/allDomains | grep -E "(^|\.)$domain$" > $outputDir/subdomains
cat $outputDir/allDomains | grep -v -E "(^|\.)$domain$" > $outputDir/filteredSubdomains

printf "[+] Probing for alive subdomain(s) for '$domain' with httprobe...\n"
printf "[+] httprobe by tomnomnom: https://github.com/tomnomnom/httprobe\n"
printf "[-] Probing $(wc -l $outputDir/subdomains | awk '{print $1}') subdomain(s) of '$domain'...\n"
cat $outputDir/subdomains | httprobe | sed 's/https*:\/\///' | sort -u > $outputDir/aliveSubdomains
printf "[-] $(wc -l $outputDir/aliveSubdomains | awk '{print $1}') alive subdomain(s) of '$domain' identified...\n"

printf "[+] Taking screenshots of alive subdomains with gowitness..."
printf "[+] gowitness by sensepost: https://github.com/sensepost/gowitness\n"
for subdomain in $(cat $outputDir/aliveSubdomains); do
	printf "[-] Gathering screenshot of '$subdomain'...\n"
	gowitness single http://$subdomain -o $outputDir/$subdomain"_http" --disable-logging &
	gowitness single https://$subdomain -o $outputDir/$subdomain"_https" --disable-logging &
	sleep 0.5
done

printf "[+] Checking for subdomain takeover with subjack...\n"
printf "[+] subjack by haccer: https://github.com/haccer/subjack\n"
printf "[+] fingerprint file by EdOverflow: https://github.com/EdOverflow/can-i-take-over-xyz\n"
curl -s https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json | sed 's/\("fingerprint":.*\)\(".*"\)/\1[\2]/g' | sed 's/"fingerprint": \[""\]/"fingerprint": \["BLANK"\]/g' | jq 'map(select(.status != "Not vulnerable"))' > fingerprintsEdOverflow.json
rm -f $outputDir/subdomainHijacking
subjack -a -w $outputDir/subdomains -c fingerprintsEdOverflow.json -o $outputDir/subdomainHijacking
subjack -w $outputDir/subdomains -c fingerprintsEdOverflow.json -ssl -o $outputDir/subdomainHijacking
rm fingerprintsEdOverflow.json


if [ -e $outputDir/subdomainHijacking ]; then
	printf "[+] Gathering page contents for potential subdomain hijacking candidates...\n"
	for subdomain in $(cat $outputDir/subdomainHijacking | awk '{print $3}' | xargs ); do
		printf "============= http://$subdomain/ =============\n" >> $outputDir/subdomainHijacking
		curl -s -i -k http://$subdomain/ >> $outputDir/subdomainHijacking
		printf "============= https://$subdomain/ =============\n" >> $outputDir/subdomainHijacking
		curl -s -i -k https://$subdomain/ >> $outputDir/subdomainHijacking
	done
else
	printf "[+] No subdomain hijacking candidates identified...\n"
fi
#