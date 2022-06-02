#!/bin/bash
get_client_credentials() {
	echo "Path to client credentials file (PKCS#12): "
	read -r P12

	echo "Enter PKCS#12 file password: "
	read -r P12_PWD

	echo "Enter CA Gateway URL:"
	read -r CAGW_URL
}
main() {
	echo "Select the CA Gateway operation:
1. List all Certificate Authorities
2. List all profiles for a Certificate Authority
3. Enroll new certificate
4. Exit"
	read -r CAGW_OP
	#echo $P12$CAGW_URL$CAGW_OP
	if [ $CAGW_OP == "1" ]
	then
		echo "Getting all CAs"
		curl  --header "Accept: application/json" -H "Content-Type: application/json" --cert-type P12 --cert $P12:$P12_PWD $CAGW_URL/v1/certificate-authorities
		main
	elif [ $CAGW_OP == "2" ]
	then
		echo "Enter CA ID: "
		read -r CAID
		curl  --header "Accept: application/json" -H "Content-Type: application/json" --cert-type P12 --cert $P12:$P12_PWD $CAGW_URL/v1/certificate-authorities/$CAID/profiles
		main
	elif [ $CAGW_OP == "4" ]
	then
		exit
	else
		echo "something else"
	fi
}
echo "--------------------------
Entrust CA Gateway Utility
--------------------------"
get_client_credentials
main
