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
1. Generate CSR with subject (using OpenSSL)
2. List all Certificate Authorities
3. List all profiles for a Certificate Authority
4. Enroll new certificate with CSR
5. Exit"
	read -r CAGW_OP
	if [ $CAGW_OP == "1" ]
	then
		echo "Enter full subject
Example: /C=CA/ST=Ontario/L=Ottawa/O=My Org/OU=IT/CN=example.com"
		read -r CSR_SUBJECT
		echo "Enter key type: "
		read -r KEY_TYPE
		echo "Enter key length: "
		read -r KEY_LEN
		echo "Where would you like to store the key (e.g. /tmp/example.key): "
		read -r KEY_PATH
		echo "Where would you like to store the CSR (e.g. /tmp/example.csr): "
		read -r CSR_PATH
		openssl req -nodes -newkey $KEY_TYPE:$KEY_LEN -keyout $KEY_PATH -out $CSR_PATH -subj \"$CSR_SUBJECT\"
		wait
		echo "-----Generated CSR-----"
		cat $CSR_PATH
		main
	elif [ $CAGW_OP == "2" ]
	then
		curl  --header "Accept: application/json" -H "Content-Type: application/json" --cert-type P12 --cert $P12:$P12_PWD $CAGW_URL/v1/certificate-authorities
		main
	elif [ $CAGW_OP == "3" ]
	then
		echo "Enter CA ID: "
		read -r CAID
		curl  --header "Accept: application/json" -H "Content-Type: application/json" --cert-type P12 --cert $P12:$P12_PWD $CAGW_URL/v1/certificate-authorities/$CAID/profiles
		main
	elif [ $CAGW_OP == "4" ]
	then
		echo "Enter CA ID: "
		read -r CAID
		echo "Enter certificate profile ID: "
		read -r PROFILE_ID
		curl  --header "Accept: application/json" -H "Content-Type: application/json" --cert-type P12 --cert $P12:$P12_PWD $CAGW_URL/v1/certificate-authorities/$CAID/profiles
		main
	elif [ $CAGW_OP == "5" ]
	then
		exit
	else
		echo "Invalid Selection"
	fi
}
echo "--------------------------
Entrust CA Gateway Utility
--------------------------"
get_client_credentials
main
