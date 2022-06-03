#!/bin/bash
get_client_credentials() {
	echo -n "Path to client credentials file (PKCS#12): "
	read -r P12

	echo -n "Enter PKCS#12 file password: "
	read -r P12_PWD

	echo -n "Enter CA Gateway URL: "
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
		echo -n "Enter key type: "
		read -r KEY_TYPE
		echo -n "Enter key length: "
		read -r KEY_LEN
		echo -n "Where would you like to store the key (e.g. /tmp/example.key): "
		read -r KEY_PATH
		echo -n "Where would you like to store the CSR (e.g. /tmp/example.csr): "
		read -r CSR_PATH
		openssl req -nodes -newkey $KEY_TYPE:$KEY_LEN -keyout $KEY_PATH -out $CSR_PATH -subj $CSR_SUBJECT &> /dev/null
		sed -i 1d $CSR_PATH &> /dev/null
		sed -i '' -e '$ d' $CSR_PATH &> /dev/null
		main
	elif [ $CAGW_OP == "2" ]
	then
		curl  --header "Accept: application/json" -H "Content-Type: application/json" --cert-type P12 --cert $P12:$P12_PWD $CAGW_URL/v1/certificate-authorities
		main
	elif [ $CAGW_OP == "3" ]
	then
		echo -n "Enter CA ID: "
		read -r CAID
		curl  --header "Accept: application/json" -H "Content-Type: application/json" --cert-type P12 --cert $P12:$P12_PWD $CAGW_URL/v1/certificate-authorities/$CAID/profiles
		main
	elif [ $CAGW_OP == "4" ]
	then
		echo -n "Enter CA ID: "
		read -r CAID
		echo -n "Enter certificate profile ID: "
		read -r PROFILE_ID
		echo -n "Enter path of the CSR file ["$CSR_PATH"]: "
		read -r CSR_INPUT_PATH
		if [ -z "$CSR_INPUT_PATH" ]
		then
				  CSR_INPUT_PATH = $CSR_PATH
		fi
		echo -n "Enter full subject DN: "
		read -r CERT_OPT_PARAMS_SUBJECT_DN
		curl  --header "Accept: application/json" -H "Content-Type: application/json" --data "{\"profileId\":\"$PROFILE_ID\",\"requiredFormat\":{\"format\":\"PEM\"},\"csr\":\"$(tr -d "\n\r" < $CSR_INPUT_PATH)\",\"optionalCertificateRequestDetails\":{\"subjectDn\":\"$CERT_OPT_PARAMS_SUBJECT_DN\"}}" --cert-type P12 --cert $P12:$P12_PWD $CAGW_URL/v1/certificate-authorities/$CAID/enrollments
		main
	elif [ $CAGW_OP == "5" ]
	then
		exit
	else
		echo -n "Invalid Selection"
	fi
}
echo "--------------------------
Entrust CA Gateway Utility
--------------------------"
get_client_credentials
main