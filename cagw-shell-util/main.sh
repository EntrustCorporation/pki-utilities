#!/bin/bash
get_client_credentials() {
	echo -n "Path to client credentials file (PKCS#12): "
	read -r P12

	echo -n "Enter PKCS#12 file password: "
	read -s P12_PWD
	
	printf "\n"

	echo -n "Enter CA Gateway URL (e.g. https://CAGW-Host/cagw): "
	read -r CAGW_URL
}
get_ation_type () {
	echo -n "Select action type from below"
	printf "\n"
	echo -n "1. Revoke
2. Renew
3. Reissue
"
	read -r ACTION_TYPE_ID
	if [ $ACTION_TYPE_ID == "1" ]
	then
		printf -v "ACTION_TYPE" "%s" "RevokeAction"
	elif [ $ACTION_TYPE_ID == "2" ]
	then
		printf -v "ACTION_TYPE" "%s" "RenewAction"
	elif [ $ACTION_TYPE_ID == "3" ]
	then
		printf -v "ACTION_TYPE" "%s" "ReissueAction"
	else
		echo -n "bad selection"
		printf -v "ACTION_TYPE" "%s" ""
		get_ation_type
	fi
}
get_ation_reason () {
	echo -n "Select action reason from below"
	printf "\n"
	echo -n "1. unspecified
2. keyCompromise
3. caCompromise
4. affiliationChanged
5. superseded
6. cessationOfOperation
7. certificateHold
8. privilegeWithdrawn
"
	read -r ACTION_REASON_ID
	if [ $ACTION_REASON_ID == "1" ]
	then
		printf -v "ACTION_REASON" "%s" "unspecified"
	elif [ $ACTION_REASON_ID == "2" ]
	then
		printf -v "ACTION_REASON" "%s" "keyCompromise"
	elif [ $ACTION_REASON_ID == "3" ]
	then
		printf -v "ACTION_REASON" "%s" "caCompromise"
	elif [ $ACTION_REASON_ID == "4" ]
	then
		printf -v "ACTION_REASON" "%s" "affiliationChanged"
	elif [ $ACTION_REASON_ID == "5" ]
	then
		printf -v "ACTION_REASON" "%s" "superseded"
	elif [ $ACTION_REASON_ID == "6" ]
	then
		printf -v "ACTION_REASON" "%s" "cessationOfOperation"
	elif [ $ACTION_REASON_ID == "7" ]
	then
		printf -v "ACTION_REASON" "%s" "certificateHold"
	elif [ $ACTION_REASON_ID == "8" ]
	then
		printf -v "ACTION_REASON" "%s" "privilegeWithdrawn"
	else
		echo -n "bad selection"
		printf -v "ACTION_REASON" "%s" ""
		get_ation_reason
	fi
}
get_subject_altnames() {
	echo -n "Do you want to enter a Subject Alternate Name (Y/N): "
	read -r SAN_NEEDED
	
	if [ -z "$SAN_NEEDED" ]
	then
		echo -n "Please select a Y/N"
		get_subject_altnames
	fi
	if [ $SAN_NEEDED == "Y" ]
	then
		echo -n "Select the SAN attribute to be added from the list "
		printf "\n"
		echo -n "1. rfc822Name
2. dNSName
3. directoryName
4. uniformResourceIdentifier
5. iPAddress
6. registeredID
"
		read -r SAN_VAR_ID
		
		#\"der\": \"string\",
		if [ $SAN_VAR_ID == "1" ]
		then
			printf -v "SAN_VAR_NAME" "%s" "rfc822Name"
		elif [ $SAN_VAR_ID == "2" ]
		then
			printf -v "SAN_VAR_NAME" "%s" "dNSName"
		elif [ $SAN_VAR_ID == "3" ]
		then
			printf -v "SAN_VAR_NAME" "%s" "directoryName"
		elif [ $SAN_VAR_ID == "4" ]
		then
			printf -v "SAN_VAR_NAME" "%s" "uniformResourceIdentifier"
		elif [ $SAN_VAR_ID == "5" ]
		then
			printf -v "SAN_VAR_NAME" "%s" "iPAddress"
		elif [ $SAN_VAR_ID == "6" ]
		then
			printf -v "SAN_VAR_NAME" "%s" "registeredID"
		else
			echo -n "bad selection"
			printf -v "SAN_ARRAY" "%s" ""
			get_subject_altnames
		fi
		
		echo -n "Enter value of the selected SAN attribute: "
		read -r SAN_VALUE
		
		printf -v "SAN_ARRAY" "%s" "${SAN_ARRAY}{\"type\": \"$SAN_VAR_NAME\",\"value\": \"$SAN_VALUE\"},"
		get_subject_altnames
	elif [ $SAN_NEEDED == "N" ]
	then
		if [ "$SAN_ARRAY" == "[" ]
		then
			printf -v "SAN_ARRAY" "%s" "[]"
		else 
			printf -v "SAN_ARRAY" "%s" "${SAN_ARRAY%?}]"
			return 1
		fi
	else
		echo -n "bad selection"
		printf -v "SAN_ARRAY" "%s" ""
		get_subject_altnames
	fi
}
main() {
	echo "Select the CA Gateway operation:
1. Generate CSR with subject (using OpenSSL)
2. List all Certificate Authorities
3. List all profiles for a Certificate Authority
4. Enroll new certificate with CSR
5. Certificate revocation by serial
6. Bulk certificate issuance
7. Bulk certificate revocation
8. Exit"
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
		echo -n "Where would you like to store the certificate (e.g. /tmp/certificate.pem): "
		read -r CERT_PATH
		if [ -z "$CSR_INPUT_PATH" ]
		then
				  printf -v "CSR_INPUT_PATH" "%s" $CSR_PATH
		fi
		echo -n "Enter full subject DN: "
		read -r CERT_OPT_PARAMS_SUBJECT_DN
		printf -v "SAN_ARRAY" "%s" "["
		get_subject_altnames
		curl -s --header "Accept: application/json" -H "Content-Type: application/json" --data "{\"profileId\":\"$PROFILE_ID\",\"requiredFormat\":{\"format\":\"PEM\"},\"csr\":\"$(tr -d "\n\r" < $CSR_INPUT_PATH)\",\"optionalCertificateRequestDetails\":{\"subjectDn\":\"$CERT_OPT_PARAMS_SUBJECT_DN\"},\"subjectAltNames\":$SAN_ARRAY}" --cert-type P12 --cert $P12:$P12_PWD $CAGW_URL/v1/certificate-authorities/$CAID/enrollments > /tmp/resout.txt
		response_data=$(cat /tmp/resout.txt)
		cert_raw=$( jq '.enrollment.body' <<< "${response_data}" )
		var1=${cert_raw%?}
		var2=${var1:1}
		echo $var2 > /tmp/tempCert.pem
		sed 's/\\n/\r\n/g' /tmp/tempCert.pem > $CERT_PATH
		rm -f /tmp/tempCert.pem
		printf "\n"
		echo "Certificate is written successfully to the file $CERT_PATH".
		main
	elif [ $CAGW_OP == "5" ]
	then
		echo -n "Enter CA ID: "
		read -r CAID
		echo -n "Enter certificate serial number (Example: 00112233): "
		read -r CERTIFICATE_SERIAL	
		get_ation_type
		echo -n "Enter a comment about the action: "
		read -r COMMENT
		get_ation_reason
		curl --header "Accept: application/json" -H "Content-Type: application/json" --data "{\"action\":{\"comment\":\"$COMMENT\",\"type\":\"$ACTION_TYPE\",\"reason\":\"$ACTION_REASON\"}}" --cert-type P12 --cert $P12:$P12_PWD $CAGW_URL/v1/certificate-authorities/$CAID/certificates/$CERTIFICATE_SERIAL/actions &> /dev/null
		main
	elif [ $CAGW_OP == "6" ]
	then
		echo -n "Feature not yet available."
		main
	elif [ $CAGW_OP == "7" ]
	then
		echo -n "Feature not yet available."
		main
	elif [ $CAGW_OP == "8" ]
	then
		exit
	else
		echo -n "Invalid Selection"
		main
	fi
}
echo "--------------------------
Entrust CA Gateway Utility
--------------------------"
get_client_credentials
main