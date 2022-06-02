#!/bin/bash
get_client_credentials() {
echo "Entrust CA Gateway Utility"
echo -n "Path to client credentials file (PKCS#12): "
read -r P12

echo -n "Enter PKCS#12 file password: "
read -r P12_PWD

echo -n "Enter CA Gateway URL:"
read -r CAGW_URL
}
main() {
echo "Select the CA Gateway operation:

1. List all Certificate Authorities
2. List all profiles for a Certificate Authority
3. Enroll new certificate
"
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
else
    echo "something else"
fi
}
get_client_credentials
main
