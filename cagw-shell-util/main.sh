#!/bin/bash

# NOTE: Any modifications to this file are made at your own risk. Support will not be provided for a modified script.

# Requirements:
#  - Bash version 4.4+
#  - jq
#  - curl v7.81+

get_client_credentials() {
  P12=""
  # Continuously ask for P12 filepath until a valid filepath has been provided
  while [[ ! -f "${P12}" ]]; do
    read -e -rp "Path to client credentials file (PKCS#12): " P12
    [[ ! -f "${P12}" ]] && printf '%s\n' "Path invalid"
  done

  # Continuously ask for P12 Password until a valid password has been provided
  P12_PWD=""
  RESULT=1
  while [[ ${RESULT} -ne 0 ]]; do
    printf '%s' "Enter PKCS#12 file password: "
    read -sr P12_PWD
    openssl pkcs12 -legacy -in "${P12}" -password pass:"${P12_PWD}" -nokeys > /dev/null
    RESULT=$?
  done
  

  CAGW_TYPE=0
  printf '%s\n' "Please select the CAGW type:"
  printf '%s\n' "  1. PKIaaS"
  printf '%s\n' "  2. On-Premises"
  while [[ ${CAGW_TYPE} -lt 1 || ${CAGW_TYPE} -gt 2 ]]; do
    read -rp "CAGW Type: " CAGW_TYPE
    [[ ${CAGW_TYPE} -lt 1 || ${CAGW_TYPE} -gt 2 ]] && echo "bad selection ${CAGW_TYPE}"
  done
  [[ "${CAGW_TYPE}" -eq 1 ]] && export PAGE_SIZE=50
  [[ "${CAGW_TYPE}" -eq 2 ]] && export PAGE_SIZE=100

  CAGW_REGION=0
  if [[ "${CAGW_TYPE}" -eq 1 ]]; then
    printf '%s\n' "Please select the PKIaaS Region:"
    printf '%s\n' "  1. US: https://cagw.pkiaas.entrust.com/cagw"
    printf '%s\n' "  2. EU: https://cagw.eu.pkiaas.entrust.com/cagw"
    printf '%s\n' "  3. PQ: https://cagw.pqlab.pkiaas.entrust.com/cagw"
    while [[ ${CAGW_REGION} -lt 1 || ${CAGW_REGION} -gt 3 ]]; do
      read -rp "CAGW REGION: " CAGW_REGION
      [[ ${CAGW_REGION} -lt 1 || ${CAGW_REGION} -gt 3 ]] && echo "bad selection ${CAGW_REGION}"
    done
    [[ ${CAGW_REGION} -eq 1 ]] && export CAGW_URL="https://cagw.pkiaas.entrust.com/cagw"
    [[ ${CAGW_REGION} -eq 2 ]] && export CAGW_URL="https://cagw.eu.pkiaas.entrust.com/cagw"
    [[ ${CAGW_REGION} -eq 3 ]] && export CAGW_URL="https://cagw.pqlab.pkiaas.entrust.com/cagw"
  elif [[ "${CAGW_TYPE}" -eq 2 ]]; then
	  read -rp "Enter CA Gateway URL (e.g. https://cagw-server.com/cagw): " CAGW_URL
    while [[ -z "${CAGW_URL// }" ]]; do
	    read -rp "Enter CA Gateway URL (e.g. https://cagw-server.com/cagw): " CAGW_URL
    done
  fi
}

get_caid_list () {
  CA_LIST=$(curl  --header "Accept: application/json" -H "Content-Type: application/json" --cert-type P12 --cert "$P12":"$P12_PWD" "$CAGW_URL/v1/certificate-authorities?%24fields=caList.certificate.certificateData" 2>/dev/null)
  CA_ID_LIST=()
  while read -r line; do CA_ID_LIST+=("$line"); done < <(echo "$CA_LIST" | jq -r '.caList[].id')
  CA_NAME_LIST=()
  CA_COUNT="${#CA_ID_LIST[@]}"
  for (( i = 0 ; i < CA_COUNT ; i++ )); do
    # Determine if CA is Root or Issuing CA
    while read -r line; do CA_NAME_LIST+=("$line"); done < <(identify_ca "${CA_ID_LIST[${i}]}")
    # Determine the CA DN
    CERT=$(printf '%s\n%s\n%s' "-----BEGIN CERTIFICATE-----" "$(echo "${CA_LIST}" | jq -r --argjson i ${i} '.caList[$i].certificate."certificateData"')" "-----END CERTIFICATE-----")
    CADN=$(printf '%s' "${CERT}" | openssl x509 -noout -subject -nameopt rfc2253 2>/dev/null)
    CADN=${CADN:8}
    CA_NAME_LIST[i]=$(printf '%s' "${CA_NAME_LIST[${i}]} (${CADN})")
  done
  export CA_ID_LIST
  export CA_NAME_LIST
}

prompt_for_caid () {
  get_caid_list
  printf '%s\n' "Select a CA ID:"
  CA_SELECTION_VALID="FALSE"
  CA_SELECTION=""
  while [[ "${CA_SELECTION_VALID}" == "FALSE" ]]; do
    for ((i = 0 ; i < ${#CA_NAME_LIST[@]} ; i++ )); do
      j=$(( i + 1 ))
      echo "${j}. ${CA_NAME_LIST[${i}]}"
    done
    echo -n "Enter CA ID [$CAID]: "
    read -r CA_SELECTION
    [[ ${CA_SELECTION} -ge 1 ]] && \
      [[ ${CA_SELECTION} -le ${#CA_ID_LIST[@]} ]] && \
      CA_SELECTION=$(( CA_SELECTION -1 )) && \
      CAID=${CA_ID_LIST[${CA_SELECTION}]} && \
      CA_SELECTION_VALID="TRUE"
    [[ "${CA_SELECTION}" == "" ]] && \
      [[ "${CAID}" != "" ]] && \
      CA_SELECTION_VALID="TRUE"
  done
  export CAID
}

get_profiles_list() {
  PROFILES_LIST=$(curl  --header "Accept: application/json" -H "Content-Type: application/json" --cert-type P12 --cert "$P12":"$P12_PWD" "$CAGW_URL/v1/certificate-authorities/${CAID}/profiles" 2>/dev/null)
  PROFILE_ID_LIST=()
  while read -r line; do PROFILE_ID_LIST+=("$line"); done < <(echo "$PROFILES_LIST" | jq -r '.profiles[].id')
  export PROFILE_ID_LIST
}

prompt_for_profileID () {
  get_profiles_list
  printf '%s\n' "Select a Profile ID:"
  PROFILE_SELECTION_VALID="FALSE"
  PROFILE_ID_SELECTION=""
  while [[ "${PROFILE_SELECTION_VALID}" == "FALSE" ]]; do
    for ((i = 0 ; i < ${#PROFILE_ID_LIST[@]} ; i++ )); do
      j=$(( i + 1 ))
      echo "${j}. ${PROFILE_ID_LIST[${i}]}"
    done
    echo -n "Enter Profile ID [$PROFILE_ID]: "
    read -r PROFILE_ID_SELECTION
    [[ ${PROFILE_ID_SELECTION} -ge 1 ]] && \
      [[ ${PROFILE_ID_SELECTION} -le ${#PROFILE_ID_LIST[@]} ]] && \
      PROFILE_ID_SELECTION=$(( PROFILE_ID_SELECTION -1 )) && \
      PROFILE_ID=${PROFILE_ID_LIST[${PROFILE_ID_SELECTION}]} && \
      PROFILE_SELECTION_VALID="TRUE"
    [[ "${PROFILE_ID_SELECTION}" == "" ]] && \
      [[ "${PROFILE_ID}" != "" ]] && \
      PROFILE_SELECTION_VALID="TRUE"
  done
  export PROFILE_ID
}

# identify_ca accepts a CAID as a paremeter. Returns with a formatted string to identify Root and Issuing CAs.
identify_ca () {
  CAID="${1}"
  # /v1/certificate-authorities/{caId}/profiles/{profileId}
  PROFILES_RESPONSE=$(curl  --header "Accept: application/json" -H "Content-Type: application/json" --cert-type P12 --cert "$P12":"$P12_PWD" "$CAGW_URL/v1/certificate-authorities/${CAID}/profiles" 2>/dev/null)
  PROFILES=$(echo "${PROFILES_RESPONSE}" | jq -r --arg profile "basic-ca-subord" '.profiles[] | select(.id == $profile) | .id')
  [[ -n "${PROFILES// }" ]] || echo "Issuing-CA: ${CAID}"
  [[ -n "${PROFILES// }" ]] && echo "Root-CA: ${CAID}"
}

sanitize_cert_events () {
  printf '\n%s\n' "Processing certificiate events..."
  FILENAME="${1}"
  FILECOUNT=1
  JSON_FILENAME="${FILENAME}.${FILECOUNT}.json"

  echo "Searching for revoked certificate events..."
  REVOKED_SN_LIST=()
  while [[ -f "${JSON_FILENAME}" ]]; do
    while read -r line; do REVOKED_SN_LIST+=("$line"); done < <(jq -r --arg status "revoked" '.[] | select(.action == $status) | ."serialNumber"' "${JSON_FILENAME}")
    FILECOUNT=$(( FILECOUNT + 1 ))
    JSON_FILENAME="${FILENAME}.${FILECOUNT}.json"
  done

  #Calculate total number of cert events:
  FILECOUNT=$(( FILECOUNT - 1 ))
  JSON_FILENAME="${FILENAME}.${FILECOUNT}.json"
  FILECOUNT=$(( FILECOUNT - 1 ))
  TOTAL_EVENT_COUNT=$(jq -r '. | length' "${JSON_FILENAME}")
  TOTAL_EVENT_COUNT=$(( (FILECOUNT * PAGE_SIZE) + TOTAL_EVENT_COUNT ))
  #Done calculation of total events (needed to print out the final stats at the end)

  REVOKED_SN_COUNT="${#REVOKED_SN_LIST[@]}"
  printf '%s\n' "Removing ${REVOKED_SN_COUNT} revoked certificate entries..."
  for (( i = 0 ; i < REVOKED_SN_COUNT ; i++ )); do
    FILECOUNT=1
    JSON_FILENAME="${FILENAME}.${FILECOUNT}.json"
    while [[ -f "${JSON_FILENAME}" ]]; do
      SN="${REVOKED_SN_LIST[${i}]}"
      SANITIZED=$(jq -r --arg sn "${SN}" 'del(.[] | select(."serialNumber" == $sn))' "${JSON_FILENAME}")
      echo "${SANITIZED}" > "${JSON_FILENAME}"
      FILECOUNT=$(( FILECOUNT + 1 ))
      JSON_FILENAME="${FILENAME}.${FILECOUNT}.json"
    done
    [[ $(( REVOKED_SN_COUNT / 10 )) -ne 0 ]] && 
      [[ $(( (i+1) % (REVOKED_SN_COUNT / 10) )) -eq 0 ]] && 
      printf '%s\n' "Removed $(( (i+1) * 2 )) of $(( REVOKED_SN_COUNT * 2 )) revoked certificate events."
  done
  
  #Calculate number certificate events remaining after removing revoked certificates
  FILECOUNT=1
  JSON_FILENAME="${FILENAME}.${FILECOUNT}.json"
  SANITIZED_EVENT_COUNT=0
  while [[ -f "${JSON_FILENAME}" ]]; do
    SANITIZED_EVENT_COUNT=$(( SANITIZED_EVENT_COUNT + $(jq -r '. | length' "${JSON_FILENAME}") ))
    FILECOUNT=$(( FILECOUNT + 1 ))
    JSON_FILENAME="${FILENAME}.${FILECOUNT}.json"
  done
  #Done calculating number of events remaining

  # Extract Subject and Expiry Date for each certificate
  printf '%s\n' "Extracting certificate details..."
  EXPIRED_COUNT=0
  FILECOUNT=1
  JSON_FILENAME="${FILENAME}.${FILECOUNT}.json"
  CSV="${FILENAME}.csv"
  printf '%s\n' '"Action","Issued Date","Status","Subject","Expiry Date","Serial Number","Certificate"' > "${CSV}"
  EVENTS_PROCESSED=0
  while [[ -f "${JSON_FILENAME}" ]]; do
    EVENTCOUNT_IN_FILE=$(jq -r '. | length' "${JSON_FILENAME}")
    for (( i=0 ; i < EVENTCOUNT_IN_FILE ; i++ )); do
      CERT=$(printf '%s\n%s\n%s' "-----BEGIN CERTIFICATE-----" "$(jq -r --argjson i ${i} '.[$i]."certificate"' "${JSON_FILENAME}")" "-----END CERTIFICATE-----")
      SUBJECT=$(printf '%s' "$CERT" | openssl x509 -noout -subject -nameopt rfc2253 2>/dev/null)
      SUBJECT=${SUBJECT:8}
      EXPIRY=$(printf '%s' "$CERT" | openssl x509 -noout -enddate 2>/dev/null)
      EXPIRY=$( date -d "${EXPIRY:9}" +"%Y-%m-%dT%H:%M:%SZ")
      NOW=$(date +%s)
      END=$(date -d "${EXPIRY}" +%s)
      STATUS="Active"
      [[ ${NOW} -ge ${END} ]] && export STATUS="Expired" && (( EXPIRED_COUNT++ ))
      JSON=$(jq -r --argjson i ${i} --arg subject "${SUBJECT}" --arg expiry "${EXPIRY}" --arg status "${STATUS}" '.[$i] += { "Subject": $subject, "Expiry Date": $expiry, "Status": $status }' "${JSON_FILENAME}")
      echo "${JSON}" > "${JSON_FILENAME}"
    done
    EVENTS_PROCESSED=$(( EVENTS_PROCESSED + EVENTCOUNT_IN_FILE ))
    printf '%s\n' "Processed ${EVENTS_PROCESSED} of ${SANITIZED_EVENT_COUNT} non-revoked certificates"
    jq -r '.[] | [."action", ."eventDate", ."Status", ."Subject", ."Expiry Date", ."serialNumber", ."certificate"] | @csv' "${JSON_FILENAME}" >> "${CSV}"
    rm "${JSON_FILENAME}"
    FILECOUNT=$(( FILECOUNT + 1 ))
    JSON_FILENAME="${FILENAME}.${FILECOUNT}.json"
  done

  #Print out Summary
  printf '\n'
  printf '%s\n' "Fetched a total of ${TOTAL_EVENT_COUNT} certificate events"
  printf '%s\n' "Removed $(( TOTAL_EVENT_COUNT - SANITIZED_EVENT_COUNT )) revoked certificates entries (this is typically double the number of revoked certificates)"
  printf '%s\n' "CSV Contains ${EXPIRED_COUNT} expired certificates"
  printf '%s\n' "CSV Contains $(( SANITIZED_EVENT_COUNT - EXPIRED )) active certificate"
  printf '%s\n' "CSV File: $(readlink -f "${CSV}")"
}

get_action_type () {
	printf '%s\n' "Select action type from below"
	echo -n "1. Revoke
2. Renew
3. Reissue
"
  ACTION_TYPE_ID=0
  read -rp "Action Type: " ACTION_TYPE_ID
  while [[ ${ACTION_TYPE_ID} -lt 1 || ${ACTION_TYPE_ID} -gt 3  ]]; do
    printf '%s\n' "bad selection: ${ACTION_TYPE_ID}"
	  read -rp "Action Type: " ACTION_TYPE_ID
  done

  [[ ${ACTION_TYPE_ID} -eq 1 ]] && printf -v "ACTION_TYPE" "%s" "RevokeAction" && return
  [[ ${ACTION_TYPE_ID} -eq 2 ]] && printf -v "ACTION_TYPE" "%s" "RenewAction" && return
  [[ ${ACTION_TYPE_ID} -eq 3 ]] && printf -v "ACTION_TYPE" "%s" "ReissueAction" && return
}
get_action_reason () {
	echo -n "Select action reason from below"
	printf "\n"
	echo "1. unspecified
2. keyCompromise
3. caCompromise
4. affiliationChanged
5. superseded
6. cessationOfOperation
7. certificateHold
8. privilegeWithdrawn
"

  ACTION_REASON_ID=0
  read -rp "Action Reason: " ACTION_REASON_ID
  while [[ ${ACTION_REASON_ID} -lt 1 || ${ACTION_REASON_ID} -gt 8  ]]; do
    printf '%s\n' "bad selection: ${ACTION_REASON_ID}"
	  read -rp "Action Reason: " ACTION_REASON_ID
  done
  [[ ${ACTION_REASON_ID} -eq 1 ]] && export ACTION_REASON="unspecified" && return
  [[ ${ACTION_REASON_ID} -eq 2 ]] && export ACTION_REASON="keyCompromise" && return
  [[ ${ACTION_REASON_ID} -eq 3 ]] && export ACTION_REASON="caCompromise" && return
  [[ ${ACTION_REASON_ID} -eq 4 ]] && export ACTION_REASON="affiliationChanged" && return
  [[ ${ACTION_REASON_ID} -eq 5 ]] && export ACTION_REASON="superseded" && return
  [[ ${ACTION_REASON_ID} -eq 6 ]] && export ACTION_REASON="cessationOfOperation" && return
  [[ ${ACTION_REASON_ID} -eq 7 ]] && export ACTION_REASON="certificateHold" && return
  [[ ${ACTION_REASON_ID} -eq 8 ]] && export ACTION_REASON="privilegeWithdrawn" && return
}
get_subject_altnames() {
	echo -n "Do you want to add a Subject Alternate Name (Y/N): "

  SAN_NEEDED=""
  read -r SAN_NEEDED
  SAN_NEEDED=$(echo "$SAN_NEEDED" | tr '[:lower:]' '[:upper:]')
  while [[ "${SAN_NEEDED}" != "Y" && "${SAN_NEEDED}" != "N" ]]; do
    printf '%s\n' "bad selection: ${SAN_NEEDED}"
	  read -r SAN_NEEDED
    SAN_NEEDED=$(echo "$SAN_NEEDED" | tr '[:lower:]' '[:upper:]')
  done

  # Exit out of get_subject_altnames() if "SAN_NEEDED" is "N"
  [[ "${SAN_NEEDED}" == "N" ]] && [[ "$SAN_ARRAY" == "[" ]] && printf -v "SAN_ARRAY" "%s" "[]" && return
  [[ "${SAN_NEEDED}" == "N" ]] && [[ "$SAN_ARRAY" != "[" ]] && printf -v "SAN_ARRAY" "%s" "${SAN_ARRAY%?}]" && return

  echo -n "Select the SAN attribute to be added from the list "
  printf "\n"
  printf '%s\n' "  1. rfc822Name"
  printf '%s\n' "  2. dNSName"
  printf '%s\n' "  3. directoryName"
  printf '%s\n' "  4. uniformResourceIdentifier"
  printf '%s\n' "  5. iPAddress"
  printf '%s\n' "  6. registeredID"

  SAN_VAR_ID=0
  read -rp "SAN Type: " SAN_VAR_ID
  while [[ "${SAN_VAR_ID}" -lt 1 || "${SAN_VAR_ID}" -gt 6 ]]; do
    printf '%s\n' "bad selection: ${SAN_VAR_ID}"
    read -rp "SAN Type: " SAN_VAR_ID
  done
  
  #\"der\": \"string\",
  [[ $SAN_VAR_ID == "1" ]] && export SAN_VAR_NAME="rfc822Name"
  [[ $SAN_VAR_ID == "2" ]] && export SAN_VAR_NAME="dNSName"
  [[ $SAN_VAR_ID == "3" ]] && export SAN_VAR_NAME="directoryName"
  [[ $SAN_VAR_ID == "4" ]] && export SAN_VAR_NAME="uniformResourceIdentifier"
  [[ $SAN_VAR_ID == "5" ]] && export SAN_VAR_NAME="iPAddress"
  [[ $SAN_VAR_ID == "6" ]] && export SAN_VAR_NAME="registeredID"
  
  echo -n "Enter value of the selected SAN attribute (${SAN_VAR_NAME}): "
  SAN_VALUE=""
  while [[ "${SAN_VALUE}" == "" ]]; do
    read -r SAN_VALUE
  done
  
  printf -v "SAN_ARRAY" "%s" "${SAN_ARRAY}{\"type\": \"$SAN_VAR_NAME\",\"value\": \"$SAN_VALUE\"},"
  get_subject_altnames
}

enroll_csr() {
  # Prompt for CSR File Path
  while [[ ! -f "${CSR_INPUT_PATH}" ]]; do
    read -e -rp "Enter path to an existing CSR file ['$CSR_PATH']: " CSR_INPUT_PATH
    while [[ -z "$CSR_INPUT_PATH" ]] && [[ -z "${CSR_PATH}" ]]; do
      read -e -rp "Enter path to an existing CSR file ['$CSR_PATH']: " CSR_INPUT_PATH
    done
    [[ -z "$CSR_INPUT_PATH" ]] &&  printf -v "CSR_INPUT_PATH" "%s" "$CSR_PATH"
  done

  # Prompt for Certificate File Path
  CERT_PATH=""
  while [[ "${CERT_PATH}" == "" ]]; do
    read -e -rp "Where would you like to store the certificate (e.g. ./certificate.pem): " CERT_PATH
  done

  # Prompt for Certificate Subject DN
  CERT_OPT_PARAMS_SUBJECT_DN=""
  while [[ "${CERT_OPT_PARAMS_SUBJECT_DN}" == "" ]]; do
    echo -n "Enter full subject DN (i.e. cn=example.com): "
    read -r CERT_OPT_PARAMS_SUBJECT_DN
  done

  # Prompt for Certificate SAN Attributes
  SAN_ARRAY="["
  get_subject_altnames

  # Execute Curl Command
  RESPONSE=$(curl -s --header "Accept: application/json" -H "Content-Type: application/json" --data "{\"profileId\":\"$PROFILE_ID\",\"requiredFormat\":{\"format\":\"PEM\"},\"csr\":\"$(tr -d "\n\r" < "$CSR_INPUT_PATH")\",\"optionalCertificateRequestDetails\":{\"subjectDn\":\"$CERT_OPT_PARAMS_SUBJECT_DN\"},\"subjectAltNames\":$SAN_ARRAY}" --cert-type P12 --cert "$P12":"$P12_PWD" "${CAGW_URL}/v1/certificate-authorities/${CAID}/enrollments" 2>/dev/null)
  printf '%s\n%s\n' "Response:" "${RESPONSE}"
  cert_raw=$( echo "${RESPONSE}" | jq '.enrollment.body')
  var1=${cert_raw%?}
  var2=${var1:1}
  TMP_FILE=$(mktemp)
  echo "$var2" > "${TMP_FILE}"
  sed 's/\\n/\r\n/g' "${TMP_FILE}" > "${CERT_PATH}"
  rm -f TMP_FILE
  printf '\n%s\n' "Certificate is written successfully to the file ${CERT_PATH}".
}

enroll_p12() {
  # Prompt for P12 Password
  PASSWORD=""
  while [[ -z "${PASSWORD// }" ]]; do
    printf '%s' "Enter a password to secure the P12 file: "
    read -sr PASSWORD
    printf '\n'
  done

  # Prompt for Certificate File Path
  CERT_PATH=""
  while [[ "${CERT_PATH}" == "" ]]; do
    read -e -rp "Where would you like to store the certificate (e.g. ./certificate.p12): " CERT_PATH
  done

  # Prompt for Certificate Subject DN
  CERT_OPT_PARAMS_SUBJECT_DN=""
  while [[ "${CERT_OPT_PARAMS_SUBJECT_DN}" == "" ]]; do
    echo -n "Enter full subject DN (i.e. cn=example.com): "
    read -r CERT_OPT_PARAMS_SUBJECT_DN
  done

  # Prompt for Certificate SAN Attributes
  SAN_ARRAY="["
  get_subject_altnames

  # Execute Curl Command
  RESPONSE=$(curl -s --header "Accept: application/json" -H "Content-Type: application/json" --data "{\"profileId\":\"$PROFILE_ID\",\"requiredFormat\":{\"format\":\"PKCS12\",\"protection\":{\"type\":\"PasswordProtection\",\"password\":\"${PASSWORD}\"}},\"optionalCertificateRequestDetails\":{\"subjectDn\":\"$CERT_OPT_PARAMS_SUBJECT_DN\"},\"subjectAltNames\":$SAN_ARRAY}" --cert-type P12 --cert "$P12":"$P12_PWD" "${CAGW_URL}/v1/certificate-authorities/${CAID}/enrollments" 2>/dev/null)
  echo "${RESPONSE}" | jq -r '.enrollment.body' | base64 -d > "${CERT_PATH}"
  printf '\n%s\n' "Certificate is written successfully to the file ${CERT_PATH}".
}

main() {

	printf '\n%s\n%s\n' "--------------------------" "Select the CA Gateway operation:"
  printf '%s\n' "  1. Generate CSR with subject (using OpenSSL)"
  printf '%s\n' "  2. List all Certificate Authorities"
  printf '%s\n' "  3. List all profiles for a Certificate Authority"
  printf '%s\n' "  4. Enroll new certificate"
  printf '%s\n' "  5. Certificate revocation by serial"
  printf '%s\n' "  6. Bulk certificate issuance"
  printf '%s\n' "  7. Bulk certificate revocation"
  printf '%s\n' "  8. Fetch all active certificates"
  printf '%s\n' "  9. Revoke Certificates by Subject DN (On-Premises CAGW Only)"
  printf '%s\n' "  10. Exit"
	read -rp "Selection: " CAGW_OP

  case ${CAGW_OP} in

  1)
    printf '%s\n' "--------------------------"
    printf '%s\n%s\n' "Enter full subject" "Example: /C=CA/ST=Ontario/L=Ottawa/O=My Org/OU=IT/CN=example.com"
		read -r CSR_SUBJECT
		read -rp "Enter key type: " KEY_TYPE
		read -rp "Enter key length: " KEY_LEN
    read -e -rp "Where would you like to store the key (e.g. /tmp/example.key): " KEY_PATH
    read -e -rp "Where would you like to store the CSR (e.g. /tmp/example.csr): " CSR_PATH
		openssl req -nodes -newkey "$KEY_TYPE":"$KEY_LEN" -keyout "$KEY_PATH" -out "$CSR_PATH" -subj "$CSR_SUBJECT" &> /dev/null
		sed -i 1d "$CSR_PATH" &> /dev/null
		sed -i '' -e '$ d' "$CSR_PATH" &> /dev/null
		main
    ;;
  2)
    printf '%s\n' "--------------------------"
    curl  --header "Accept: application/json" -H "Content-Type: application/json" --cert-type P12 --cert "$P12":"$P12_PWD" "$CAGW_URL/v1/certificate-authorities"
    printf '\n'
		main
    ;;
  3)
    printf '%s\n' "--------------------------"
    prompt_for_caid
		curl  --header "Accept: application/json" -H "Content-Type: application/json" --cert-type P12 --cert "$P12":"$P12_PWD" "$CAGW_URL/v1/certificate-authorities/$CAID/profiles"
    printf '\n'
		main
    ;;
  4)
    printf '%s\n' "--------------------------"
    # Prompt for CAID
    prompt_for_caid

    # Prompt for Profile ID
    prompt_for_profileID

    # Prompt for enrollment method
    METHOD=0
    while [[ ${METHOD} -lt 1 || ${METHOD} -gt 2 ]]; do
      printf '%s\n%s\n%s\n' "Select an enrollment type:" "  1. CSR" "  2. PKCS #12"
      read -rp "Enrollment Type: " METHOD
    done

    [[ ${METHOD} -eq 1 ]] && enroll_csr
    [[ ${METHOD} -eq 2 ]] && enroll_p12
		main
    ;;
  5)
    printf '%s\n' "--------------------------"
    prompt_for_caid
    while [[ "${CERTIFICATE_SERIAL}" == "" ]]; do
		  echo -n "Enter certificate serial number in hexadecimal format (Example: 0000000091ca4b4b136a86b718ae01a5403ce62b): "
		  read -r CERTIFICATE_SERIAL	
    done
		get_action_type
		read -rp "Enter a comment about the action (optional): " COMMENT
		get_action_reason
		curl --header "Accept: application/json" -H "Content-Type: application/json" --data "{\"action\":{\"comment\":\"$COMMENT\",\"type\":\"$ACTION_TYPE\",\"reason\":\"$ACTION_REASON\"}}" --cert-type P12 --cert "$P12":"$P12_PWD" "$CAGW_URL/v1/certificate-authorities/$CAID/certificates/$CERTIFICATE_SERIAL/actions" 2> /dev/null
    RESULT="${?}"
    [[ ${RESULT} -ne 0 ]] && echo "ERROR!!"
		main
    ;;
  6)
    printf '%s\n' "--------------------------"
    prompt_for_caid
    prompt_for_profileID
    echo "Note, this operation requires a CSV-formatted file in the following format:"
    echo "Common Name, Key Algorithm, Key Size"
    echo "For example:"
    echo "example common name, rsa, 4096"
    ISSUE_CSV=""
    while [[ ! -f "${ISSUE_CSV}" ]]; do
		  read  -e -rp "Enter the path to the CSV file: " ISSUE_CSV
    done
    TARGET_FOLDER=""
    while [[ ! -d "${TARGET_FOLDER}" ]]; do
		  read -e -rp "Enter the path for saving keys and certs: " TARGET_FOLDER
    done
    BULK_COUNT=$(wc -l < "${ISSUE_CSV}" | tr -d ' ')
    PROCESSED_COUNT=0
    printf '%s\n' "Processing list of ${BULK_COUNT} bulk certificate enrollments..."
		{
			read -r
			while IFS=, read -r commonName keyLen keyAlgo
			do 
				openssl req -nodes -newkey "${keyAlgo}":"${keyLen}" -keyout "$TARGET_FOLDER/${commonName}.key" -out "$TARGET_FOLDER/${commonName}.csr" -subj "/CN=$commonName" &> /dev/null
				sed -i 1d "${TARGET_FOLDER}/${commonName}.csr" &> /dev/null
				sed -i '' -e '$ d' "${TARGET_FOLDER}/${commonName}.csr" &> /dev/null
				RESPONSE=$(curl -s --header "Accept: application/json" -H "Content-Type: application/json" --data "{\"profileId\":\"$PROFILE_ID\",\"requiredFormat\":{\"format\":\"PEM\"},\"csr\":\"$(tr -d "\n\r" < "${TARGET_FOLDER}/${commonName}.csr")\",\"optionalCertificateRequestDetails\":{\"subjectDn\":\"CN=$commonName\"}}" --cert-type P12 --cert "$P12":"$P12_PWD" "$CAGW_URL/v1/certificate-authorities/$CAID/enrollments" 2>/dev/null)
				cert_raw=$( echo "${RESPONSE}" | jq '.enrollment.body')
				var1=${cert_raw%?}
				var2=${var1:1}
        TMP_FILE=$(mktemp)
				echo "$var2" > "${TMP_FILE}"
				sed 's/\\n/\r\n/g' "${TMP_FILE}" > "${TARGET_FOLDER}/${commonName}.pem"
				rm -f TMP_FILE
        PROCESSED_COUNT=$(( PROCESSED_COUNT + 1 ))
        [[ $(( (PROCESSED_COUNT) % PAGE_SIZE )) -eq 0 ]] && printf '%s\n' "Processed ${PROCESSED_COUNT} certificate requests of ${BULK_COUNT}."
			done
		} < "${ISSUE_CSV}"
		printf '%s\n' "Certificates and Keys written to the folder $(readlink -f "${TARGET_FOLDER}")"
		main
    ;;
  7)
    printf '%s\n' "--------------------------"
    REVOKE_CSV=""
    while [[ ! -f "${REVOKE_CSV}" ]]; do
		  read -e -rp  "Enter the path to the CSV file: " REVOKE_CSV
    done
    prompt_for_caid
    HEADERS_INCLUDED=""
    read -rp "Does the CSV File contain a row of headers (Y/N): " HEADERS_INCLUDED
    HEADERS_INCLUDED=$(echo "$HEADERS_INCLUDED" | tr '[:lower:]' '[:upper:]')
    while [[ "${HEADERS_INCLUDED}" != "Y" && "${HEADERS_INCLUDED}" != "N" ]]; do
      printf '%s\n' "bad selection: ${HEADERS_INCLUDED}"
      read -rp "Does the CSV File contain a row of headers (Y/N): " HEADERS_INCLUDED
      HEADERS_INCLUDED=$(echo "$HEADERS_INCLUDED" | tr '[:lower:]' '[:upper:]')
    done
    get_action_reason
    [[ "${HEADERS_INCLUDED}" == "Y" ]] && export headers=0
    [[ "${HEADERS_INCLUDED}" == "N" ]] && export headers=1
    OLDIFS=$IFS
    IFS=','
    snToRevoke=0
    while read dummy1 sn dummy2; do
      if test "$headers" == "0"; then
        headers=1
        continue
      fi
      if test "$snToRevoke" != "0"; then
        echo "REVOKE SN : $snToRevoke"
        curl --header "Accept: application/json" -H "Content-Type: application/json" --data "{\"action\":{\"type\":\"RevokeAction\",\"reason\":\"$ACTION_REASON\"}}" --cert-type P12 \
          --cert "$P12":"$P12_PWD" "$CAGW_URL/v1/certificate-authorities/$CAID/certificates/$snToRevoke/actions"
        res=$?
        if test "$res" != "0"; then
          echo "ERROR!!!: $res"
        fi
      fi
      snToRevoke=$(printf '%s' "$sn" | tr -d '\r')

    done <"$REVOKE_CSV"

    echo "REVOKE SN : $snToRevoke"
    curl --header "Accept: application/json" -H "Content-Type: application/json" --data "{\"action\":{\"type\":\"RevokeAction\",\"reason\":\"$ACTION_REASON\",\"issueCrl\":\"true\"}}" \
      --cert-type P12 --cert "$P12":"$P12_PWD" "$CAGW_URL/v1/certificate-authorities/$CAID/certificates/$snToRevoke/actions"
    res=$?
    if test "$res" != "0"; then
      echo "ERROR!!!: $res"
    fi

    IFS=$OLDIFS

		main
    ;;
  8)
    printf '%s\n' "--------------------------"
    prompt_for_caid
    # Create CSV File with headers
    FILENAME="certificates_report_${CAID}_$(date +%s)"
    CSV_FILENAME="${FILENAME}.csv"
    printf '%s\n' '"Action","Event Date","Certificate","Serial Number"' > "${CSV_FILENAME}"
    # Run initial CURL command to fetch first page of certificates
    printf '\n%s\n' "Fetching list of certificate events..."
    CURL_OUTPUT=$(curl -s --header "Accept: application/json" -H "Content-Type: application/json" --cert-type P12 --cert "$P12":"$P12_PWD" "$CAGW_URL/v1/certificate-authorities/$CAID/certificate-events?preferredPageSize=${PAGE_SIZE}&startDate=2024-01-01T00:00:00.00Z"  2>/dev/null)
    NEXT_PAGE_INDEX=$(echo "${CURL_OUTPUT}" | jq -r '.nextPageIndex')
    MORE_PAGES=$(echo "${CURL_OUTPUT}" | jq -r '.morePages')
    TOTAL_CERT_EVENTS=$(echo "${CURL_OUTPUT}" | jq -r '.events | length')

    FILECOUNT=1
    JSON_FILENAME="${FILENAME}.${FILECOUNT}.json"
    echo "${CURL_OUTPUT}" | jq '.events' > "${JSON_FILENAME}"

    [[ ${CAGW_TYPE} -eq 1 ]] && echo "CAGW API requests to fetch certificate events are limited to 50 events per page when using PKIaaS."
    while [[ ${MORE_PAGES} == "true" ]]; do
      echo "Fetched ${TOTAL_CERT_EVENTS}. Fetching next batch of ${PAGE_SIZE} certificate events."
      CURL_OUTPUT=$(curl -s --header "Accept: application/json" -H "Content-Type: application/json" --cert-type P12 --cert "$P12":"$P12_PWD" "$CAGW_URL/v1/certificate-authorities/$CAID/certificate-events?preferredPageSize=${PAGE_SIZE}&startDate=2000-01-01T00:00:00.00Z&nextPageIndex=$NEXT_PAGE_INDEX"  2>/dev/null)
      NEXT_PAGE_INDEX=$(echo "${CURL_OUTPUT}" | jq -r '.nextPageIndex')
      MORE_PAGES=$(echo "${CURL_OUTPUT}" | jq -r '.morePages')
      TOTAL_CERT_EVENTS=$(( TOTAL_CERT_EVENTS + $(echo "${CURL_OUTPUT}" | jq -r '.events | length') ))
      FILECOUNT=$(( FILECOUNT + 1 ))
      JSON_FILENAME="${FILENAME}.${FILECOUNT}.json"
      echo "${CURL_OUTPUT}" | jq -r '.events' > "${JSON_FILENAME}"
      unset CURL_OUTPUT
    done
    sanitize_cert_events "${FILENAME}"
		main
    ;;
  9)
    printf '%s\n' "--------------------------"
    [[ "${CAGW_TYPE}" -eq 1 ]] && echo "The CAGW API for PKIaaS does not support this feature." && main
    prompt_for_caid
    SUBJECT_DN=""
    while [[ -z "${SUBJECT_DN// }" ]]; do 
      read -rp "Subject DN: " SUBJECT_DN
    done
    get_action_type
		read -rp "Enter a comment about the action (optional): " COMMENT
		get_action_reason
    curl -s --header "Accept: application/json" -H "Content-Type: application/json" --cert-type P12 --cert "$P12":"$P12_PWD"  --data "{\"action\":{\"comment\":\"$COMMENT\",\"type\":\"$ACTION_TYPE\",\"reason\":\"$ACTION_REASON\"}}" "$CAGW_URL/v1/certificate-authorities/$CAID/subjects/$(printf '%s' "${SUBJECT_DN}" | jq -sRr @uri)/actions"  2>/dev/null
    main
    ;;
  10)
    exit
    ;;
  *)
  printf '%s\n' "Invalid Selection"
    main
    ;;
esac
}

printf '%s\n%s\n%s\n' "--------------------------" "Entrust CA Gateway Utility" "--------------------------"

get_client_credentials
printf '%s\n' "--------------------------"
printf '%s\n' "CAGW P12: ${P12}"
printf '%s\n' "CAGW URL: ${CAGW_URL}"
main