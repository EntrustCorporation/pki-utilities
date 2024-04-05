#!/usr/bin/env bash

# NOTE: Any modifications to this file are made at your own risk. Customer Support will not provide assistance for a modified script.

# Script Requirements:
# - Trusted TLS Connection from script to an On-Prem CAGW or to PKIaaS
# - CAGW Client Credential: A P12 file containing only a single private key.

# Package Requirements:
#  - Bash v4.4+
#  - curl v7.81+
#  - jq
#  - pkill
#  - awk
#  - openssl

# Options:
# MAX_THREADS_DEFAULT
#   - Defines the maximum number of concurrent subprocesses that can be spawned by the script.
#   - Recommended to set this value to the number of CPU Cores
MAX_THREADS_DEFAULT=10
# PATH_FOR_TMP_WORKING_DIR:
#   - Path to folder to use for temporary files.
#   - This folder will be created if it doesn't exist
PATH_FOR_TMP_WORKING_DIR="./tmp_working_dir"
# CLEANUP:
#   - When value is '1': Delete the folder of temporary files (defined by PATH_FOR_TMP_WORKING_DIR).
#   - When value is '0'; Don't delete the folder of temporary files (defined by PATH_FOR_TMP_WORKING_DIR).
CLEANUP=1
# REPORT_START_DATE
#   - Setting is used to define the start date to use when generating a report of Active Certificates
#   - Default value should be adequate in most cases.
#   - Default value: 2000-01-01T00:00:00.00Z
REPORT_START_DATE="2000-01-01T00:00:00.00Z"
# INSECURE_TLS
#   - Enable this setting to curl with untrusted TLS Connections
#   - Default Value: 0
#   - To enabled the setting, use a value of: 1
INSECURE_TLS=1

# START: CONSTANTS - Do not modify
DIVIDER="--------------------------"
CURL_COMMAND="curl"
[[ "${INSECURE_TLS}" -eq 1 ]] && CURL_COMMAND="curl -k"
REQ_CURL_VER="7.81"
REQ_OPENSSL_VER="3.0.0"
PKIAAS=1
ONPREM=2
DIR="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "${PATH_FOR_TMP_WORKING_DIR}"
TMP_WORKING_DIR="$(cd "${PATH_FOR_TMP_WORKING_DIR}" && pwd)"
STDOUT="${TMP_WORKING_DIR}/stdout_$(date +%s)"
STDERR="${TMP_WORKING_DIR}/stderr_$(date +%s)"
P12_CERT="${TMP_WORKING_DIR}/p12cert_$(date +%s)"
P12_KEY="${TMP_WORKING_DIR}/p12key_$(date +%s)"
P12_CA="${TMP_WORKING_DIR}/p12ca_$(date +%s)"
DN_OPTIONS=(
  "CN"
  "SN"
  "serialNumber"
  "C"
  "L"
  "ST"
  "street"
  "O"
  "OU"
  "title"
  "businessCategory"
  "postalCode"
  "givenName"
  "initials"
  "organizationIdentifier"
  "UID"
  "DC"
  "emailAddress"
  "unstructuredName"
  "unstructuredAddress"
)
KEY_USAGES=(
  "nonRepudiation"
  "digitalSignature"
  "keyEncipherment"
)
EKUS=(
  "serverAuth"
  "clientAuth"
  "codeSigning"
  "emailProtection"
)
SANS=(
  "email"
  "DNS"
  "URI"
  "IP"
  "RID"
)
# END: CONSTANTS


exit_and_cleanup() {
  EXIT_STATUS="${1}"
  [[ "${CLEANUP}" -eq 1 ]] && rm -rf "${TMP_WORKING_DIR}"
  printf '\n%s\n' "Exiting with exit status '${EXIT_STATUS}'"
  # Kill all child processes using pkill
  pkill -P $$
  exit "${EXIT_STATUS}"
}

# trap ctrl-c and call ctrl_c() to gracefully exit and cleanup.
trap ctrl_c INT

function ctrl_c() {
  exit_and_cleanup 0
}

vercomp () {
  ACTUAL="${1}"
  EXPECTED="${2}"
  [[ "${ACTUAL}" == "${EXPECTED}" ]] && return 0
  local IFS=.
  local i ver1=("${ACTUAL}") ver2=("${EXPECTED}")
  # fill empty fields in ver1 with zeros
  for ((i=${#ver1[@]}; i<${#ver2[@]}; i++))
  do
      ver1[i]=0
  done
  for ((i=0; i<${#ver1[@]}; i++))
  do
    # fill empty fields in ver2 with zeros
    [[ -z ${ver2[i]} ]] && ver2[i]=0
    [[ ((10#${ver1[i]} > 10#${ver2[i]})) ]] && return 1
    [[ ((10#${ver1[i]} < 10#${ver2[i]})) ]] && return 2
  done
  return 0
}

print_deps() {
  printf '%s\n%s\n%s\n' "${DIVIDER}" "Depedencies" "${DIVIDER}"
  CURL_VERSION=$(curl --version | head -c 11 | sed 's/[^0-9.]//g')
  OPENSSL_VERSION=$(openssl version | head -c 15 | sed 's/[^0-9.]//g')
  BASH_VERSION=$(env bash --version | head -1)
  echo "OpenSSL: ${OPENSSL_VERSION}"
  echo "Curl: ${CURL_VERSION}"
  echo "JQ: $(jq --version)"
  echo "Bash: ${BASH_VERSION}"
  # Analyze OpenSSL and Curl versions to determine how they should be used.
  vercomp "${CURL_VERSION}" "${REQ_CURL_VER}"; RESULT=$?
  [[ "${RESULT}" -eq 2 ]] && CURL_VERSION="OLD"
  vercomp "${OPENSSL_VERSION}" "${REQ_OPENSSL_VER}"; RESULT=$?
  [[ "${RESULT}" -eq 2 ]] && OPENSSL_VERSION="OLD"
}

# special_curl executes curl differently depending on the curl version.
# older versions of curl do not support P12 files.
prep_p12_for_curl() {
  if [[ "${OPENSSL_VERSION}" == "OLD" ]]; then
    openssl pkcs12 -info -in "${P12}" -password pass:"${P12_PWD}" -nodes 2>"${STDERR}" 1>"${STDOUT}"; RESULT=$?
    [[ "${RESULT}" -ne 0 ]] && printf '%s\n' "Error: $(cat "${STDERR}")" && exit_and_cleanup "${RESULT}"
    sed -ne '/-BEGIN PRIVATE KEY-/,/-END PRIVATE KEY-/p' < "${STDOUT}" > "${P12_KEY}"
    openssl pkcs12 -info -in "${P12}" -password pass:"${P12_PWD}" -clcerts -nokeys -nodes 2>"${STDERR}" 1>"${STDOUT}"; RESULT=$?
    [[ "${RESULT}" -ne 0 ]] && printf '%s\n' "Error: $(cat "${STDERR}")" && exit_and_cleanup "${RESULT}"
    sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' < "${STDOUT}" > "${P12_CERT}"
    openssl pkcs12 -info -in "${P12}" -password pass:"${P12_PWD}" -clcerts -nokeys -chain -nodes 2>"${STDERR}" 1>"${STDOUT}"; RESULT=$?
    [[ "${RESULT}" -ne 0 ]] && printf '%s\n' "Error: $(cat "${STDERR}")" && exit_and_cleanup "${RESULT}"
    sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' < "${STDOUT}" > "${P12_CA}"
  else
    openssl pkcs12 -legacy -info -in "${P12}" -password pass:"${P12_PWD}" -nodes 2>"${STDERR}" 1>"${STDOUT}"; RESULT=$?
    [[ "${RESULT}" -ne 0 ]] && printf '%s\n' "Error: $(cat "${STDERR}")" && exit_and_cleanup "${RESULT}"
    sed -ne '/-BEGIN PRIVATE KEY-/,/-END PRIVATE KEY-/p' < "${STDOUT}" > "${P12_KEY}"
    openssl pkcs12 -legacy -info -in "${P12}" -password pass:"${P12_PWD}" -clcerts -nokeys -nodes 2>"${STDERR}" 1>"${STDOUT}"; RESULT=$?
    [[ "${RESULT}" -ne 0 ]] && printf '%s\n' "Error: $(cat "${STDERR}")" && exit_and_cleanup "${RESULT}"
    sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' < "${STDOUT}" > "${P12_CERT}"
    openssl pkcs12 -legacy -info -in "${P12}" -password pass:"${P12_PWD}" -clcerts -nokeys -chain -nodes 2>"${STDERR}" 1>"${STDOUT}"; RESULT=$?
    [[ "${RESULT}" -ne 0 ]] && printf '%s\n' "Error: $(cat "${STDERR}")" && exit_and_cleanup "${RESULT}"
    sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' < "${STDOUT}" > "${P12_CA}"
  fi
}

init() {
  print_deps
  printf '%s\n%s\n%s\n' "${DIVIDER}" "Entrust CA Gateway Utility" "${DIVIDER}"
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
    if [[ "${OPENSSL_VERSION}" == "OLD" ]]; then
      openssl pkcs12 -in "${P12}" -password pass:"${P12_PWD}" -nokeys 2>"${STDERR}" 1>"${STDOUT}"; RESULT=$?
    else
      openssl pkcs12 -legacy -in "${P12}" -password pass:"${P12_PWD}" -nokeys 2>"${STDERR}" 1>"${STDOUT}"; RESULT=$?
    fi
    [[ "${RESULT}" -ne 0 ]] && cat "${STDERR}"
  done


  CAGW_TYPE=0
  printf '%s\n' "Please select the CAGW type:"
  printf '%s\n' "  1. PKIaaS"
  printf '%s\n' "  2. On-Premises"
  while [[ "${CAGW_TYPE}" != "${PKIAAS}" && "${CAGW_TYPE}" != "${ONPREM}" ]]; do
    read -rp "CAGW Type: " CAGW_TYPE
  done
  [[ "${CAGW_TYPE}" -eq "${PKIAAS}" ]] && export PAGE_SIZE=50
  [[ "${CAGW_TYPE}" -eq "${ONPREM}" ]] && PAGE_SIZE=100

  CAGW_REGION=0
  case "${CAGW_TYPE}" in
    "${PKIAAS}")
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
      ;;
    "${ONPREM}")
      read -rp "Enter CA Gateway URL (e.g. https://cagw-server.com/cagw): " CAGW_URL
      while [[ -z "${CAGW_URL// }" ]]; do
        read -rp "Enter CA Gateway URL (e.g. https://cagw-server.com/cagw): " CAGW_URL
      done
      ;;
    *)
      ;;
  esac
  [[ "${CURL_VERSION}" == "OLD" ]] && prep_p12_for_curl
  printf '%s\n' "${DIVIDER}"
  printf '%s\n' "CAGW P12: ${P12}"
  printf '%s\n' "CAGW URL: ${CAGW_URL}"
}

# Arg1: Indexed array of pids to wait
# Arg2: Associative array to map a pid with its output file
function wait_pids {
  _pids="$1[@]"

  var=$(declare -p "$2")
  eval "declare -A _tmpFiles="${var#*=}

  pendingToVisit=true
  save=$-
  exitCodes=()
  visitedPids=()
  while $pendingToVisit; do
    pendingToVisit=false
    for pid in ${!_pids}; do
      # Check if pid is not visited yet
      if [[ "${visitedPids[*]}" =~ "${pid}" ]]; then
        continue
      fi
      pendingToVisit=true

      # Check if PID is running
      set +e
      kill -s 0 $pid 2> /dev/null
      exitCode=$?
      set -e
      if [[ $exitCode -ne 0 ]]; then
        visitedPids+=( $pid )
        
        set +e
        wait $pid
        pidExitCode=$?
        exitCodes[$pid]=$pidExitCode
        set -e

        file=${_tmpFiles[$pid]}
        if [[ "$file" == "" ]]; then
          fatal "ERROR: No output file found for $pid pid"
        fi

        if [[ $pidExitCode -ne 0 ]]; then
          echo "ERROR:$pidExitCode"
          cat $file
        fi
        rm $file
      fi
      set -e
    done
    sleep 0.5
  done

  # Exit if some child failed
  for pid in ${!exitCodes[@]}; do
    exit_code=${exitCodes[$pid]} 
    if [[ $exit_code -ne 0 ]]; then
      echo "ERROR exit pid:$pid"
      exit $exit_code
    fi
  done

  # Configure $- as it was before
  if [[ $save =~ e ]]; then
    set -e
  else
    set +e
  fi
}

# Arg1: Command to execute in a background process
# Arg2: Array where background process pid will be added
# Arg3: Array to map a pid with its outputfile
function parallel_exec {
  _command="$1"
  _pids="$2"
  _tmpFiles="$3"
  tmpFile=$(mktemp -p "${TMP_WORKING_DIR}")
  echo "$_command" > "$tmpFile"
  #$_command &>>"$tmpFile" & 
  $_command >>"$tmpFile" 2>&1 &
  pid=$!
  #echo "PID: $pid running command \"$_command\""
  eval "$_pids+=($pid)"
  eval "$_tmpFiles[$pid]=$tmpFile"
}

get_caid_list () {
  if [[ "${CURL_VERSION}" == "OLD" ]]; then
    ${CURL_COMMAND}  --header "Accept: application/json" -H "Content-Type: application/json" --cert-type PEM --cert "${P12_CERT}" --key "${P12_KEY}" --cacert "${P12_CA}"  "$CAGW_URL/v1/certificate-authorities?%24fields=caList.certificate.certificateData" 2>"${STDERR}" 1>"${STDOUT}"; RESULT=$?
  else
    ${CURL_COMMAND}  --header "Accept: application/json" -H "Content-Type: application/json" --cert-type P12 --cert "$P12":"$P12_PWD" "$CAGW_URL/v1/certificate-authorities?%24fields=caList.certificate.certificateData" 2>"${STDERR}" 1>"${STDOUT}"; RESULT=$?
  fi
  if [[ "${RESULT}" -ne 0 ]]; then
   printf '%s\n' "ERROR ${RESULT}: $(cat "${STDOUT}") $(cat "${STDERR}")"
   exit_and_cleanup "${RESULT}"
  fi
  CA_LIST=$(cat "${STDOUT}")
  CA_ID_LIST=()
  while read -r line; do CA_ID_LIST+=("$line"); done < <(echo "$CA_LIST" | jq -r '.caList[].id')
  CA_NAME_LIST=( "${CA_ID_LIST[@]}" )
  CA_COUNT="${#CA_ID_LIST[@]}"
  for (( i = 0 ; i < CA_COUNT ; i++ )); do
    # Determine if CA is Root or Issuing CA
    CERT=$(printf '%s\n%s\n%s' "-----BEGIN CERTIFICATE-----" "$(printf '%s' "${CA_LIST}" | jq -r --argjson i ${i} '.caList[$i]."certificate"."certificateData"')" "-----END CERTIFICATE-----")
    SUBJECT=$(printf '%s' "$CERT" | openssl x509 -noout -subject -nameopt rfc2253 2>/dev/null)
    SUBJECT=${SUBJECT:8}
    ISSUER=$(printf '%s' "$CERT" | openssl x509 -noout -issuer -nameopt rfc2253 2>/dev/null)
    ISSUER=${ISSUER:7}
    [[ "${SUBJECT}" == "${ISSUER}" ]] && export CATYPE="Root-CA"
    [[ "${SUBJECT}" != "${ISSUER}" ]] && export CATYPE="Issuing-CA"
    CA_NAME_LIST[i]=$(printf '%s' "${CATYPE}: ${CA_ID_LIST[${i}]} (${SUBJECT})")
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
    read -rp "Enter CA ID [$CAID]: " CA_SELECTION
    [[ ${CA_SELECTION} -ge 1 && ${CA_SELECTION} -le ${#CA_ID_LIST[@]} ]] && \
      CA_SELECTION=$(( CA_SELECTION -1 )) && CAID=${CA_ID_LIST[${CA_SELECTION}]} && CA_SELECTION_VALID="TRUE"
    [[ "${CA_SELECTION}" == "" && "${CAID}" != "" ]] && \
      CA_SELECTION_VALID="TRUE"
  done
  export CAID
}

get_profiles_list() {
  if [[ "${CURL_VERSION}" == "OLD" ]]; then
    ${CURL_COMMAND}  --header "Accept: application/json" -H "Content-Type: application/json" --cert-type PEM --cert "${P12_CERT}" --key "${P12_KEY}" --cacert "${P12_CA}"  "$CAGW_URL/v1/certificate-authorities/${CAID}/profiles" 2>"${STDERR}" 1>"${STDOUT}"; RESULT=$?
  else
    ${CURL_COMMAND}  --header "Accept: application/json" -H "Content-Type: application/json" --cert-type P12 --cert "$P12":"$P12_PWD" "$CAGW_URL/v1/certificate-authorities/${CAID}/profiles" 2>"${STDERR}" 1>"${STDOUT}"; RESULT=$?
  fi
  if [[ "${RESULT}" -ne 0 ]]; then
    printf '%s\n' "ERROR ${RESULT}: $(cat "${STDOUT}") $(cat "${STDERR}")"
    exit_and_cleanup "${RESULT}"
  fi
  PROFILES_LIST=$(cat "${STDOUT}")
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

progress_bar() {
    COMPLETED="${1}"
    TOTAL="${2}"
    PROG=$(( (( COMPLETED * 10000 ) / TOTAL ) * 10000 ))
    DONE=$(( ( PROG * 4 ) / 10000000 ))
    LEFT=$(( 40 - DONE ))
    FULL=$( printf "%${DONE}s" )
    EMPTY=$( printf "%${LEFT}s" )

    printf '\033[K\r%s%.2f%s' "[${FULL// /#}${EMPTY// /-}]"  "${PROG}e-6" "%"
}

extract_cert_details () {
  JSON_FILENAME="${1}.json"
  CSV_FILENAME="${1}.csv"
  EVENTCOUNT_IN_FILE=$(jq -r '. | length' "${JSON_FILENAME}" --unbuffered)
  # Process all events in a single file.
  for (( i=0 ; i < EVENTCOUNT_IN_FILE ; i++ )); do
    CERT=$(printf '%s\n%s\n%s' "-----BEGIN CERTIFICATE-----" "$(jq -r --argjson i ${i} '.[$i]."certificate"' "${JSON_FILENAME}" --unbuffered)" "-----END CERTIFICATE-----")
    SUBJECT=$(printf '%s' "$CERT" | openssl x509 -noout -subject -nameopt rfc2253 2>/dev/null)
    SUBJECT=${SUBJECT:8}
    EXPIRY=$(printf '%s' "$CERT" | openssl x509 -noout -enddate 2>/dev/null)
    EXPIRY=$( date -d "${EXPIRY:9}" +"%Y-%m-%dT%H:%M:%SZ")
    NOW=$(date +%s)
    END=$(date -d "${EXPIRY}" +%s)
    STATUS="Active"
    [[ ${NOW} -ge ${END} ]] && export STATUS="Expired" && (( EXPIRED_COUNT++ ))
    JSON=$(jq -r --argjson i ${i} --arg subject "${SUBJECT}" --arg expiry "${EXPIRY}" --arg status "${STATUS}" '.[$i] += { "Subject": $subject, "Expiry Date": $expiry, "Status": $status }' "${JSON_FILENAME}" --unbuffered)
    echo "${JSON}" > "${JSON_FILENAME}"
  done
  jq -r '.[] | [."action", ."eventDate", ."Status", ."Subject", ."Expiry Date", ."serialNumber", ."certificate"] | @csv' "${JSON_FILENAME}" --unbuffered >> "${CSV_FILENAME}"
  JQ_RESULT="${?}"
  return "${JQ_RESULT}"
}

sanitize_cert_events () {
  printf '\n%s\n' "[$(date -Iseconds)] Processing certificiate events..."
  FILENAME="${1}"
  FILECOUNT=1
  TOTAL_FILECOUNT="${2}"
  JSON_FILENAME="${FILENAME}.${FILECOUNT}.json"

  printf '\n%s\n' "[$(date -Iseconds)] Searching for revoked certificate events..."
  REVOKED_SN_LIST="${TMP_WORKING_DIR}/revoked_sn_list_$(date +%s)"
  echo "/Expired" > "${REVOKED_SN_LIST}"
  while [[ -f "${JSON_FILENAME}" ]]; do
    jq -r --arg status "revoked" '.[] | select(.action == $status) | ."serialNumber"' "${JSON_FILENAME}" >> "${REVOKED_SN_LIST}"
    progress_bar "${FILECOUNT}" "${TOTAL_FILECOUNT}"
    FILECOUNT=$(( FILECOUNT + 1 ))
    JSON_FILENAME="${FILENAME}.${FILECOUNT}.json"
  done

  #Calculate total number of cert events:
  FILECOUNT=$(( FILECOUNT - 1 ))
  TOTAL_FILECOUNT="${FILECOUNT}"
  LAST_FILE="${FILENAME}.${FILECOUNT}.json"
  FILECOUNT=$(( FILECOUNT - 1 ))
  EVENT_COUNT_IN_LAST_FILE=$(jq -r '. | length' "${LAST_FILE}")
  TOTAL_EVENT_COUNT=$(( (FILECOUNT * PAGE_SIZE) + EVENT_COUNT_IN_LAST_FILE ))
  #Done calculation of total events (needed to print out the final stats at the end)

  # Extract Subject and Expiry Date for each certificate
  printf '\n\n%s\n' "[$(date -Iseconds)] Extracting certificate details..."
  # Extract data from files in batches
  export pids=()
  export tmpFiles=()
  concurrent=0
  FILECOUNT=1
  JSON_FILENAME="${FILENAME}.${FILECOUNT}.json"
  MAX_THREADS="${MAX_THREADS_DEFAULT}"
  [[ "${TOTAL_FILECOUNT}" -lt "${MAX_THREADS_DEFAULT}" ]] && MAX_THREADS="${TOTAL_FILECOUNT}"
  while [[ -f "${JSON_FILENAME}" ]]; do
    parallel_exec "extract_cert_details ${FILENAME}.${FILECOUNT}" pids tmpFiles
    concurrent=$(( concurrent + 1 ))
    if [[ "$concurrent" -eq $MAX_THREADS ]]; then
      wait_pids pids tmpFiles
      progress_bar "${FILECOUNT}" "${TOTAL_FILECOUNT}"
      RETURN_STATUS="${?}"
      if [[ "${RETURN_STATUS}" -eq 1 ]]; then
        echo "Error occurred attempting to sanitize SNs." \
        exit_and_cleanup "${RETURN_STATUS}"
      fi
      pids=()
      tmpFiles=()
      concurrent=0
      [[ "$(( TOTAL_FILECOUNT - FILECOUNT ))" -lt "${MAX_THREADS_DEFAULT}" ]] && MAX_THREADS="$(( TOTAL_FILECOUNT - FILECOUNT ))"
    fi
    FILECOUNT=$(( FILECOUNT + 1 ))
    JSON_FILENAME="${FILENAME}.${FILECOUNT}.json"
  done
  progress_bar "$(( FILECOUNT - 1 ))" "${TOTAL_FILECOUNT}"
  printf '\n'

  # Combine all of the CSV files into a single CSV File.
  printf '\n%s\n' "[$(date -Iseconds)] Combining all events into a single CSV File..."
  printf '%s\n' '"Action","Issued Date","Status","Subject","Expiry Date","Serial Number","Certificate"' > "${CSV}.tmp"
  FILECOUNT=1
  CSV_FILENAME="${FILENAME}.${FILECOUNT}.csv"
  while true; do
    [[ ! -f "${CSV_FILENAME}" ]] && break
    cat "${CSV_FILENAME}" >> "${CSV}.tmp"
    progress_bar "${FILECOUNT}" "${TOTAL_FILECOUNT}"
    FILECOUNT=$(( FILECOUNT + 1 ))
    CSV_FILENAME="${FILENAME}.${FILECOUNT}.csv"
  done
  printf '\n\n'

  printf '\n%s\n' "[$(date -Iseconds)] Removing all expired and revoked certificates..."
  # Convert list of Revoked SNs into a "sed script" to get around the sed limitations
  # regarding a very large list of arguments.
  # Format of file needs to be: /111/d;222d;...999d
  SED_SCRIPT="${TMP_WORKING_DIR}/SED_SCRIPT_$(date +%s)"
  awk '{printf "%s/d;/", $0}' "${REVOKED_SN_LIST}" > "${SED_SCRIPT}"
  truncate -s-1 "${SED_SCRIPT}"
  # Remove Expired and Revoked Certificates
  sed -E -f "${SED_SCRIPT}" "${CSV}.tmp" > "${CSV}"

  EVENTS_REMAINING=$(wc -l < "${CSV}" | tr -d ' ')
  # Decrement by 1 to account for CSV Header
  EVENTS_REMAINING=$(( EVENTS_REMAINING - 1 ))

  #Print out Summary
  printf '%s\n' "[$(date -Iseconds)] Report Generated"
  printf '%s\n' "Fetched a total of ${TOTAL_EVENT_COUNT} certificate events"
  printf '%s\n' "Removed $(( TOTAL_EVENT_COUNT - EVENTS_REMAINING )) revoked and expired certificates entries"
  printf '%s\n' "CSV Contains ${EVENTS_REMAINING} active certificate"
  printf '%s\n' "CSV File: $(readlink -f "${CSV}")"
}

get_action_type () {
	printf '%s\n' "Select action type from below:"
  printf '%s\n' "  1. Revoke"
  printf '%s\n' "  2. Renew"
  printf '%s\n' "  3. Reissue"
  ACTION_TYPE_ID=0
  while [[ ${ACTION_TYPE_ID} -lt 1 || ${ACTION_TYPE_ID} -gt 3  ]]; do
	  read -rp "Action Type: " ACTION_TYPE_ID
  done

  [[ ${ACTION_TYPE_ID} -eq 1 ]] && export ACTION_TYPE="RevokeAction" && return
  [[ ${ACTION_TYPE_ID} -eq 2 ]] && export ACTION_TYPE="RenewAction" && return
  [[ ${ACTION_TYPE_ID} -eq 3 ]] && export ACTION_TYPE="ReissueAction" && return
}
get_action_reason () {
	printf '%s\n' "Select action reason from below"
  printf '%s\n' "  1. unspecified"
	printf '%s\n' "  2. keyCompromise"
	printf '%s\n' "  3. caCompromise"
	printf '%s\n' "  4. affiliationChanged"
	printf '%s\n' "  5. superseded"
  printf '%s\n' "  6. cessationOfOperation"
	printf '%s\n' "  7. certificateHold"
	printf '%s\n' "  8. privilegeWithdrawn"
  ACTION_REASON_ID=0
  while [[ ${ACTION_REASON_ID} -lt 1 || ${ACTION_REASON_ID} -gt 8  ]]; do
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
  SAN_NEEDED=""
  while [[ "${SAN_NEEDED}" != "Y" && "${SAN_NEEDED}" != "N" ]]; do
    read -rp "Do you want to add a Subject Alternate Name (Y/N): " SAN_NEEDED
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
  # Ask if CSR exists, or need to create a new one...
  while [[ "${EXISTINGCSR}" != "Y" && "${EXISTINGCSR}" != "N" ]]; do
    read -rp "Use existing CSR (Y/N): " EXISTINGCSR
    EXISTINGCSR=$(printf '%s' "$EXISTINGCSR" | tr '[:lower:]' '[:upper:]')
  done

  if [[ "${EXISTINGCSR}" == "N" ]]; then
    generate_csr
    CSR_INPUT_PATH="${CSR_PATH}"
  elif [[ "${EXISTINGCSR}" == "Y" ]]; then
    # Prompt for CSR File Path
    while [[ ! -f "${CSR_INPUT_PATH}" ]]; do
      read -e -rp "Enter path to an existing CSR file ['$CSR_PATH']: " CSR_INPUT_PATH
      while [[ -z "$CSR_INPUT_PATH" ]] && [[ -z "${CSR_PATH}" ]]; do
        read -e -rp "Enter path to an existing CSR file ['$CSR_PATH']: " CSR_INPUT_PATH
      done
      [[ -z "$CSR_INPUT_PATH" ]] &&  printf -v "CSR_INPUT_PATH" "%s" "$CSR_PATH"
    done
  fi

  # Ask whether or not to use Subject DN from CSR, or to provide a different Subject DN
  while [[ "${REUSEDN}" != "Y" && "${REUSEDN}" != "N" ]]; do
    read -rp "Use Subject DN from CSR (Y/N): " REUSEDN
    REUSEDN=$(printf '%s' "$REUSEDN" | tr '[:lower:]' '[:upper:]')
  done
  if [[ "${REUSEDN}" == "N" ]]; then
    # Prompt for new Subject DN
    CERT_OPT_PARAMS_SUBJECT_DN=""
    while [[ "${CERT_OPT_PARAMS_SUBJECT_DN}" == "" ]]; do
      echo -n "Enter full subject DN (i.e. cn=example.com): "
      read -r CERT_OPT_PARAMS_SUBJECT_DN
    done
  elif [[ "${REUSEDN}" == "Y" ]]; then
    #extract Subject DN from CSR
    SUBJECT=$(openssl req -in "${CSR_INPUT_PATH}" -noout -subject -nameopt rfc2253)
    SUBJECT="${SUBJECT:8}"
    printf '%s\n' "Subject: ${SUBJECT}"
  fi


  # Ask whether or not to use SANs from CSR, or to provide a different different set of SANs
  # This only works for OpenSSL 3.0 or later, so skip this when OPENSSL_VERSION is "OLD"
  while [[ "${REUSE_SAN}" != "Y" && "${REUSE_SAN}" != "N" && "${OPENSSL_VERSION}" != "OLD" ]]; do
    read -rp "Use Subject Alternative Names (SAN) from CSR (Y/N): " REUSE_SAN
    REUSE_SAN=$(printf '%s' "$REUSE_SAN" | tr '[:lower:]' '[:upper:]')
  done
  if [[ -z "${REUSE_SAN}" || "${REUSE_SAN}" == "N" ]]; then
    # Prompt for Certificate SAN Attributes
    SAN_ARRAY="["
    get_subject_altnames
  elif [[ "${REUSE_SAN}" == "Y" ]]; then
    # Create self-signed certificate temporarily. Needed to extract Extensions from CSR properly using OpenSSL
    TEMP_KEY="${TMP_WORKING_DIR}/tmpkey_$(date +%s)"
    TEMP_CERT="${TMP_WORKING_DIR}/tmpcrt_$(date +%s)"
    openssl genrsa -out "${TEMP_KEY}" 3072  2>"${STDERR}" 1>"${STDOUT}"; RESULT=$?
    if [[ "${RESULT}" -ne 0 ]]; then
      echo "Error generating temporary RSA Key"
      printf '%s\n%s\n' "${STDOUT}" "${STDERR}"
      exit_and_cleanup "${RESULT}"
    fi
    openssl x509 -in "${CSR_INPUT_PATH}" -out "${TEMP_CERT}"  -req -signkey "${TEMP_KEY}" -days 1 -copy_extensions copy 2>"${STDERR}" 1>"${STDOUT}"; RESULT=$?
    if [[ "${RESULT}" -ne 0 ]]; then
      echo "Error generating temporary Self-Signed Cert"
      printf '%s\n%s\n' "${STDOUT}" "${STDERR}"
      exit_and_cleanup "${RESULT}"
    fi
    # Extract SANs from self-signed cert
    IFS_ORIG="${IFS}"
    IFS=', ' read -r -a SANS <<< "$(openssl x509 -noout -ext subjectAltName -in "${TEMP_CERT}" | sed 1d)"
    IFS="${IFS_ORIG}"
    EMAIL=()
    DNS=()
    URI=()
    IP=()
    RID=()
    for (( i=0; i < "${#SANS[@]}"; i++ )); do
      [[ "${SANS[i]}" == "email:"* ]] && EMAIL=( "${EMAIL[@]}" "${SANS[i]:6}" )
      [[ "${SANS[i]}" == "DNS:"* ]] && DNS=( "${DNS[@]}" "${SANS[i]:4}" )
      [[ "${SANS[i]}" == "URI:"* ]] && URI=( "${URI[@]}" "${SANS[i]:4}" )
      [[ "${SANS[i]}" == "IP Address:"* ]] && IP=( "${IP[@]}" "${SANS[i]:11}" )
      [[ "${SANS[i]}" == "Registered ID:"* ]] && RID=( "${RID[@]}" "${SANS[i]:14}" )
    done
    #Build SAN_ARRAY
    SAN_ARRAY="["
    for (( i=0; i < "${#EMAIL[@]}"; i++ )); do
      printf -v "SAN_ARRAY" "%s" "${SAN_ARRAY}{\"type\": \"rfc822Name\",\"value\": \"${EMAIL[i]}\"},"
    done
    for (( i=0; i < "${#DNS[@]}"; i++ )); do
      printf -v "SAN_ARRAY" "%s" "${SAN_ARRAY}{\"type\": \"dNSName\",\"value\": \"${DNS[i]}\"},"
    done
    for (( i=0; i < "${#URI[@]}"; i++ )); do
      printf -v "SAN_ARRAY" "%s" "${SAN_ARRAY}{\"type\": \"uniformResourceIdentifier\",\"value\": \"${URI[i]}\"},"
    done
    for (( i=0; i < "${#IP[@]}"; i++ )); do
      printf -v "SAN_ARRAY" "%s" "${SAN_ARRAY}{\"type\": \"iPAddress\",\"value\": \"${IP[i]}\"},"
    done
    for (( i=0; i < "${#RID[@]}"; i++ )); do
      printf -v "SAN_ARRAY" "%s" "${SAN_ARRAY}{\"type\": \"registeredID\",\"value\": \"${RID[i]}\"},"
    done
    [[ "$SAN_ARRAY" == "[" ]] && printf -v "SAN_ARRAY" "%s" "[]"
    [[ "$SAN_ARRAY" != "[" ]] && printf -v "SAN_ARRAY" "%s" "${SAN_ARRAY%?}]"
    printf '%s\n' "SANs (JSON-formatted for CAGW): ${SAN_ARRAY}"
  fi

  CSR=$(sed '1,1d' < "${CSR_INPUT_PATH}" | sed '$d' |  tr -d "\n\r")

  # Execute Curl Command
  if [[ "${CURL_VERSION}" == "OLD" ]]; then
    ${CURL_COMMAND} -s --header "Accept: application/json" -H "Content-Type: application/json" --data "{\"profileId\":\"$PROFILE_ID\",\"requiredFormat\":{\"format\":\"PEM\"},\"csr\":\"${CSR}\",\"optionalCertificateRequestDetails\":{\"subjectDn\":\"$CERT_OPT_PARAMS_SUBJECT_DN\"},\"subjectAltNames\":$SAN_ARRAY}" --cert-type PEM --cert "${P12_CERT}" --key "${P12_KEY}" --cacert "${P12_CA}"  "${CAGW_URL}/v1/certificate-authorities/${CAID}/enrollments" 2>"${STDERR}" 1>"${STDOUT}"; RESULT=$?
  else
    ${CURL_COMMAND} -s --header "Accept: application/json" -H "Content-Type: application/json" --data "{\"profileId\":\"$PROFILE_ID\",\"requiredFormat\":{\"format\":\"PEM\"},\"csr\":\"${CSR}\",\"optionalCertificateRequestDetails\":{\"subjectDn\":\"$CERT_OPT_PARAMS_SUBJECT_DN\"},\"subjectAltNames\":$SAN_ARRAY}" --cert-type P12 --cert "$P12":"$P12_PWD" "${CAGW_URL}/v1/certificate-authorities/${CAID}/enrollments" 2>"${STDERR}" 1>"${STDOUT}"; RESULT=$?
  fi
  if [[ "${RESULT}" -ne 0 ]]; then
    printf '%s\n' "ERROR ${RESULT}: $(cat "${STDOUT}") $(cat "${STDERR}")"
    exit_and_cleanup "${RESULT}"
  fi
  RESPONSE=$(cat "${STDOUT}")
  RESPONSE_TYPE=$(printf '%s' "${RESPONSE}" | jq -r '.type')
  if [[ "${RESPONSE_TYPE}" == "ErrorResponse" ]]; then
    printf '%s\n' "ERROR ${RESULT}: $(cat "${STDOUT}") $(cat "${STDERR}")"
    exit_and_cleanup 1
  fi
  printf '%s\n%s\n' "Response:" "${RESPONSE}"
  # Prompt for Certificate File Path
  CERT_PATH=""
  while [[ "${CERT_PATH}" == "" ]]; do
    read -e -rp "Where would you like to store the certificate (e.g. ./certificate.pem): " CERT_PATH
  done
  echo "${RESPONSE}" | jq -r '.enrollment.body' >  "${CERT_PATH}"
  printf '\n%s\n' "Certificate is written successfully to the file $(readlink -f "${CERT_PATH}")".
}

enroll_p12() {
  # Prompt for Certificate Subject DN
  CERT_OPT_PARAMS_SUBJECT_DN=""
  while [[ "${CERT_OPT_PARAMS_SUBJECT_DN}" == "" ]]; do
    echo -n "Enter full subject DN (i.e. cn=example.com): "
    read -r CERT_OPT_PARAMS_SUBJECT_DN
  done

  # Prompt for Certificate SAN Attributes
  SAN_ARRAY="["
  get_subject_altnames

  # Prompt for P12 Password
  PASSWORD=""
  while [[ -z "${PASSWORD// }" ]]; do
    printf '%s' "Enter a password to secure the P12 file: "
    read -sr PASSWORD
    printf '\n'
  done

  # Execute Curl Command
  if [[ "${CURL_VERSION}" == "OLD" ]]; then
    ${CURL_COMMAND} -s --header "Accept: application/json" -H "Content-Type: application/json" --data "{\"profileId\":\"$PROFILE_ID\",\"requiredFormat\":{\"format\":\"PKCS12\",\"protection\":{\"type\":\"PasswordProtection\",\"password\":\"${PASSWORD}\"}},\"optionalCertificateRequestDetails\":{\"subjectDn\":\"$CERT_OPT_PARAMS_SUBJECT_DN\"},\"subjectAltNames\":$SAN_ARRAY}" --cert-type PEM --cert "${P12_CERT}" --key "${P12_KEY}" --cacert "${P12_CA}"  "${CAGW_URL}/v1/certificate-authorities/${CAID}/enrollments" 2>"${STDERR}" 1>"${STDOUT}"; RESULT=$?
  else
    ${CURL_COMMAND} -s --header "Accept: application/json" -H "Content-Type: application/json" --data "{\"profileId\":\"$PROFILE_ID\",\"requiredFormat\":{\"format\":\"PKCS12\",\"protection\":{\"type\":\"PasswordProtection\",\"password\":\"${PASSWORD}\"}},\"optionalCertificateRequestDetails\":{\"subjectDn\":\"$CERT_OPT_PARAMS_SUBJECT_DN\"},\"subjectAltNames\":$SAN_ARRAY}" --cert-type P12 --cert "$P12":"$P12_PWD" "${CAGW_URL}/v1/certificate-authorities/${CAID}/enrollments" 2>"${STDERR}" 1>"${STDOUT}"; RESULT=$?
  fi
  if [[ "${RESULT}" -ne 0 ]]; then
     printf '%s\n' "ERROR ${RESULT}: $(cat "${STDOUT}") $(cat "${STDERR}")"
     exit_and_cleanup "${RESULT}"
  fi
  RESPONSE=$(cat "${STDOUT}")
  RESPONSE_TYPE=$(printf '%s' "${RESPONSE}" | jq -r '.type')
  [[ "${RESPONSE_TYPE}" == "ErrorResponse" ]] && printf '%s\n' "ERROR ${RESULT}: $(cat "${STDOUT}") $(cat "${STDERR}")" && main
  printf '%s\n%s\n' "Response:" "${RESPONSE}"
  # Prompt for Certificate File Path
  CERT_PATH=""
  while [[ "${CERT_PATH}" == "" ]]; do
    read -e -rp "Where would you like to store the certificate (e.g. ./certificate.p12): " CERT_PATH
  done
  echo "${RESPONSE}" | jq -r '.enrollment.body' | base64 -d > "${CERT_PATH}"
  printf '\n%s\n' "Certificate is written successfully to the file ${CERT_PATH}".
}

generate_csr() {
  printf '%s\n' "${DIVIDER}"
  [[ "${CAGW_TYPE}" -eq "${PKIAAS}" ]] && \
    echo "Notice: PKIaaS will ignore ALL attributes inside the CSR. Only the public key is used."

  # Ask where to save Private Key and CSR files
  while [[ -z "${KEY_PATH}" ]]; do
    read -e -rp "Where would you like to store the key (e.g. /tmp/example.key): " KEY_PATH
  done
  while [[ -z "${CSR_PATH}" ]]; do
    read -e -rp "Where would you like to store the CSR (e.g. /tmp/example.csr): " CSR_PATH
  done
  
  # Build a CSR config File.
  CSR_CONFIG="${TMP_WORKING_DIR}/csr_config_$(date +%s)"
  SUBJECTS="${TMP_WORKING_DIR}/subjects_$(date +%s)"
  {
    printf '%s\n' "[req]";
    printf '%s\n' 'distinguished_name = req_dn';
    printf '%s\n' 'req_extensions = v3_req'
    printf '%s\n\n' 'prompt = no';
    printf '%s\n' "[req_dn]";
  }  > "${CSR_CONFIG}"
  
  BUILDING_SUBJECT="true"
  FULL_DN=""
  while [[ "${BUILDING_SUBJECT}" == "true" ]]; do
    echo "Select a Distinguished Name attribute to add to the Subject DN:"
    for (( i=0; i < ${#DN_OPTIONS[@]}; i++ )); do
      printf '%s\n' "  $(( i+1 )). ${DN_OPTIONS[${i}]}"
    done
    printf '%s\n' "  $(( ${#DN_OPTIONS[@]} + 1 )). Done"
    [[ "${FULL_DN}" != "" ]] && printf '%s\n' "Subject: ${FULL_DN}"
    DN_ATT=""
    while [[ "${DN_ATT}" -lt 1 || "${DN_ATT}" -gt $(( ${#DN_OPTIONS[@]} + 1 )) ]]; do
      read -rp "Next DN Attribute: " DN_ATT
    done
    [[ "${DN_ATT}" -eq $(( ${#DN_OPTIONS[@]} + 1 )) ]] && BUILDING_SUBJECT="false" && continue
    DN_VAL=""
    while [[ -z "${DN_VAL// }" ]]; do
      read -rp "Value for ${DN_OPTIONS[$(( DN_ATT-1 ))]}: " DN_VAL
    done

    ## Add component into CSR_CONFIG file.
    printf '%s%s\n' "${DN_OPTIONS[$(( DN_ATT-1 ))]}=" "${DN_VAL}" >> "${SUBJECTS}"

    [[ "${FULL_DN}" != "" ]] && FULL_DN=$(printf '%s%s' "${FULL_DN},${DN_OPTIONS[$(( DN_ATT-1 ))]}=" "${DN_VAL}")
    [[ "${FULL_DN}" == "" ]] && FULL_DN=$(printf '%s%s' "${DN_OPTIONS[$(( DN_ATT-1 ))]}=" "${DN_VAL}")
  done
  tac "${SUBJECTS}" >> "${CSR_CONFIG}"

  printf '%s\n' "Select the Key Alorithm:"
  printf '%s\n' "  1. RSA"
  printf '%s\n' "  2. Elliptic Curve"
  KEY_ALG=0
  while [[ "${KEY_ALG}" -lt 1 || "${KEY_ALG}" -gt 2 ]]; do
      read -rp "Key Algorithm: " KEY_ALG
  done

  case "${KEY_ALG}" in
    1)
      # RSA
        SUPPORTED_SIZES=( "1024" "2048" "3072" "4096" )
        printf '%s\n' "Select the Key Size:"
        printf '%s\n' "  1. 1024"
        printf '%s\n' "  2. 2048"
        printf '%s\n' "  3. 3072"
        printf '%s\n' "  4. 4096"
        KEY_SIZE=0
        while [[ "${KEY_SIZE}" -lt 1 || "${KEY_SIZE}" -gt 4 ]]; do
            read -rp "Key Size: " KEY_SIZE
        done
        openssl genrsa -out "${KEY_PATH}" "${SUPPORTED_SIZES[$(( KEY_SIZE - 1 ))]}" 
      ;;
    2)
      # EC
        SUPPORTED_CURVES=( "secp256k1" "secp384r1" "secp521r1" )
        printf '%s\n' "Select the EC Named Curve:"
        printf '%s\n' "  1. ECDSA P-256 (secp256k1)"
        printf '%s\n' "  2. ECDSA P-384 (secp384r1)"
        printf '%s\n' "  3. ECDSA P-521 (secp521r1)"
        KEY_SIZE=0
        while [[ "${KEY_SIZE}" -lt 1 || "${KEY_SIZE}" -gt 3 ]]; do
            read -rp "EC Named Curve: " KEY_SIZE
        done
        openssl ecparam -name "${SUPPORTED_CURVES[$(( KEY_SIZE - 1 ))]}" -genkey -noout -out "${KEY_PATH}"
      ;;
    *)
      ;;
  esac

  # Add the [v3_req] section to the CSR_CONFIG File. It's okay if it's empty
  printf '\n%s' "[v3_req]">> "${CSR_CONFIG}"


  # Add key usage to CSR if desired
  ADD_KEYUSAGE=""
  SELECTED_KEYUSAGES=()
  COMMA=""
  while [[ "${ADD_KEYUSAGE}" != "Y" && "${ADD_KEYUSAGE}" != "N" ]]; do
    read -rp "Add key usage to CSR (Y/N): " ADD_KEYUSAGE
    ADD_KEYUSAGE=$(echo "$ADD_KEYUSAGE" | tr '[:lower:]' '[:upper:]')
  done
  KEY_USAGES_AVAILABLE=( "${KEY_USAGES[@]}" )
  if [[ "${ADD_KEYUSAGE}" == "Y" ]]; then
      printf '\n%s' 'keyUsage =' >> "${CSR_CONFIG}"
    while [[ "${ADD_KEYUSAGE}" == "Y" ]]; do
      KEY_USAGE=0
      while [[ "${KEY_USAGE}" -lt 1 || "${KEY_USAGE}" -gt $(( ${#KEY_USAGES_AVAILABLE[@]} + 1 )) ]]; do
        printf '%s\n' "Add key usage to CSR:"
        for (( i=0; i<${#KEY_USAGES_AVAILABLE[@]}; i++ )); do
          printf '%s\n' "  $(( i + 1)). ${KEY_USAGES_AVAILABLE[${i}]}"
        done
        printf '%s\n' "  $(( ${#KEY_USAGES_AVAILABLE[@]} + 1 )). Done"
        read -rp "Key usage: " KEY_USAGE
      done
      [[ "${KEY_USAGE}" -eq $(( ${#KEY_USAGES_AVAILABLE[@]} + 1 )) ]] && export ADD_KEYUSAGE="N" && continue
      # Add Key Usage to CSR Conf File
      [[ $(( ${#KEY_USAGES[@]} - ${#KEY_USAGES_AVAILABLE[@]} )) -ne 0 ]] && export COMMA=","
      SELECTED_KEYUSAGES=( "${SELECTED_KEYUSAGES[@]}" "${KEY_USAGES_AVAILABLE[$(( KEY_USAGE - 1 ))]}" )
      printf '%s' "${COMMA} ${KEY_USAGES_AVAILABLE[$(( KEY_USAGE - 1 ))]}" >> "${CSR_CONFIG}"
      printf '%s %s %s %s %s\n' "CSR Key Usages: " "${SELECTED_KEYUSAGES[@]}"

      # Remove Key Usage from list of available Key Usages
      NEW_LIST=()
      for (( i=0; i<${#KEY_USAGES_AVAILABLE[@]}; i++ )); do
        [[ ${i} -ne $(( KEY_USAGE - 1 )) ]] && export NEW_LIST=( "${NEW_LIST[@]}" "${KEY_USAGES_AVAILABLE[${i}]}" )
      done
      KEY_USAGES_AVAILABLE=( "${NEW_LIST[@]}" )

    done
  fi

  # Add Extended Key Usage to CSR if desired
  ADD_EKU=""
  SELECTED_EKUS=()
  COMMA=""
  while [[ "${ADD_EKU}" != "Y" && "${ADD_EKU}" != "N" ]]; do
    read -rp "Add extended key usage (EKU) to CSR (Y/N): " ADD_EKU
    ADD_EKU=$(echo "$ADD_EKU" | tr '[:lower:]' '[:upper:]')
  done
  EKUS_AVAILABLE=( "${EKUS[@]}" )
  if [[ "${ADD_EKU}" == "Y" ]]; then
      printf '\n%s' 'extendedKeyUsage =' >> "${CSR_CONFIG}"
    while [[ "${ADD_EKU}" == "Y" ]]; do
      EKU=0
      while [[ "${EKU}" -lt 1 || "${EKU}" -gt $(( ${#EKUS_AVAILABLE[@]} + 1 )) ]]; do
        printf '%s\n' "Add extended key usage (EKU) to CSR:"
        for (( i=0; i<${#EKUS_AVAILABLE[@]}; i++ )); do
          printf '%s\n' "  $(( i + 1)). ${EKUS_AVAILABLE[${i}]}"
        done
        printf '%s\n' "  $(( ${#EKUS_AVAILABLE[@]} + 1 )). Done"
        read -rp "Extended Key Usage: " EKU
      done
      [[ "${EKU}" -eq $(( ${#EKUS_AVAILABLE[@]} + 1 )) ]] && export ADD_EKU="N" && continue
      # Add Key Usage to CSR Conf File
      [[ $(( ${#EKUS[@]} - ${#EKUS_AVAILABLE[@]} )) -ne 0 ]] && export COMMA=","
      SELECTED_EKUS=( "${SELECTED_EKUS[@]}" "${EKUS_AVAILABLE[$(( EKU - 1 ))]}" )
      printf '%s' "${COMMA} ${EKUS_AVAILABLE[$(( EKU - 1 ))]}" >> "${CSR_CONFIG}"
      printf '%s %s %s %s %s\n' "CSR Extended Key Usages: " "${SELECTED_EKUS[@]}"

      # Remove Key Usage from list of available Key Usages
      NEW_LIST=()
      for (( i=0; i<${#EKUS_AVAILABLE[@]}; i++ )); do
        [[ ${i} -ne $(( EKU - 1 )) ]] && export NEW_LIST=( "${NEW_LIST[@]}" "${EKUS_AVAILABLE[${i}]}" )
      done
      EKUS_AVAILABLE=( "${NEW_LIST[@]}" )
    done
  fi

  # Add SANs to CSR if desired.
  ADD_SAN=""
  SELECTED_SANS=()
  while [[ "${ADD_SAN}" != "Y" && "${ADD_SAN}" != "N" ]]; do
    read -rp "Add Subject Alternative Name (SAN) to CSR (Y/N): " ADD_SAN
    ADD_SAN=$(echo "$ADD_SAN" | tr '[:lower:]' '[:upper:]')
  done

  SANS_AVAILABLE=( "${SANS[@]}" )
  if [[ "${ADD_SAN}" == "Y" ]]; then
      {
      printf '\n%s' 'subjectAltName = @alt_names';
      printf '\n\n%s' "[alt_names]";
      } >> "${CSR_CONFIG}"
    while [[ "${ADD_SAN}" == "Y" ]]; do
      SAN=0
      while [[ "${SAN}" -lt 1 || "${SAN}" -gt $(( ${#SANS_AVAILABLE[@]} + 1 )) ]]; do
        printf '%s\n' "Add Subject Alternative Name (SAN) to CSR:"
        for (( i=0; i<${#SANS_AVAILABLE[@]}; i++ )); do
          printf '%s\n' "  $(( i + 1)). ${SANS_AVAILABLE[${i}]}"
        done
        printf '%s\n' "  $(( ${#SANS_AVAILABLE[@]} + 1 )). Done"
        read -rp "Subject Alernative Name (SAN): " SAN
      done
      [[ "${SAN}" -eq $(( ${#SANS_AVAILABLE[@]} + 1 )) ]] && export ADD_SAN="N" && continue
      # Add Key Usage to CSR Conf File
      ADDING_SINGLE_SAN_TYPE='Y'
      COUNT=1
      while [[ "${ADDING_SINGLE_SAN_TYPE}" == "Y" ]]; do
        read -rp "Provide a value for ${SANS_AVAILABLE[$(( SAN - 1 ))]}: " SAN_VALUE
        printf '\n%s%s' "${SANS_AVAILABLE[$(( SAN - 1 ))]}.${COUNT} = " "${SAN_VALUE}" >> "${CSR_CONFIG}"
        read -rp "Would you like to add another ${SANS_AVAILABLE[$(( SAN - 1 ))]} SAN (Y/N): " ADDING_SINGLE_SAN_TYPE
        ADDING_SINGLE_SAN_TYPE=$(echo "$ADDING_SINGLE_SAN_TYPE" | tr '[:lower:]' '[:upper:]')
        COUNT=$(( COUNT + 1 ))
      done
      printf '%s %s %s %s %s\n' "CSR Subject Alternative Names (SAN): " "${SELECTED_SANS[@]}"

      # Remove Key Usage from list of available Key Usages
      NEW_LIST=()
      for (( i=0; i<${#SANS_AVAILABLE[@]}; i++ )); do
        [[ ${i} -ne $(( SAN - 1 )) ]] && export NEW_LIST=( "${NEW_LIST[@]}" "${SANS_AVAILABLE[${i}]}" )
      done
      SANS_AVAILABLE=( "${NEW_LIST[@]}" )
    done
  fi

  printf '\n\n' >> "${CSR_CONFIG}"
  printf '%s\n' "Generating CSR using the following OpenSSL conf file:"
  cat "${CSR_CONFIG}"

  openssl req -new -key "${KEY_PATH}" -out "${CSR_PATH}" -config "${CSR_CONFIG}" -nodes
  echo "CSR:"
  cat "${CSR_PATH}"
  printf '%s\n' "Private Key: $(readlink -f "${KEY_PATH}")"
  printf '%s\n' "CSR: $(readlink -f "${CSR_PATH}")"
}

list_cas() {
  printf '%s\n' "${DIVIDER}"
  if [[ "${CURL_VERSION}" == "OLD" ]]; then
    ${CURL_COMMAND}  --header "Accept: application/json" -H "Content-Type: application/json" --cert-type PEM --cert "${P12_CERT}" --key "${P12_KEY}" --cacert "${P12_CA}"  "$CAGW_URL/v1/certificate-authorities" 2>"${STDERR}" 1>"${STDOUT}"; RESULT=$?
  else
    ${CURL_COMMAND}  --header "Accept: application/json" -H "Content-Type: application/json" --cert-type P12 --cert "$P12":"$P12_PWD" "$CAGW_URL/v1/certificate-authorities" 2>"${STDERR}" 1>"${STDOUT}"; RESULT=$?
  fi
  if [[ "${RESULT}" -ne 0 ]]; then
    printf '%s\n' "ERROR ${RESULT}: $(cat "${STDOUT}") $(cat "${STDERR}")"
    exit_and_cleanup "${RESULT}"
  fi
  printf '%s\n%s\n' "RESULT:" "$(cat "${STDOUT}")"
}

list_ca_profiles() {
  printf '%s\n' "${DIVIDER}"
  prompt_for_caid
  if [[ "${CURL_VERSION}" == "OLD" ]]; then
    ${CURL_COMMAND}  --header "Accept: application/json" -H "Content-Type: application/json" --cert-type PEM --cert "${P12_CERT}" --key "${P12_KEY}" --cacert "${P12_CA}"  "$CAGW_URL/v1/certificate-authorities/$CAID/profiles" 2>"${STDERR}" 1>"${STDOUT}"; RESULT=$?
  else
    ${CURL_COMMAND}  --header "Accept: application/json" -H "Content-Type: application/json" --cert-type P12 --cert "$P12":"$P12_PWD" "$CAGW_URL/v1/certificate-authorities/$CAID/profiles" 2>"${STDERR}" 1>"${STDOUT}"; RESULT=$?
  fi
  if [[ "${RESULT}" -ne 0 ]]; then
   printf '%s\n' "ERROR ${RESULT}: $(cat "${STDOUT}") $(cat "${STDERR}")"
   exit_and_cleanup "${RESULT}"
  fi
  printf '%s\n%s\n' "RESULT:" "$(cat "${STDOUT}")"
}

enroll_cert() {
  printf '%s\n' "${DIVIDER}"
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
}

revoke_sn() {
  printf '%s\n' "${DIVIDER}"
  prompt_for_caid
  while [[ "${CERTIFICATE_SERIAL}" == "" ]]; do
    echo -n "Enter certificate serial number in hexadecimal format (Example: 0000000091ca4b4b136a86b718ae01a5403ce62b): "
    read -r CERTIFICATE_SERIAL	
  done
  get_action_type
  read -rp "Enter a comment about the action (optional): " COMMENT
  get_action_reason
  if [[ "${CURL_VERSION}" == "OLD" ]]; then
    ${CURL_COMMAND} --header "Accept: application/json" -H "Content-Type: application/json" --data "{\"action\":{\"comment\":\"$COMMENT\",\"type\":\"$ACTION_TYPE\",\"reason\":\"$ACTION_REASON\"}}" --cert-type PEM --cert "${P12_CERT}" --key "${P12_KEY}" --cacert "${P12_CA}"  "$CAGW_URL/v1/certificate-authorities/$CAID/certificates/$CERTIFICATE_SERIAL/actions" 2>"${STDERR}" 1>"${STDOUT}"; RESULT=$?
  else
    ${CURL_COMMAND} --header "Accept: application/json" -H "Content-Type: application/json" --data "{\"action\":{\"comment\":\"$COMMENT\",\"type\":\"$ACTION_TYPE\",\"reason\":\"$ACTION_REASON\"}}" --cert-type P12 --cert "$P12":"$P12_PWD" "$CAGW_URL/v1/certificate-authorities/$CAID/certificates/$CERTIFICATE_SERIAL/actions" 2>"${STDERR}" 1>"${STDOUT}"; RESULT=$?
  fi
  if [[ "${RESULT}" -ne 0 ]]; then
    printf '%s\n' "ERROR ${RESULT}: $(cat "${STDOUT}") $(cat "${STDERR}")"
    exit_and_cleanup "${RESULT}"
  fi
  printf '%s\n%s\n' "RESULT:" "$(cat "${STDOUT}")"
}

bulk_issue() {
  printf '%s\n' "${DIVIDER}"
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
      if [[ "${CURL_VERSION}" == "OLD" ]]; then
        ${CURL_COMMAND} -s --header "Accept: application/json" -H "Content-Type: application/json" --data "{\"profileId\":\"$PROFILE_ID\",\"requiredFormat\":{\"format\":\"PEM\"},\"csr\":\"$(tr -d "\n\r" < "${TARGET_FOLDER}/${commonName}.csr")\",\"optionalCertificateRequestDetails\":{\"subjectDn\":\"CN=$commonName\"}}" --cert-type PEM --cert "${P12_CERT}" --key "${P12_KEY}" --cacert "${P12_CA}"  "$CAGW_URL/v1/certificate-authorities/$CAID/enrollments" 2>"${STDERR}" 1>"${STDOUT}"; RESULT=$?
      else
         ${CURL_COMMAND} -s --header "Accept: application/json" -H "Content-Type: application/json" --data "{\"profileId\":\"$PROFILE_ID\",\"requiredFormat\":{\"format\":\"PEM\"},\"csr\":\"$(tr -d "\n\r" < "${TARGET_FOLDER}/${commonName}.csr")\",\"optionalCertificateRequestDetails\":{\"subjectDn\":\"CN=$commonName\"}}" --cert-type P12 --cert "$P12":"$P12_PWD" "$CAGW_URL/v1/certificate-authorities/$CAID/enrollments" 2>"${STDERR}" 1>"${STDOUT}"; RESULT=$?
      fi
      if [[ "${RESULT}" -ne 0 ]]; then 
        printf '%s\n' "ERROR ${RESULT}: $(cat "${STDOUT}") $(cat "${STDERR}")"
        exit_and_cleanup "${RESULT}"
      fi
      RESPONSE=$(cat "${STDOUT}")
      CERT_PATH=""
      while [[ "${CERT_PATH}" == "" ]]; do
        read -e -rp "Where would you like to store the certificate (e.g. ./certificate.pem): " CERT_PATH
      done
      echo "${RESPONSE}" | jq -r '.enrollment.body' >  "${TARGET_FOLDER}/${commonName}.pem"
      PROCESSED_COUNT=$(( PROCESSED_COUNT + 1 ))
      [[ $(( (PROCESSED_COUNT) % PAGE_SIZE )) -eq 0 ]] && printf '%s\n' "Processed ${PROCESSED_COUNT} certificate requests of ${BULK_COUNT}."
    done
  } < "${ISSUE_CSV}"
  printf '%s\n' "Certificates and Keys written to the folder $(readlink -f "${TARGET_FOLDER}")"
}

bulk_revoke() {
  printf '%s\n' "${DIVIDER}"
  REVOKE_CSV=""
  while [[ ! -f "${REVOKE_CSV}" ]]; do
    read -e -rp  "Enter the path to the CSV file: " REVOKE_CSV
  done
  prompt_for_caid
  HEADERS_INCLUDED=""
  while [[ "${HEADERS_INCLUDED}" != "Y" && "${HEADERS_INCLUDED}" != "N" ]]; do
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
      if [[ "${CURL_VERSION}" == "OLD" ]]; then
        ${CURL_COMMAND} --header "Accept: application/json" -H "Content-Type: application/json" --data "{\"action\":{\"type\":\"RevokeAction\",\"reason\":\"$ACTION_REASON\"}}" --cert-type PEM --cert "${P12_CERT}" --key "${P12_KEY}" --cacert "${P12_CA}"  "$CAGW_URL/v1/certificate-authorities/$CAID/certificates/$snToRevoke/actions" 2>"${STDERR}" 1>"${STDOUT}"; RESULT=$?
      else
         ${CURL_COMMAND} --header "Accept: application/json" -H "Content-Type: application/json" --data "{\"action\":{\"type\":\"RevokeAction\",\"reason\":\"$ACTION_REASON\"}}" --cert-type P12 --cert "$P12":"$P12_PWD" "$CAGW_URL/v1/certificate-authorities/$CAID/certificates/$snToRevoke/actions" 2>"${STDERR}" 1>"${STDOUT}"; RESULT=$?
      fi
      if [[ "${RESULT}" -ne 0 ]]; then
        printf '%s\n' "ERROR ${RESULT}: $(cat "${STDOUT}") $(cat "${STDERR}")"
        exit_and_cleanup "${RESULT}"
      fi
    fi
    snToRevoke=$(printf '%s' "$sn" | tr -d '\r')

  done <"$REVOKE_CSV"

  echo "REVOKE SN : $snToRevoke"
  if [[ "${CURL_VERSION}" == "OLD" ]]; then
  ${CURL_COMMAND} --header "Accept: application/json" -H "Content-Type: application/json" --data "{\"action\":{\"type\":\"RevokeAction\",\"reason\":\"$ACTION_REASON\",\"issueCrl\":\"true\"}}" --cert-type PEM --cert "${P12_CERT}" --key "${P12_KEY}" --cacert "${P12_CA}"  "$CAGW_URL/v1/certificate-authorities/$CAID/certificates/$snToRevoke/actions" 2>"${STDERR}" 1>"${STDOUT}"; RESULT=$?
  else
    ${CURL_COMMAND} --header "Accept: application/json" -H "Content-Type: application/json" --data "{\"action\":{\"type\":\"RevokeAction\",\"reason\":\"$ACTION_REASON\",\"issueCrl\":\"true\"}}" --cert-type P12 --cert "$P12":"$P12_PWD" "$CAGW_URL/v1/certificate-authorities/$CAID/certificates/$snToRevoke/actions" 2>"${STDERR}" 1>"${STDOUT}"; RESULT=$?
  fi
  if [[ "${RESULT}" -ne 0 ]]; then
    printf '%s\n' "ERROR ${RESULT}: $(cat "${STDOUT}") $(cat "${STDERR}")"
    exit_and_cleanup "${RESULT}"
  fi
  IFS=$OLDIFS
}

generate_report() {
  printf '%s\n' "${DIVIDER}"
  prompt_for_caid
  # Create CSV File with headers
  FILENAME="certificates_report_${CAID}_$(date +%s)"
  CSV="${DIR}/${FILENAME}.csv"
  export CSV
  FILENAME="${TMP_WORKING_DIR}/${FILENAME}"
  # Run initial CURL command to fetch first page of certificates
  printf '\n%s\n' "[$(date -Iseconds)] Fetching list of certificate events..."
  if [[ "${CURL_VERSION}" == "OLD" ]]; then
    ${CURL_COMMAND} -s --header "Accept: application/json" -H "Content-Type: application/json" --cert-type PEM --cert "${P12_CERT}" --key "${P12_KEY}" --cacert "${P12_CA}"  "$CAGW_URL/v1/certificate-authorities/$CAID/certificate-events?preferredPageSize=${PAGE_SIZE}&startDate=${REPORT_START_DATE}" 2>"${STDERR}" 1>"${STDOUT}"; RESULT=$?
  else
    ${CURL_COMMAND} -s --header "Accept: application/json" -H "Content-Type: application/json" --cert-type P12 --cert "$P12":"$P12_PWD" "$CAGW_URL/v1/certificate-authorities/$CAID/certificate-events?preferredPageSize=${PAGE_SIZE}&startDate=${REPORT_START_DATE}" 2>"${STDERR}" 1>"${STDOUT}"; RESULT=$?
  fi
  if [[ "${RESULT}" -ne 0 ]];then
    printf '%s\n' "ERROR ${RESULT}: $(cat "${STDOUT}") $(cat "${STDERR}")"
    exit_and_cleanup "${RESULT}"
  fi
  CURL_OUTPUT=$(cat "${STDOUT}")
  # Stop if CURL_OUTPUT doesn't contain expected JSON Data
  VALID_JSON=$(echo "$CURL_OUTPUT" | jq -r '.type' 2>/dev/null)
  [[ "${VALID_JSON}" != "CertificateEventsResponse" ]] && printf '%s\n%s\n' "ERROR!!" "${CURL_OUTPUT}" && main
  NEXT_PAGE_INDEX=$(echo "${CURL_OUTPUT}" | jq -r '.nextPageIndex')
  MORE_PAGES=$(echo "${CURL_OUTPUT}" | jq -r '.morePages')
  TOTAL_CERT_EVENTS=$(echo "${CURL_OUTPUT}" | jq -r '.events | length')

  FILECOUNT=1
  JSON_FILENAME="${FILENAME}.${FILECOUNT}.json"
  echo "${CURL_OUTPUT}" | jq '.events' > "${JSON_FILENAME}"

  [[ "${CAGW_TYPE}" -eq "${PKIAAS}" ]] && echo "CAGW API requests to fetch certificate events are limited to 50 events per page when using PKIaaS."
  while [[ ${MORE_PAGES} == "true" ]]; do
    printf '\r%s' "Fetched ${TOTAL_CERT_EVENTS}. Fetching next batch of ${PAGE_SIZE} certificate events."
    if [[ "${CURL_VERSION}" == "OLD" ]]; then
      ${CURL_COMMAND} -s --header "Accept: application/json" -H "Content-Type: application/json" --cert-type PEM --cert "${P12_CERT}" --key "${P12_KEY}" --cacert "${P12_CA}"  "$CAGW_URL/v1/certificate-authorities/$CAID/certificate-events?preferredPageSize=${PAGE_SIZE}&startDate=${REPORT_START_DATE}&nextPageIndex=$NEXT_PAGE_INDEX" 2>"${STDERR}" 1>"${STDOUT}"; RESULT=$?
    else
      ${CURL_COMMAND} -s --header "Accept: application/json" -H "Content-Type: application/json" --cert-type P12 --cert "$P12":"$P12_PWD" "$CAGW_URL/v1/certificate-authorities/$CAID/certificate-events?preferredPageSize=${PAGE_SIZE}&startDate=${REPORT_START_DATE}&nextPageIndex=$NEXT_PAGE_INDEX" 2>"${STDERR}" 1>"${STDOUT}"; RESULT=$?
    fi
    if [[ "${RESULT}" -ne 0 ]]; then
      printf '\n%s\n' "ERROR ${RESULT}: $(cat "${STDOUT}") $(cat "${STDERR}")"
      exit_and_cleanup "${RESULT}"
    fi
    CURL_OUTPUT=$(cat "${STDOUT}")
    NEXT_PAGE_INDEX=$(echo "${CURL_OUTPUT}" | jq -r '.nextPageIndex')
    MORE_PAGES=$(echo "${CURL_OUTPUT}" | jq -r '.morePages')
    TOTAL_CERT_EVENTS=$(( TOTAL_CERT_EVENTS + $(echo "${CURL_OUTPUT}" | jq -r '.events | length') ))
    FILECOUNT=$(( FILECOUNT + 1 ))
    JSON_FILENAME="${FILENAME}.${FILECOUNT}.json"
    echo "${CURL_OUTPUT}" | jq -r '.events' > "${JSON_FILENAME}"
    unset CURL_OUTPUT
  done
  sanitize_cert_events "${FILENAME}" "${FILECOUNT}"
  printf '\n'
}

revoke_subject() {
  printf '%s\n' "${DIVIDER}"
  [[ "${CAGW_TYPE}" -eq "${PKIAAS}" ]] && echo "The CAGW API for PKIaaS does not support this feature." && main
  prompt_for_caid
  SUBJECT_DN=""
  while [[ -z "${SUBJECT_DN// }" ]]; do 
    read -rp "Subject DN: " SUBJECT_DN
  done
  get_action_type
  read -rp "Enter a comment about the action (optional): " COMMENT
  get_action_reason
  if [[ "${CURL_VERSION}" == "OLD" ]]; then
    ${CURL_COMMAND} -s --header "Accept: application/json" -H "Content-Type: application/json" --cert-type PEM --cert "${P12_CERT}" --key "${P12_KEY}" --cacert "${P12_CA}"   --data "{\"action\":{\"comment\":\"$COMMENT\",\"type\":\"$ACTION_TYPE\",\"reason\":\"$ACTION_REASON\"}}" "$CAGW_URL/v1/certificate-authorities/$CAID/subjects/$(printf '%s' "${SUBJECT_DN}" | jq -sRr @uri)/actions" 2>"${STDERR}" 1>"${STDOUT}"; RESULT=$?
  else
    ${CURL_COMMAND} -s --header "Accept: application/json" -H "Content-Type: application/json" --cert-type P12 --cert "$P12":"$P12_PWD"  --data "{\"action\":{\"comment\":\"$COMMENT\",\"type\":\"$ACTION_TYPE\",\"reason\":\"$ACTION_REASON\"}}" "$CAGW_URL/v1/certificate-authorities/$CAID/subjects/$(printf '%s' "${SUBJECT_DN}" | jq -sRr @uri)/actions" 2>"${STDERR}" 1>"${STDOUT}"; RESULT=$?
  fi
  if [[ "${RESULT}" -ne 0 ]];then
    printf '%s\n' "ERROR ${RESULT}: $(cat "${STDOUT}") $(cat "${STDERR}")"
    exit_and_cleanup "${RESULT}"
  fi
}


PKIAAS_MENU=(
  "${DIVIDER}"
  "Select the CA Gateway operation:"
  "  1. Generate CSR with subject (using OpenSSL)"
  "  2. List all Certificate Authorities"
  "  3. List all profiles for a Certificate Authority"
  "  4. Enroll new certificate (CSR / P12)"
  "  5. Certificate revocation by serial"
  "  6. Bulk certificate issuance"
  "  7. Bulk certificate revocation"
  "  8. Generate Report of all active certificates (CSV)"
  "  9. Exit"
)

PKIAAS_ACTIONS=(
  "generate_csr"
  "list_cas"
  "list_ca_profiles"
  "enroll_cert"
  "revoke_sn"
  "bulk_issue"
  "bulk_revoke"
  "generate_report"
  "exit_and_cleanup 0"
)

ONPREM_MENU=(
  "${DIVIDER}"
  "Select the CA Gateway operation:"
  "  1. Generate CSR with subject (using OpenSSL)"
  "  2. List all Certificate Authorities"
  "  3. List all profiles for a Certificate Authority"
  "  4. Enroll new certificate (CSR / P12)"
  "  5. Certificate revocation by serial"
  "  6. Bulk certificate issuance"
  "  7. Bulk certificate revocation"
  "  8. Generate Report of all active certificates (CSV)"
  "  9. Revoke Certificates by Subject DN (On-Premises CAGW Only)"
  "  10. Exit"
)
ONPREM_ACTIONS=(
  "generate_csr"
  "list_cas"
  "list_ca_profiles"
  "enroll_cert"
  "revoke_sn"
  "bulk_issue"
  "bulk_revoke"
  "generate_report"
  "revoke_subject"
  "exit_and_cleanup 0"
)


main() {
  [[ "${CAGW_TYPE}" -eq "${PKIAAS}" ]] && export MENU=( "${PKIAAS_MENU[@]}" ) && export ACTIONS=( "${PKIAAS_ACTIONS[@]}" )
  [[ "${CAGW_TYPE}" -eq "${ONPREM}" ]] && export MENU=( "${ONPREM_MENU[@]}" ) && export ACTIONS=( "${ONPREM_ACTIONS[@]}" )
  for (( i = 0 ; i < "${#MENU[@]}" ; i++ )); do
    printf '%s\n' "${MENU[${i}]}"
  done
  read -rp "Selection: " CAGW_OP
  [[ "${CAGW_OP}" -le 0 || "${CAGW_OP}" -gt "${#MENU[@]}" ]] && main
  eval "${ACTIONS[$(( CAGW_OP - 1 ))]}"
  main
}

init
main