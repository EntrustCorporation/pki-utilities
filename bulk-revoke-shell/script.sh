#!/bin/bash
CAID=ecssample~sample
INPUT=./certlist.csv
P12=./cagw.p12
CAGW_URL=https://cagw.pkiaas.entrust.com
REV_REASON=cessationOfOperation
read -sp "$P12 Password: " P12_PWD
OLDIFS=$IFS
IFS=','
[ ! -f $INPUT ] && {
  echo "$INPUT file not found"
  exit 99
}
[ ! -f $P12 ] && {
  echo "$P12 file not found"
  exit 99
}
headers=0
snToRevoke=0
while read dummy1 sn dummy2; do
  if test "$headers" == "0"; then
    headers=1
    continue
  fi
  if test "$snToRevoke" != "0"; then
    echo "REVOKE SN : $snToRevoke"
    curl --header "Accept: application/json" -H "Content-Type: application/json" --data "{\"action\":{\"type\":\"RevokeAction\",\"reason\":\"$REV_REASON\"}}" --cert-type P12 \
      --cert $P12:$P12_PWD $CAGW_URL/cagw/v1/certificate-authorities/$CAID/certificates/$snToRevoke/actions
    res=$?
    if test "$res" != "0"; then
      echo "ERROR!!!: $res"
    fi
  fi
  snToRevoke=$sn
done <$INPUT

echo "REVOKE SN : $snToRevoke"
curl --header "Accept: application/json" -H "Content-Type: application/json" --data "{\"action\":{\"type\":\"RevokeAction\",\"reason\":\"$REV_REASON\",\"issueCrl\":\"true\"}}" \
  --cert-type P12 --cert $P12:$P12_PWD $CAGW_URL/cagw/v1/certificate-authorities/$CAID/certificates/$snToRevoke/actions
res=$?
if test "$res" != "0"; then
  echo "ERROR!!!: $res"
fi

IFS=$OLDIFS
