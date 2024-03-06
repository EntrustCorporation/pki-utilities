## Entrust Certificate Authority (CA) Gateway Shell utility

### Table of Contents

[Prerequisites](https://github.com/EntrustCorporation/pki-utilities/tree/main/cagw-shell-util#entrust-certificate-authority-ca-gateway-shell-utility)

* [Acquiring credentials](https://github.com/EntrustCorporation/pki-utilities/tree/main/cagw-shell-util#acquiring-credentials)

[Operations supported by the utility](https://github.com/EntrustCorporation/pki-utilities/tree/main/cagw-shell-util#operations-supported-by-the-utility)

[Running the script](https://github.com/EntrustCorporation/pki-utilities/tree/main/cagw-shell-util#running-the-script)

* [Generate CSR with subject](https://github.com/EntrustCorporation/pki-utilities/tree/main/cagw-shell-util#generate-csr-with-subject)
* [List all Certificate Authorities](https://github.com/EntrustCorporation/pki-utilities/tree/main/cagw-shell-util#list-all-certificate-authorities)
* [List all profiles for a Certificate Authority](https://github.com/EntrustCorporation/pki-utilities/tree/main/cagw-shell-util#list-all-profiles-for-a-certificate-authority)
* [Enroll new certificate with CSR](https://github.com/EntrustCorporation/pki-utilities/tree/main/cagw-shell-util#enroll-new-certificate-with-csr)
* [Enroll new certificate with PKCS #12](https://github.com/EntrustCorporation/pki-utilities/tree/main/cagw-shell-util#enroll-new-certificate-with-pkcs-12)
* [Certificate revocation by serial](https://github.com/EntrustCorporation/pki-utilities/tree/main/cagw-shell-util#certificate-revocation-by-serial)
* [Bulk certificate issuance](https://github.com/EntrustCorporation/pki-utilities/tree/main/cagw-shell-util#bulk-certificate-issuance)
* [Bulk certificate revocation](https://github.com/EntrustCorporation/pki-utilities/tree/main/cagw-shell-util#bulk-certificate-revocation)
* [Generate Report of Active Certificates](https://github.com/EntrustCorporation/pki-utilities/tree/main/cagw-shell-util#generate-report-of-active-certificates)

### Prerequisites
#### Acquiring credentials
1. PKIaaS Root CA and Issuing CA is set up and active.
   - Copy and store the CA identifier(CAID):
![image](https://user-images.githubusercontent.com/98990887/171658845-a006a93b-bda6-4cf5-9026-b7fa3f734b32.png)

2. CA Gateway Credential is downloaded along with the password.
   - To generate and download the CA Gateway credentials

| Step | Description |
| --- | --- |
| 1. | Select **Administration > PKIaaS Management.** |
| 2. | In the side pane, click **CA GW Credentials.** |
| 3. | Click **Generate CA Gateway Credential.** |
| 4. | Select an issuing **Certification Authority.**<br />![image](https://user-images.githubusercontent.com/98990887/172181635-935e89d9-5b37-4c75-b7f7-3a25d350bcab.png) |
| 5. | Click **Submit** and accept the confirmation request. |
| 6. | The credential will appear in the grid with the **Provisioning** status. Refresh the grid to check completion. |
| 7. | When the credential status is **Active**, click the credential row and select **Actions > Download**.<br />![image](https://user-images.githubusercontent.com/98990887/172181770-2225d0f8-074d-4b61-81ef-94e75d9e4b0c.png) |
| 8. | Copy and store the PKCS12 password and the CA Gateway URL. |
| 9. | Click **Download PKCS12.**<br />![image](https://user-images.githubusercontent.com/98990887/172181900-f3adc645-ca85-4483-b90b-3e0b482d754a.png) |

[return to top of page](https://github.com/EntrustCorporation/pki-utilities/tree/main/cagw-shell-util#entrust-certificate-authority-ca-gateway-shell-utility)

### Operations supported by the utility

- Generate CSR with subject (using OpenSSL)
- List all Certificate Authorities
- List all profiles for a Certificate Authority
- Enroll new certificate with CSR
- Enroll new certificate with P12
- Certificate revocation by serial
- Bulk certificate issuance
- Generate report of active certificates (CSV)

[return to top of page](https://github.com/EntrustCorporation/pki-utilities/tree/main/cagw-shell-util#entrust-certificate-authority-ca-gateway-shell-utility)

### Running the script
Execute the script in a terminal which has access to the CAGW Client Credential P12.
The script will prompt for the following information:

- Path to CAGW Client Credential P12
- Password for the CAGW Client Credential P12
- The URL for CAGW (such as https://cagw.pkiaas.entrust.com/cagw)

Sample output:

```
--------------------------
Entrust CA Gateway Utility
--------------------------
Path to client credentials file (PKCS#12): ./entrust-cagw-rqblr8xekifien.p12
Enter PKCS#12 file password: Please select the CAGW type:
  1. PKIaaS
  2. On-Premises
CAGW Type: 1
Please select the PKIaaS Region:
  1. US: https://cagw.pkiaas.entrust.com/cagw
  2. EU: https://cagw.eu.pkiaas.entrust.com/cagw
  3. PQ: https://cagw.pqlab.pkiaas.entrust.com/cagw
CAGW REGION: 1
--------------------------
CAGW P12: ./entrust-cagw-rqblr8xekifien.p12
CAGW URL: https://cagw.pkiaas.entrust.com/cagw

--------------------------
Select the CA Gateway operation:
  1. Generate CSR with subject (using OpenSSL)
  2. List all Certificate Authorities
  3. List all profiles for a Certificate Authority
  4. Enroll new certificate
  5. Certificate revocation by serial
  6. Bulk certificate issuance
  7. Bulk certificate revocation
  8. Fetch all active certificates
  9. Exit
```

[return to top of page](https://github.com/EntrustCorporation/pki-utilities/tree/main/cagw-shell-util#entrust-certificate-authority-ca-gateway-shell-utility)

#### Generate CSR with subject
Generate CSR with given subject.

It also massages the CSR so that the request is acceptable by CA Gateway.

CA Gateway, currently requires header, footer, and nelines deleted.

Sample output:

```
--------------------------
Select the CA Gateway operation:
  1. Generate CSR with subject (using OpenSSL)
  2. List all Certificate Authorities
  3. List all profiles for a Certificate Authority
  4. Enroll new certificate
  5. Certificate revocation by serial
  6. Bulk certificate issuance
  7. Bulk certificate revocation
  8. Fetch all active certificates
  9. Exit
Selection: 1
--------------------------
Enter full subject
Example: /C=CA/ST=Ontario/L=Ottawa/O=My Org/OU=IT/CN=example.com
/CN=example.com
Enter key type: rsa
Enter key length: 2048
Where would you like to store the key (e.g. /tmp/example.key): ./example.key
Where would you like to store the CSR (e.g. /tmp/example.csr): ./example.csr
```

[return to top of page](https://github.com/EntrustCorporation/pki-utilities/tree/main/cagw-shell-util#entrust-certificate-authority-ca-gateway-shell-utility)

#### List all Certificate Authorities
Fetches all the Certificate Authorities as configured on a given CA Gateway instance.

Requires CA Gateway credentials for authenticating requests.
Prints out a list of Certificate Authorities.

Sample output:

```
--------------------------
Select the CA Gateway operation:
  1. Generate CSR with subject (using OpenSSL)
  2. List all Certificate Authorities
  3. List all profiles for a Certificate Authority
  4. Enroll new certificate
  5. Certificate revocation by serial
  6. Bulk certificate issuance
  7. Bulk certificate revocation
  8. Fetch all active certificates
  9. Exit
Selection: 2
--------------------------
{
  "type" : "CAListResponse",
  "caList" : [ {
    "id" : "ecsmcn158emsuw~1sw46hf1g0wrdc",
    "name" : "pkiaas prod env connection: ecsmcn158emsuw~1sw46hf1g0wrdc",
    "properties" : {
      "connector-name" : "com.entrust.PKIHub",
      "type" : "PKIaaS Certificate Authority"
    },
    "chain" : [ ]
  }, {
    "id" : "ecsmcn158emsuw~mrajwn1pklzxjb",
    "name" : "pkiaas prod env connection: ecsmcn158emsuw~mrajwn1pklzxjb",
    "properties" : {
      "connector-name" : "com.entrust.PKIHub",
      "type" : "PKIaaS Certificate Authority"
    },
    "chain" : [ ]
  } ]
}
```

[return to top of page](https://github.com/EntrustCorporation/pki-utilities/tree/main/cagw-shell-util#entrust-certificate-authority-ca-gateway-shell-utility)

#### List all profiles for a Certificate Authority
Fetches all the Certificate Profiles configured for a give Certificate Authority.

Requires CA Gateway credentials for authenticating requests.
Prints a list of Certificate Profiles supported on the selected Certificate Authority.

```
--------------------------
Select the CA Gateway operation:
  1. Generate CSR with subject (using OpenSSL)
  2. List all Certificate Authorities
  3. List all profiles for a Certificate Authority
  4. Enroll new certificate
  5. Certificate revocation by serial
  6. Bulk certificate issuance
  7. Bulk certificate revocation
  8. Fetch all active certificates
  9. Exit
Selection: 3
--------------------------
Select a CA ID:
1. Issuing-CA: ecsmcn158emsuw~1sw46hf1g0wrdc (CN=Example Issuing)
2. Root-CA: ecsmcn158emsuw~mrajwn1pklzxjb (CN=Example Root)
Enter CA ID [ecsmcn158emsuw~mrajwn1pklzxjb]: 2
--------------------------
{
  "message" : {
    "message" : "Profiles retrieved successfully.",
    "details" : [ ]
  },
  "profiles" : [ {
    "id" : "basic-ca-subord",
    "name" : "basic-ca-subord",
    "properties" : {
      "cert_lifetime" : "87600h0m0s",
      "issue_ca_certificate" : "true",
      "key_client_generated" : "true",
      "key_usage" : "digital signature, cert sign, crl sign"
    },
    "protocols" : [ ],
    "requestedProperties" : [ ],
    "subjectAltNameRequirements" : [ ],
    "subjectVariableRequirements" : [ ]
  } ],
  "type" : "ProfilesResponse"
}
```

[return to top of page](https://github.com/EntrustCorporation/pki-utilities/tree/main/cagw-shell-util#entrust-certificate-authority-ca-gateway-shell-utility)

#### Enroll new certificate with CSR

Submit an enrollment request using a pre-generated CSR file. The user will be prompted to select the desired Certificate Authority and the desired Certificate Profile.

The resulting certificate will be saved to the user-defined path.

You can optionally add multiple Subject Altnames to the request.

Sample output:

```
--------------------------
Select the CA Gateway operation:
  1. Generate CSR with subject (using OpenSSL)
  2. List all Certificate Authorities
  3. List all profiles for a Certificate Authority
  4. Enroll new certificate
  5. Certificate revocation by serial
  6. Bulk certificate issuance
  7. Bulk certificate revocation
  8. Fetch all active certificates
  9. Exit
Selection: 4
--------------------------
Select a CA ID:
1. Issuing-CA: ecsmcn158emsuw~1sw46hf1g0wrdc (CN=Example Issuing)
2. Root-CA: ecsmcn158emsuw~mrajwn1pklzxjb (CN=Example Root)
Enter CA ID []: 1
Select a Profile ID:
1. mdmws-digital-signature
2. mdmws-digital-signature-key-encipherment
3. mdmws-digital-signature-key-encipherment-clientauth
4. mdmws-key-encipherment
5. mdmws-non-repudiation
Enter Profile ID []: 3
Select an enrollment type:
  1. CSR
  2. PKCS #12
Enrollment Type: 1
Enter path to an existing CSR file ['']: ./example.csr
Where would you like to store the certificate (e.g. ./certificate.pem): ./example.crt
Enter full subject DN (i.e. cn=example.com): cn=example.com
Do you want to add a Subject Alternate Name (Y/N): y
Select the SAN attribute to be added from the list
  1. rfc822Name
  2. dNSName
  3. directoryName
  4. uniformResourceIdentifier
  5. iPAddress
  6. registeredID
SAN Type: 2
Enter value of the selected SAN attribute (dNSName): example.com
Do you want to add a Subject Alternate Name (Y/N): n

Certificate is written successfully to the file ./example.crt.
```

[return to top of page](https://github.com/EntrustCorporation/pki-utilities/tree/main/cagw-shell-util#entrust-certificate-authority-ca-gateway-shell-utility)

#### Enroll new certificate with PKCS #12
Submit an enrollment request without requiring a CSR. CAGW will generate a private key and a certificate in a password protected P12 file. The user will be prompted to select the desired Certificate Authority, Certificate Profile, and password to secure the P12 file.

The resulting certificate will be saved to the user-defined path.

You can optionally add multiple Subject Altnames to the request.

Sample output:

```
--------------------------
Select the CA Gateway operation:
  1. Generate CSR with subject (using OpenSSL)
  2. List all Certificate Authorities
  3. List all profiles for a Certificate Authority
  4. Enroll new certificate
  5. Certificate revocation by serial
  6. Bulk certificate issuance
  7. Bulk certificate revocation
  8. Fetch all active certificates
  9. Exit
Selection: 4
--------------------------
Select a CA ID:
1. Issuing-CA: ecsmcn158emsuw~1sw46hf1g0wrdc (CN=Example Issuing)
2. Root-CA: ecsmcn158emsuw~mrajwn1pklzxjb (CN=Example Root)
Enter CA ID [ecsmcn158emsuw~1sw46hf1g0wrdc]: 1
Select a Profile ID:
1. mdmws-digital-signature
2. mdmws-digital-signature-key-encipherment
3. mdmws-digital-signature-key-encipherment-clientauth
4. mdmws-key-encipherment
5. mdmws-non-repudiation
Enter Profile ID []: 3
Select an enrollment type:
  1. CSR
  2. PKCS #12
Enrollment Type: 2
Enter a password to secure the P12 file:
Where would you like to store the certificate (e.g. ./certificate.p12): ./example.p12
Enter full subject DN (i.e. cn=example.com): cn=example.com
Do you want to add a Subject Alternate Name (Y/N): y
Select the SAN attribute to be added from the list
  1. rfc822Name
  2. dNSName
  3. directoryName
  4. uniformResourceIdentifier
  5. iPAddress
  6. registeredID
SAN Type: 2
Enter value of the selected SAN attribute (dNSName): example.com
Do you want to add a Subject Alternate Name (Y/N): n

Certificate is written successfully to the file ./example.p12.
```

[return to top of page](https://github.com/EntrustCorporation/pki-utilities/tree/main/cagw-shell-util#entrust-certificate-authority-ca-gateway-shell-utility)

#### Certificate revocation by serial
Revoke/renew/reissue certificate using the certificate's serial number.

Sample output:

```
--------------------------
Select the CA Gateway operation:
  1. Generate CSR with subject (using OpenSSL)
  2. List all Certificate Authorities
  3. List all profiles for a Certificate Authority
  4. Enroll new certificate
  5. Certificate revocation by serial
  6. Bulk certificate issuance
  7. Bulk certificate revocation
  8. Fetch all active certificates
  9. Exit
Selection: 5
--------------------------
Select a CA ID:
1. Issuing-CA: ecsmcn158emsuw~1sw46hf1g0wrdc (CN=Example Issuing)
2. Root-CA: ecsmcn158emsuw~mrajwn1pklzxjb (CN=Example Root)
Enter CA ID []: 1
Enter certificate serial number in hexadecimal format (Example: 0000000091ca4b4b136a86b718ae01a5403ce62b): 0000000091ca4b4b136a86b718ae01a5403ce62b
Select action type from below
1. Revoke
2. Renew
3. Reissue
Action Type: 1
Enter a comment about the action (optional):
Select action reason from below
1. unspecified
2. keyCompromise
3. caCompromise
4. affiliationChanged
5. superseded
6. cessationOfOperation
7. certificateHold
8. privilegeWithdrawn

Action Reason: 1
{
  "type" : "ActionResponse",
  "action" : {
    "type" : "RevokeAction",
    "id" : "98c1a818-0896-4dac-bab1-4315da5554d1",
    "properties" : { },
    "comment" : "",
    "status" : "COMPLETED",
    "succeedIfAlreadyInRequestedState" : true,
    "reason" : "unspecified",
    "compromiseDate" : "2024-03-05T22:43:23.429157524Z"
  }
}
```

[return to top of page](https://github.com/EntrustCorporation/pki-utilities/tree/main/cagw-shell-util#entrust-certificate-authority-ca-gateway-shell-utility)

#### Bulk certificate issuance
Use a CSV file to generate keys and certs in bulk.

Sample CSV file must have the data arranged in the following format **without headers**.

| commonName | keyLen | keyAlgo |
| --- | --- | --- |
| example.com | 2048 | rsa |
| abc.corp | 2048 | rsa |

See below for an excerpt of a valid CSV file:

```
example.com,2048,rsa
abc.corp,2048,rsa
```

Sample output:

```
--------------------------
Select the CA Gateway operation:
  1. Generate CSR with subject (using OpenSSL)
  2. List all Certificate Authorities
  3. List all profiles for a Certificate Authority
  4. Enroll new certificate
  5. Certificate revocation by serial
  6. Bulk certificate issuance
  7. Bulk certificate revocation
  8. Fetch all active certificates
  9. Exit
Selection: 6
--------------------------
Select a CA ID:
1. Issuing-CA: ecsmcn158emsuw~1sw46hf1g0wrdc (CN=Example Issuing)
2. Root-CA: ecsmcn158emsuw~mrajwn1pklzxjb (CN=Example Root)
Enter CA ID []: 1
Select a Profile ID:
1. mdmws-digital-signature
2. mdmws-digital-signature-key-encipherment
3. mdmws-digital-signature-key-encipherment-clientauth
4. mdmws-key-encipherment
5. mdmws-non-repudiation
Enter Profile ID []: 3
Note, this operation requires a CSV-formatted file in the following format:
Common Name, Key Algorithm, Key Size
For example:
example common name, rsa, 4096
Enter the path to the CSV file: ./bulk.csv
Enter the path for saving keys and certs: /tmp
Processing list of 2 bulk certificate enrollments...
Certificates and Keys written to the folder /tmp
```

[return to top of page](https://github.com/EntrustCorporation/pki-utilities/tree/main/cagw-shell-util#entrust-certificate-authority-ca-gateway-shell-utility)

#### Bulk certificate revocation
Revoke a list of certificates using a CSV File.
The contents of the CSV file must contain serial numbers in the 2nd column. For example, the following structure is valid

| commonName | serialNumber
| --- | --- |
| example.com | 00000000dc517fb9b9c3eb3b890ff2a34812e33c |
| abc.corp | 0000000011ddbf8d7346f20834769f7a8ffc43ca |

See below for an excerpt of a valid CSV file:

```
example.com,00000000dc517fb9b9c3eb3b890ff2a34812e33c
abc.corp,0000000011ddbf8d7346f20834769f7a8ffc43ca
```

Sample output:

```
--------------------------
Select the CA Gateway operation:
  1. Generate CSR with subject (using OpenSSL)
  2. List all Certificate Authorities
  3. List all profiles for a Certificate Authority
  4. Enroll new certificate
  5. Certificate revocation by serial
  6. Bulk certificate issuance
  7. Bulk certificate revocation
  8. Fetch all active certificates
  9. Exit
Selection: 7
--------------------------
Enter the path to the CSV file: revoke.csv
Select a CA ID:
1. Issuing-CA: ecsmcn158emsuw~1sw46hf1g0wrdc (CN=Example Issuing)
2. Root-CA: ecsmcn158emsuw~mrajwn1pklzxjb (CN=Example Root)
Enter CA ID []: 1
Does the CSV File contain a row of headers (Y/N): n
Select action reason from below
1. unspecified
2. keyCompromise
3. caCompromise
4. affiliationChanged
5. superseded
6. cessationOfOperation
7. certificateHold
8. privilegeWithdrawn

Action Reason: 2
REVOKE SN : 00000000dc517fb9b9c3eb3b890ff2a34812e33c
{
  "type" : "ActionResponse",
  "action" : {
    "type" : "RevokeAction",
    "id" : "57013ff6-ab6d-4a4a-a277-ea03100ae48e",
    "properties" : { },
    "comment" : "",
    "status" : "COMPLETED",
    "succeedIfAlreadyInRequestedState" : true,
    "reason" : "keyCompromise",
    "compromiseDate" : "2024-03-06T12:48:02.293536733Z"
  }
}REVOKE SN : 0000000011ddbf8d7346f20834769f7a8ffc43ca
{
  "type" : "ActionResponse",
  "action" : {
    "type" : "RevokeAction",
    "id" : "b02f3a7c-7e30-467f-90e3-fb123884c170",
    "properties" : { },
    "comment" : "",
    "status" : "COMPLETED",
    "succeedIfAlreadyInRequestedState" : true,
    "reason" : "keyCompromise",
    "compromiseDate" : "2024-03-06T12:48:02.681390364Z"
  }
}
```

[return to top of page](https://github.com/EntrustCorporation/pki-utilities/tree/main/cagw-shell-util#entrust-certificate-authority-ca-gateway-shell-utility)

#### Generate Report of Active Certificates
Generate a CSV-formatted report of all active certificates from the selected Certificate Authority.

Sample output:

```
--------------------------
Select the CA Gateway operation:
  1. Generate CSR with subject (using OpenSSL)
  2. List all Certificate Authorities
  3. List all profiles for a Certificate Authority
  4. Enroll new certificate
  5. Certificate revocation by serial
  6. Bulk certificate issuance
  7. Bulk certificate revocation
  8. Fetch all active certificates
  9. Exit
Selection: 8
--------------------------
Select a CA ID:
1. Issuing-CA: ecsmcn158emsuw~1sw46hf1g0wrdc (CN=Example Issuing)
2. Root-CA: ecsmcn158emsuw~mrajwn1pklzxjb (CN=Example Root)
Enter CA ID []: 1

Fetching list of certificate events...
CAGW API requests to fetch certificate events are limited to 50 events per page when using PKIaaS.
Fetched 50. Fetching next batch of 50 certificate events.
Fetched 100. Fetching next batch of 50 certificate events.
Fetched 150. Fetching next batch of 50 certificate events.
Fetched 200. Fetching next batch of 50 certificate events.
Fetched 250. Fetching next batch of 50 certificate events.
Fetched 300. Fetching next batch of 50 certificate events.
Fetched 350. Fetching next batch of 50 certificate events.
Fetched 400. Fetching next batch of 50 certificate events.
Fetched 450. Fetching next batch of 50 certificate events.
Fetched 500. Fetching next batch of 50 certificate events.

Processing certificiate events...
Searching for revoked certificate events...
Removing expired certificate entries...
Extracting certificate details...
Processed 48 of 548 non-revoked certificates
Processed 98 of 548 non-revoked certificates
Processed 148 of 548 non-revoked certificates
Processed 198 of 548 non-revoked certificates
Processed 248 of 548 non-revoked certificates
Processed 298 of 548 non-revoked certificates
Processed 348 of 548 non-revoked certificates
Processed 398 of 548 non-revoked certificates
Processed 448 of 548 non-revoked certificates
Processed 498 of 548 non-revoked certificates
Processed 548 of 548 non-revoked certificates

Fetched a total of 550 certificate events
Removed 2 revoked certificates entries (this is typically double the number of revoked certificates)
CSV Contains 0 expired certificates
CSV Contains 548 active certificate
CSV File: ./certificates_report_ecsmcn158emsuw~1sw46hf1g0wrdc_1709679837.csv
```

[return to top of page](https://github.com/EntrustCorporation/pki-utilities/tree/main/cagw-shell-util#entrust-certificate-authority-ca-gateway-shell-utility)
