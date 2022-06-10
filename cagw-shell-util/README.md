## Entrust Certificate Authority (CA) Gateway Shell utility

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

### Operations supported by the utility

- Generate CSR with subject (using OpenSSL)
- List all Certificate Authorities
- List all profiles for a Certificate Authority
- Enroll new certificate with CSR
- Certificate revocation by serial
- Bulk certificate issuance

#### Generate CSR with subject
Generate CSR with given subject.

It also massages the CSR so that the request is acceptable by CA Gateway.

CA Gateway, currently requires header, footer, and nelines deleted.

```
Enter full subject (Example: /C=CA/ST=Ontario/L=Ottawa/O=My Org/OU=IT/CN=example.com): /CN=example.com
Enter key type: rsa
Enter key length: 2048
Where would you like to store the key (e.g. /tmp/example.key): ./example.key
Where would you like to store the CSR (e.g. /tmp/example.csr): ./example.csr
```

#### List all Certificate Authorities
Fetches all the Certificate Authorities as configured on a given CA Gateway instance.

Requires CA Gateway credentials for authenticating requests.

```
Path to client credentials file (PKCS#12): <Path to p12 file downloaded from ECS>
Enter PKCS#12 file password: <P12 password>
Enter CA Gateway URL (e.g. https://CAGW-Host/cagw): <CAGW URL>
# Select option 2 list all CA Gateway supported CAs
```

#### List all profiles for a Certificate Authority
Fetches all the Certificate Profiles configured for a give Certificate Authority.

Requires CA Gateway credentials for authenticating requests.

```
Path to client credentials file (PKCS#12): <Path to p12 file downloaded from ECS>
Enter PKCS#12 file password: <P12 password>
Enter CA Gateway URL (e.g. https://CAGW-Host/cagw): <CAGW URL>
Enter CA ID: <Get the CA ID using option 2>
# Select option 3 list all CA Certificate Profiles
```

#### Enroll new certificate with CSR
Using a CSR generated via this script or any other external tool, use this option to send that certificate signing request to CA Gateway and get signed certificate back in PEM encoded format. 

You can optionally add Subject Altnames to the request.
```
Enter CA ID []: <Get the CA ID using option 2>
Enter certificate profile ID []: <Get the CA ID using option 3>
Enter path of the CSR file []: <CSR generated using external tool or using option 1>
Where would you like to store the certificate (e.g. /tmp/certificate.pem): <path where you want cert to be saved>
Enter full subject DN: <subject DN of the cert to be issued. e.g. cn=example.com>
Do you want to enter a Subject Alternate Name (Y/N): Y
Select the SAN attribute to be added from the list
1. rfc822Name
2. dNSName
3. directoryName
4. uniformResourceIdentifier
5. iPAddress
6. registeredID
5
Enter value of the selected SAN attribute: 1.1.1.1
```

#### Certificate revocation by serial
Revoke/renew/reissue certificate using the certificate's serial number.

```
Enter CA ID: <Get the CA ID using option 2>
Enter certificate serial number (Example: 00112233): <cert serial number>
Select action type from below
1. Revoke
2. Renew
3. Reissue
1
Enter a comment about the action: some comment
Select action reason from below
1. unspecified
2. keyCompromise
3. caCompromise
4. affiliationChanged
5. superseded
6. cessationOfOperation
7. certificateHold
8. privilegeWithdrawn
2
```

#### Bulk certificate issuance
Using a CSV file to generate keys and certs in bulk.

Sample CSV file as below -

| commonName | keyLen | keyAlgo |
| --- | --- | --- |
| example.com | 2048 | rsa |
| myorg.com | 2048 | rsa |

```
Enter CA ID []: <Get the CA ID using option 2>
Enter certificate profile ID []: <Get the CA ID using option 3>
Enter key type: rsa
Enter key length: 2048
Enter the path to the CSV file: ./bulkIssue.csv
Enter the path for saving keys and certs: /tmp/certs
```
