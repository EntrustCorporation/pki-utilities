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

#### List all profiles for a Certificate Authority

#### Enroll new certificate with CSR

#### Certificate revocation by serial

#### Bulk certificate issuance
