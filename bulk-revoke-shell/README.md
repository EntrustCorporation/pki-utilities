## Introduction
PKIaaS relies on Entrust ECS Enterprise portal for CA provisioning and manual issuance and revocation of end-entity certificates. 

In some cases, customers need to bulk revoke multiple (hundreds or even thousands of) certificates, especially when customers are blocked from issuing certificates when the certificate licenses are maxed out.  Using the ECS enterprise portal to revoke the certificates one by one is time-consuming.  

That is why we built this tool to allow customers to bulk revoke PKIaaS certificates.

## Prerequisites
1. PKIaaS Root CA and Issuing CA is set up and active.
   - Copy and store the CA identifier(CAID):
![image](https://user-images.githubusercontent.com/98990887/171658845-a006a93b-bda6-4cf5-9026-b7fa3f734b32.png)

2. CA Gateway Credential is downloaded along with the password.
   - To generate and download the CA Gateway credentials

| Step | Description |
| --- | --- |
| 1. | Select Administration > PKIaaS Management. |
| 1. | Select Administration > PKIaaS Management. |
