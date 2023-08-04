## Introduction

PKIaaS relies on Entrust ECS Enterprise portal for CA provisioning and manual issuance and revocation of end-entity certificates.

In some cases, customers need to bulk revoke multiple (hundreds or even thousands of) certificates, especially when customers are blocked from issuing certificates when the certificate licenses are maxed out.  Using the ECS enterprise portal to revoke the certificates one by one is time-consuming.  

That is why we built this tool to allow customers to bulk revoke PKIaaS certificates.

## Prerequisites

1. Have a Linux machine with `bash`, that also has `curl` v7.81 or higher already installed.
2. PKIaaS Root CA and Issuing CA are set up and active.
   - Copy and store the Issuing CA identifier (CAID):
![image](https://user-images.githubusercontent.com/98990887/171658845-a006a93b-bda6-4cf5-9026-b7fa3f734b32.png)

3. **CA Gateway Credential (PKCS#12)** is downloaded along with the password.
   - To generate and download the **CA Gateway Credential**:

    | Step | Description |
    | --- | --- |
    | 1. | Select **Administration > PKIaaS Management.** |
    | 2. | In the side pane, click **CA GW Credentials.** |
    | 3. | Click **Generate CA Gateway Credential.** |
    | 4. | Select an issuing **Certification Authority.**<br />![image](https://user-images.githubusercontent.com/98990887/172181635-935e89d9-5b37-4c75-b7f7-3a25d350bcab.png) |
    | 5. | Click **Submit** and accept the confirmation request. |
    | 6. | The credential will appear in the grid with the **Provisioning** status. Refresh the grid to check completion. |
    | 7. | When the credential status is **Active**, click the credential row and select **Actions > Download**.<br />![image](https://user-images.githubusercontent.com/98990887/172181770-2225d0f8-074d-4b61-81ef-94e75d9e4b0c.png) |
    | 8. | Copy and store the PKCS#12 password and the CA Gateway URL. |
    | 9. | Click **Download PKCS12.**<br />![image](https://user-images.githubusercontent.com/98990887/172181900-f3adc645-ca85-4483-b90b-3e0b482d754a.png) |

## Steps to follow to run the script

1. Export the certificates that need to be revoked.
   - To export certificates on **ECS Enterprise Portal**:

        | Step | Description |
        | --- | --- |
        | 1. | Go to **Certificates > Managed Certificates > PKIaaS Certificates**. |
        | 2. | Select one or more certificates on the grid. |
        | 3. | Click **Export to Excel** to export the selected certificates in .xlsx file.<br />![image](https://user-images.githubusercontent.com/98990887/172182457-de4bfadc-b2c0-4534-9937-5a45adb42680.png) |
        | 4. | Open the .xlsx file and save it as a CSV file |

2. Download the **PKIaaS Bulk Revocation Script** from this repository.
3. Put the **PKIaaS Bulk Revocation Script**, the **CA Gateway Credential (PKCS#12)**, and the converted CSV file in one folder.
4. Edit the **PKIaaS Bulk Revocation Script** and enter the CAID of the Issuing CA, check that the INPUT file matches the file name of the converted CSV file and that P12 points to the proper **CA Gateway Credential (PKCS#12)** file as shown here:

    ```bash
    CAID=ecssample~sample
    INPUT=./certificate_list.csv
    P12=./cagw.p12
    CAGW_URL=https://cagw.pkiaas.entrust.com
    ```

5. Execute the script and enter the **CA Gateway Credential (PKCS#12)** password when asked.

Now all the certificates listed in the CSV should be revoked.

**Note**: This script is tied to a credential that only talks to one issuing CA. If you have multiple issuing CAs and need to bulk revoke certificates issued by different issuing CAs, please repeat the steps to revoke the certificates issued by each issuing CA separately.
