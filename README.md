# Demo - AWS Key Management Service - External Key Store

This repository provides code to quickly demonstrate the new feature of AWS KMS, namely External Key Store (XKS).

## Table of Contents

1. [Disclaimer](#disclaimer)
2. [Solution overview](#solution-overview)
3. [Prerequisites](#prerequisites)
4. [Deployment instructions](#deployment-instructions)
5. [Auditing XKS](#auditing-xks)

## Disclaimer

This demonstration relies on a Software-HSM as a backend. While it allows to quickly explore the new XKS feature, it **DOES NOT** grant any additionnal security over the native usage of AWS KMS (arguably, it even *lowers* the security of native AWS KMS). The code of this repository is provided "as-is" and is intended only as a demonstration. It **MUST NOT** be used for a production environment.

In order to afford better control and auditability without sacrificing security, AWS KMS XKS **MUST** be used with real Hardware Security Modules (HSM) as a backend and strong operationnal procedures ensuring the *confidentiality*, *availability* and *durability* of the encryption keys.

You must also understand how the usage of AWS KMS XKS drasticaly increase your scope of responsabilities as a customer. **Failure to do so could result in the definitive loss of all your data**.

See the [AWS KMS XKS announcement](https://aws.amazon.com/blogs/aws/announcing-aws-kms-external-key-store-xks) and the [AWS documentation](https://docs.aws.amazon.com/kms/latest/developerguide/keystore-external.html) as starting points to know more.

## Solution overview

The demonstration setup will look like this:
![overview1](docs/solution-overview.png)

We deploy a dedicated VPC with four subnets in two Availability Zone. The public subnets each contain a single EC2 instance used as a NAT instance for their availability zone. The private subnets each host an EC2 instance with the XKS proxy and SoftHSMv2 installed, as well as a Network Load Balancer with a TLS listener on port TCP 443. The Network Load Balancer will support the creation of a VPC Service Endpoint that AWS KMS will use to talk with the XKS proxy. Finally, XKS proxy instances use an EFS share as storage for SoftHSMv2 so that each instance has access to the same keys. This also ensure that the XKS proxy instances are stateless and throwable.

AWS KMS imposes the use of a custom named VPC Service Endpoint with a TLS listener using a publicly valid X.509 certificate for the same name. It means you need to have a **public** DNS hosted zone at disposal in order to sucessfully deploy this demo (Amazon Route53 is encouraged but not required and you can use another DNS service) because DNS verification is required for the VPC Service Endpoint custom name (and probably also by your X.509 certificate provider).

## Prerequisites

In order to sucessfully deploy this demo, you will need:

- administrative access to an AWS account;
- administrative access to a public DNS hosted zone (Amazon Route53 or an external provider).

The total cost of the AWS resources deployed for this demonstration is expected around $0.09/hour in eu-west-1 (Ireland) - or $2/day.

Assuming you already have all the prerequisites (a public DNS hosted zone) and some AWS knowledge (ACM, CloudFormation and KMS), the deployment should take less than 30 minutes, including AWS validations for the certificate and the custom endpoint service name.

## Deployment instructions

### Choose an AWS region

Choose an AWS region for you deploiement and **stick with it**. For this instructions, we will assume you are using eu-west-3 (Paris) but it should work the same in any region supported by AWS KMS XKS.

### Choose a name for the Endpoint Service

We will deploy a VPC Endpoint Service (see [here](https://docs.aws.amazon.com/vpc/latest/privatelink/concepts.html#concepts-endpoint-services)) to provide access to AWS KMS to our XKS proxy. It is mandatory that this Endpoint Service is given a public DNS name.

As underlined in the prerequisites, you will need access to a public DNS hosted zone to validate the name of the endpoint. You can choose any name under your public domain name.

For example, if you own the domain ```my-domain.com``` ; you could choose ```xks-demo.my-domain.com``` as your VPC Endpoint Service name. We will use this example name in the instructions.

### Create an ACM public certificate

We need a public certificate (i.e. a certificate signed by a public Certification Authority) for the name we chose, e.g. ```xks-demo.my-domain.com```.

The easiest way is to request the certificate directly from AWS Certificate Manager (ACM). You can follow [the AWS documentation](https://docs.aws.amazon.com/acm/latest/userguide/gs-acm-request-public.html) if you don't know how to do it. You should create an RSA2048 public certificate for the service name you chose. ACM will ask for a DNS validation via the creation of a specific CNAME in your public hosted zone.

Alternatively, you can also request the certificate from another provider and import it into ACM (see [AWS documentation](https://docs.aws.amazon.com/acm/latest/userguide/import-certificate.html)).

Regardless of your choice, **you must have the ARN of a valid public certificate in ACM** before going on to the next step of the deployment.

### Deploy the foundations with CloudFormation

Use the CloudFormation template at *cloudformation/template.yml* to deploy the foundation infrastructure. Unfortunatly, CloudFormation cannot easily perform all the required configuration to setup KMS XKS. Nevertheless, it can perform the vast majority of the work.

This template expects the ARN of your ACM certificate as a parameter. You can use the default values for all the other parameters.

Here are the details of the template parameters:

| Parameter             | Default Value           | Description |
|:----------------------|-------------------------|:------------|
| ACMCertificateArn | none | The ACM certificate ARN of the Public Certificate used by the Network Load Balancer. Must use the same name that will be used for the VPC Service Endpoint |
| ProjectName      | demo-xks     | The name of the project to use in resource names and tags |
| XKSProxyAccessKeyId | BETWEEN2TENAND3TENCHARACTERS* | The Access Key ID that the XKS Proxy will use to authenticate requests from KMS |
| XKSProxySecretAccessKey | PleaseReplaceThisWithSomeSecretOfLength43To64* | The Secret Access Key that the XKS Proxy will use to validate the signatures of the requests from KMS |
| NATInstanceAMI | Latest AWS image for amzn2-ami-kernel-5.10-hvm-arm64-gp2 | The AMI used for the NAT instance, you should not change it |
| XKSProxyInstanceAMI | Latest AWS image for amzn2-ami-kernel-5.10-hvm-x86_64-gp2 | The AMI used for the XKS Proxy instance, you should not change it |

\* *Obviously these values are not suited for production use. Also, please note that they will appear in clear text in the user-data of the XKSProxy EC2 instance, along with other dummy secrets.*

If you do not know how to create a CloudFormation stack from a template, you can follow the [AWS CloudFormation documentation](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-console-create-stack.html).

Once the CloudFormation stack is sucessfully deployed, go in the *Outputs* tab. You will find important values for the instructions that follow:

- VPCEndpointService
- XKSProxyAccessKeyId
- XKSProxySecretAccessKey

### Name the VPC Endpoint Service

In the VPC service page, go to the *Endpoint services*, select the one created by CloudFormation at the previous step (referenced in the outputs) and choose **Modify private DNS name** in the *Actions* menu.

![screenshot-rename-vpce-1](docs/screenshot-rename-vpce-1.png)

Tick the box for *Associate a private DNS name with the service* and input the name you chose at the second step and for which you created a certificate.

You now need to verify this name. Once again, this will be done by creating a DNS record in your public DNS Hosted Zone. Here is the TXT record you need to create:

`<Domain verification name>.<Private DNS name> TXT <Domain verification value>`

All three values you need are in the Details pane of your Endpoint Service:
![screenshot-rename-vpce-2](docs/screenshot-rename-vpce-2.png)

The *Domain verification status* of your VPC Endpoint Service will become `Verified` after up to 10 minutes (be patient).

### Configure the External Key Store in AWS KMS

We can now configure an External Key Store for KMS. Go to the KMS service, then in the *External key stores* page and choose **Create external key store**.
![screenshot-create-xks-1](docs/screenshot-create-xks-1.png)

Name it whatever you like.

Choose *VPC endpoint service* as the Proxy connectivity and find your endpoint in the list.

The *Proxy URI endpoint* value should automaticaly become: `https://<Private DNS name>`

For *Proxy credential: Access key ID* and *Proxy credential: Secret access key* use the values found in the CloudFormation stack outputs.

Create the External key store.

![screenshot-create-xks-2](docs/screenshot-create-xks-2.png)

Then Connect it.

![screenshot-create-xks-3](docs/screenshot-create-xks-3.png)

Connection can take some time. Once your key store is successfuly connected, it is proof that the link between your XKS Proxy instance and KMS is ready to be used (congrats).

### Create two CMKs backed by XKS

Last but not least, we can now creates XKS-backed Customer Master Keys (CMK) in KMS!

In principle, when you create an XKS-backed CMK you must give to KMS the *Label* of the key in your HSMs. KMS **will NOT** create the key in your HSMs, it is expected to already exist.

In this demo, two keys are already created in SoftHSMv2 with labels `foo` and `bar` so you can create two CMKs. If you need more, you will need to connect on the XKSProxy instance (using SSM Session Manager) to create additional keys in SoftHSMv2. The commands to do so are all in the User-Data of the instance.

To create an XKS-backed CMK, start by creating a CMK and chose XKS in the *Advanced options*:

![screenshot-create-cmk-1](docs/screenshot-create-cmk-1.png)

Then select your External Key Store and put an HSM key label in *External key ID*:

![screenshot-create-cmk-2](docs/screenshot-create-cmk-2.png)

The remainder of the configuration is just regular CMK creation stuff. If you are unfamiliar with using KMS, use [the documentation](https://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html#create-symmetric-cmk).

## Auditing XKS

On our demo instance, the XKS Proxy log files are configured in debug mode and can be found in: `/var/log/xks-proxy/xks-proxy.log.*`.

The configuration file of the XKS Proxy is at: `/var/local/xks-proxy/.secret/settings.toml`

You are now free to experiment with XKS. Use SSM Session Manager to connect to the XKS Proxy instance and inspect its log or tweek its configuration.

Something we can highlight is the ability to corelate a KMS CloudTrail log event with an XKS Proxy log event. The main advantage of using KMS XKS is indeed the ability to verify that Cloudtrail logs for KMS are accurate and there should always be a 1-to-1 association between Cloudtrail and XKSProxy logs.

As an example, we performed a `kms:GenerateDataKey` on our XKS-backed CMK.

CloudTrail shows the following event (slightly redacted):

```json
{
    "eventVersion": "1.08",
    "userIdentity": {
        "type": "IAMUser",
        "principalId": "AIDAEXAMPLEEXAMPLEEXA",
        "arn": "arn:aws:iam::############:user/example",
        "accountId": "############",
        "accessKeyId": "AKIAEXAMPLEEXAMPLEEX",
        "userName": "example"
    },
    "eventTime": "2023-05-17T08:52:13Z",
    "eventSource": "kms.amazonaws.com",
    "eventName": "GenerateDataKey",
    "awsRegion": "eu-west-3",
    "sourceIPAddress": "#.#.#.#",
    "userAgent": "aws-cli/2.2.7 Python/3.8.8 Windows/10 exe/AMD64 prompt/off command/kms.generate-data-key",
    "requestParameters": {
        "keySpec": "AES_256",
        "keyId": "alias/xks-foo"
    },
    "responseElements": null,
    "additionalEventData": {
        "customKeyStoreId": "cks-22efce94713d0da98",
        "xksKeyId": "foo"
    },
    "requestID": "422bd03b-f1f7-4ece-b12c-2ca109443806",
    "eventID": "f43d2bdc-2118-42fd-bc58-6c9b145edd90",
    "readOnly": true,
    "resources": [
        {
            "accountId": "############",
            "type": "AWS::KMS::Key",
            "ARN": "arn:aws:kms:eu-west-3:############:key/6b88eb2e-4e43-4932-896a-2153e100fb28"
        }
    ],
    "eventType": "AwsApiCall",
    "managementEvent": true,
    "recipientAccountId": "############",
    "eventCategory": "Management",
    "tlsDetails": {
        "tlsVersion": "TLSv1.3",
        "cipherSuite": "TLS_AES_256_GCM_SHA384",
        "clientProvidedHostHeader": "kms.eu-west-3.amazonaws.com"
    }
}
```

And my XKSProxy log (in the instance at `/var/log/xks-proxy/xks-proxy.log.*`) shows:

```text
---------clip------------
2023-05-17T08:52:13.797324Z  INFO tokio-runtime-worker request{method=POST uri=/kms/xks/v1/keys/foo/encrypt version=HTTP/1.1}:encrypt{kmsRequestId="422bd03b-f1f7-4ece-b12c-2ca109443806"}: xks_proxy::xks_proxy::handlers::encrypt: 124: requestMetadata: {"awsPrincipalArn":"arn:aws:iam::############:user/example","kmsOperation":"GenerateDataKey","kmsRequestId":"422bd03b-f1f7-4ece-b12c-2ca109443806","kmsKeyArn":"arn:aws:kms:eu-west-3:############:key/6b88eb2e-4e43-4932-896a-2153e100fb28"}
---------clip------------
```

Note that `requestID` in CloudTrail is the same as `kmsRequestId` in the XKS Proxy logs.

Also note that the XKS Proxy receive the calling Principal and the KMS operation, so it can decide to allow or deny the request based on these informations. Therefore, XKS brings an additionnal autorization mecanism, though authentication is still only performed by AWS IAM.

---
***Made by Jérémie RODON***
