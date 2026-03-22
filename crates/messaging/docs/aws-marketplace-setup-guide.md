# AWS Marketplace Setup Guide

DIDComm Mediator, published on AWS Marketplace, allows you to host the mediator in your AWS account using the CloudFormation template.

Creating a mediator instance from AWS Marketplace gives you full control over the configuration, scaling, and resource usage of your mediator, allowing you to achieve more scalability and performance based on your requirements.

Once the setup is complete, you will have a fully functional DIDComm Mediator running in your AWS account, ready to handle and route DIDComm messages securely and privately.

## Table of Contents

- [Step 1. Prerequisites](#step-1-prerequisites)
- [Step 2. Generate DIDs and Secrets](#step-2-generate-dids-and-secrets)
- [Step 3. Launch from Marketplace](#step-3-launch-from-marketplace)
- [Step 4. Set up CloudFormation](#step-4-set-up-cloudformation)
    - [4.1. Specify Stack Details](#41-specify-stack-details)
    - [4.2. Select IAM Role & Deploy](#42-select-iam-role--deploy)
- [Step 5. Configure Mediator Secrets](#step-5-configure-mediator-secrets)
    - [5.1. Mediator DID Secrets](#51-mediator-did-secrets)
    - [5.2. Medaitor JWT Secret](#52-mediator-jwt-secret)
- [Step 6. Test Mediator Connection](#step-6-test-mediator-connection)
    - [6.1. Set up Environment](#61-set-up-environment)
    - [6.2. Set up the Mediator Instance](#62-set-up-the-mediator-instance)
    - [6.3. Send Ping to Mediator](#63-send-ping-to-mediator)

---

## Step 1. Prerequisites

- An active AWS account with permissions to create CloudFormation stack, Secrets Manager entries, and ECS resources.
- A Hosted Zone in AWS Route53 for your base domain name to host the mediator instance.
- The DID secrets containing the private key associated with the DID and JWT secret to securely store in AWS Secrets Manager during deployment.

## Step 2. Generate DIDs and Secrets

To configure and successfully deploy the DIDComm Mediator from the AWS Marketplace, you have to generate the `did:web`, along with the corresponding DID and JWT secrets for the mediator instance and the `did:peer` of the mediator admin user. 

> This step requires Rust (1.85.0 2024 Edition) to be installed on your machine. If you haven't installed it yet, please follow the [installation guide](https://www.rust-lang.org/tools/install).

Follow the steps below to generate these using our open-sourced mediator project:


1. Clone the [GitHub repo](https://github.com/affinidi/affinidi-tdk-rs) on your local.

```bash
git clone git@github.com:affinidi/affinidi-tdk-rs.git
```

2. Navigate to the `crates/affinidi-messaging` folder. 

```bash
cd affinidi-tdk-rs/crates/affinidi-messaging
```

3. Run the `generate_mediator_config` script to generate the DIDs and secrets. 

```bash
cargo run --bin generate_mediator_config -- --host <HOST_DOMAIN_NAME>
```

> Replace `<HOST_DOMAIN_NAME>` with the full domain name where you'll host the mediator instance, e.g., `mediator.goodcompany.com`.

We will need the JSON-encoded `DID secret` and `JWT secret` at a later stage of deployment.

## Step 3. Launch from Marketplace

To set up and host your own DIDComm Mediator from your AWS account, subscribe to the AWS Marketplace listing of Affinidi:

1. Go to AWS Marketplace.

2. Search and click DIDComm Mediator.

3. Click **View Purchase Options** to review details.

4. Click the **Launch your software** button to initiate the setup.

> The AWS Marketplace DIDComm Mediator setup is available for free. **The AWS infrastructure costs of running the server apply.**

5. Select the region in which you want to deploy the DIDComm Mediator server.

> Currently available only in the Asia Pacific (Singapore) region. 
*Stay tuned as we expand support for other regions for deployment.*

6. Click on the **Launch with CloudFormation** button to configure and create the stack.

## Step 4. Set up CloudFormation

On the Create stack page for CloudFormation, you can view the **Infrastructure Composer** to adjust some settings. We recommend keeping the default values to get started.

Click on the **Next** button to continue the setup.

### 4.1 Specify Stack Details

In the stack details section, you can specify the stack name to easily identify its purpose. Additionally, set up the required parameters to be configured and create the DIDComm Mediator instance.

At this stage, you must create a Hosted Zone in AWS for the `HostBaseDomainName` you will use to host the DIDComm Mediator server. Refer to this [AWS documentation](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/hosted-zones-working-with.html) for more details about Hosted Zone setup.


|  Field    | Description    |
| -------- | --------------- |
| AWSMarketplaceAMI | AWS Marketplace requires the Marketplace AMI. This dummy AMI will not be launched when setting up the mediator. |
| AWSMediatorImage | The Docker image of the mediator. We recommend using the default version. |
| HostBaseDomainName | The base domain name where the mediator will be hosted (e.g., `goodcompany.com`). The setup requires configuring the hosted zone of this base domain name on your AWS account. |
| HostSubdomainName | The subdomain name where the mediator will be hosted (e.g., mediator). The value will be concatenated to the `HostBaseDomainName` during setup (e.g., `mediator.goodcompany.com`). |
| HostedZoneID | The hosted zone ID of the base domain name. The hosted zone for the base domain name must be created on your AWS account. The Hosted Zone ID looks like this: `Z03677621X7HFOMLQK20J`. |
| MediatorAdminDID | The Decentralised Identifier (DID) of the administrator for the mediator. The administrator must use the did:peer method (e.g., `did:peer:2.Vz6MkwXy...`). |
| MediatorDID | The Decentralised Identifier (DID) for the mediator. The value is stored in the parameter store and can be updated later. The mediator DID must use the did:web method (e.g., `did:web:mediator.goodcompany.com`). |
| MediatorDIDDoc | The corresponding DID document of the mediator DID. The value is stored in the parameter store and must be updated if the mediator DID changed. Refer to the documentation for the sample DID Document. |


**Sample mediator DID document**

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1"
  ],
  "assertionMethod": [
    "did:web:mediator.goodcompany.com#key-1",
    "did:web:mediator.goodcompany.com#key-2"
  ],
  "authentication": [
    .....
  ],
  "id": "did:web:mediator.goodcompany.com",
  "keyAgreement": [
    .....
  ],
  "service": [
    {
      "id": "did:web:mediator.goodcompany.com#service",
      "serviceEndpoint": [
        {
          "accept": [
            "didcomm/v2"
          ],
          "routingKeys": [],
          "uri": "https://mediator.goodcompany.com"
        },
        {
          "accept": [
            "didcomm/v2"
          ],
          "routingKeys": [],
          "uri": "wss://mediator.goodcompany.com/ws"
        }
      ],
      "type": "DIDCommMessaging"
    },
    {
      "id": "did:web:mediator.goodcompany.com#auth",
      "serviceEndpoint": "https://mediator.goodcompany.com/authenticate",
      "type": "Authentication"
    }
  ],
  "verificationMethod": [
    {
      "controller": "did:web:mediator.goodcompany.com",
      "id": "did:web:mediator.goodcompany.com#key-1",
      "publicKeyJwk": {
        "crv": "P-256",
        "kty": "EC",
        "x": "t_urdyvDKJLgYxJMrV6u0...",
        "y": "DWciV1aBxqHXH2jW..."
      },
      "type": "JsonWebKey2020"
    },
    .....
  ]
}
```

### 4.2 Select IAM Role & Deploy

After setting up the required parameters, click the Next button to finalise the CloudFormation template. On this page, you must select the **CDK IAM Role** that can be used by the CloudFormation to create the stack. 

Check on the acknowledgement section and then, click on Next button.

The last page shows you all the setting you have configured for final review. Once you are done with the review, click on the Submit button to start the deployment.

## Step 5. Configure Mediator Secrets

The mediator requires the setup of AWS Secrets Manager to enable it to successfully process messages forwarded to the server by the sender and route them securely to the recipient.

During deployment, CloudFormation automatically generates the following secret names in the AWS Secrets Manager:
- `mediator/atn/atm/mediator/global/secrets/dev`
- `mediator/atn/atm/mediator/global/jwt_secret/dev`

Paste the value for DID and JWT secret in the AWS Secrets Manager record as plaintext.


### 5.1 Mediator DID Secrets

Copy the mediator's JSON-encoded DID document secret generated in [Step 2](#step-2-generate-dids-and-secrets) as the value of `mediator/atn/atm/mediator/global/secrets/dev`.

The DID secret contains the private key information of the mediator DID to decrypting and verifying messages addressed to the mediator.

**Sample DID Secret:**

```json
[
  {
    "id": "did:web:mediator.goodcompany.com#key-1",
    "privateKeyJwk": {
      "crv": "P-256",
      "d": "soi0RdleEYyzCX...",
      "kty": "EC",
      "x": "t_urdyvDKJLgYxJM...",
      "y": "DWciV1aBxqHXH2..."
    },
    "type": "JsonWebKey2020"
  },
  {
    "id": "did:web:mediator.goodcompany.com#key-2",
    "privateKeyJwk": {
      "crv": "Ed25519",
      "d": "qjRq7akRjv22RSus...",
      "kty": "OKP",
      "x": "tuJadwaoBEb7vTD..."
    },
    "type": "JsonWebKey2020"
  },
  {
    "id": "did:web:mediator.goodcompany.com#key-3",
    "privateKeyJwk": {
      "crv": "secp256k1",
      "d": "5GIxIbn03X_...",
      "kty": "EC",
      "x": "mrR3O-sqRKsuJ9q...",
      "y": "CJy9Ss70LW2..."
    },
    "type": "JsonWebKey2020"
  },
  {
    "id": "did:web:mediator.goodcompany.com#key-4",
    "privateKeyJwk": {
      "crv": "P-256",
      "d": "rT2pIZMaOIF2HebA...",
      "kty": "EC",
      "x": "DlDk3EALp_kZl-...",
      "y": "AH9aYsXlTJ8Qi2..."
    },
    "type": "JsonWebKey2020"
  }
]
```

### 5.2 Mediator JWT Secret

Copy the mediator's JWT secret generated in [Step 2](#step-2-generate-dids-and-secrets) as the value of `mediator/atn/atm/mediator/global/jwt_secret/dev`.

**Sample JWT Secret**
```bash
MFECAQEwBQYDK2VwBCIEIN_YPGCcfxWJAJ1bKp91GsQbfZuDr737ARJ65lmyAbMDgSEA1n9cHIy4Ivu55FVfph4t0...
```

## Step 6. Test Mediator Connection

After deployment, you can verify the mediator by opening `https://<HOST_DOMAIN_NAME>/.well-known/did.json` in your web browser. This page should display the mediator's DID document.

To test your instance using the Rust SDK, go through the following steps.

### 6.1. Set up Environment

1. Install Rust (1.85.0 2024 Edition) on your machine if you haven't installed it yet using [this guide](https://www.rust-lang.org/tools/install).

2. Install Docker on your machine if you haven't installed it yet using [this guide](https://docs.docker.com/desktop/). We will need this to run Redis instance for the mediator to store messages temporarily and mediator configurations.

### 6.2. Set up the Mediator Instance

1. On the same repository cloned earlier from [Step 2](#step-2-generate-dids-and-secrets), navigate to the `crates/affinidi-messaging` folder. 

```bash
cd affinidi-tdk-rs/crates/affinidi-messaging
```

2. Run the Redis Docker container using the command below from your terminal:

```bash
docker run --name=redis-local --publish=6379:6379 --hostname=redis --restart=on-failure --detach redis:latest
```

> The latest supported version of Redis is **version 8.0**.

2. Run `setup_environment` to configure the mediator with all the required information to run locally.

```bash
cargo run --bin setup_environment
```

3. In the on-screen example, it is important to select the **Remote mediator** option and provide the mediator DID generated from the Affinidi Portal.

After entering the mediator DID, the set up will resolve the DID to get the mediator URL to be configured in the environment settings.

4. Skip SSL certificate and Admin account creation.

5. Generate sample users to connect and send messages to the mediator server. The setup will generate 4 users and save them in the `environment.json` file.


### 6.3. Send Ping to Mediator

After setting up the environment, run the ping script to connect, send, and receive messages from the Mediator.

```bash
export RUST_LOG=none,affinidi_messaging_helpers=debug,affinidi_messaging_sdk=debug
cargo run --example mediator_ping
```

The above example will execute a code that authenticates to the mediator and send a ping message to the mediator. If successful, it sends a pong message back.

For more example, refer to the [helpers](../affinidi-messaging-helpers/) folder.
