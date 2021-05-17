# CrowdStrike Container Image Scan [![Flake8](https://github.com/CrowdStrike/container-image-scan/actions/workflows/linting.yml/badge.svg)](https://github.com/CrowdStrike/container-image-scan/actions/workflows/linting.yml)

This script will scan a container and return response codes indicating pass/fail status.

Specifically, this script:
1. Tags your image using ``docker tag``
2. Authenticates to CrowdStrike using your [OAuth2 API keys](https://falcon.crowdstrike.com/support/api-clients-and-keys)
3. Pushes your image to CrowdStrike for evaluation using ``docker push``, after which CrowdStrike performs an Image Scan
4. Parses returned scan report, generating return error codes as needed

All output is sent to stdout/stderr.


## Prerequisites
This sample/demo script requires the [Docker Engine API python library](https://pypi.org/project/docker/) and the [``requests`` HTTP library](https://pypi.org/project/requests/). These can be installed via ``pip``:

```shell
$ pip3 install docker requests
```

## Usage
```shell
$ python3 cs_scanimage.py --help
usage: cs_scanimage.py [-h] -u CLIENT_ID -r REPO [-t TAG]
                       [-c {us-1,us-2,eu-1}] [--json-report REPORT]
                       [--log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}]

Crowdstrike - scan your container image.

optional arguments:
  -h, --help            show this help message and exit
  --json-report REPORT  Export JSON report to specified file
  --log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                        Set the logging level
  -s SCORE --score_threshold
                        Vulnerability score threshold default 200

required arguments:
  -u CLIENT_ID, --clientid CLIENT_ID
                        Falcon OAuth2 API ClientID
  -r REPO, --repo REPO  Container image repository
  -t TAG, --tag TAG     Container image tag
  -c {us-1,us-2,eu-1}, --cloud-region {us-1,us-2,eu-1}
                        CrowdStrike cloud region
```

Note that CrowdStrike Falcon OAuth2 credentials may be supplied also by the means of environment variables: FALCON_CLIENT_ID, FALCON_CLIENT_SECRET, and FALCON_CLOUD_REGION. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.

FALCON_CLIENT_ID and FALCON_CLIENT_SECRET can be set via environment variables for automation.

## Example Scans

### Example 1:

```shell
$ python cs_scanimage.py --clientid FALCON_CLIENT_ID --repo <repo> --tag <tag> --cloud-region <cloud_region>

please enter password to login
Password:
```

The command above will return output similar to:

```shell
running get_alerts_vuln
Alert: High severity vulnerability found
running get_alerts_malware
running get_alerts_malware
Leaked secrets detected
running get_alerts_malware
Alert: Misconfiguration found
```

### Example 2:

The script provided was built to score vulnerabilities on a scale show below.
```
critical_score = 1000
high_score = 200
medium_score = 100
low_score = 50
```

The default value to return a non-zero error code for vulnerabilties is one high vulnerabilty. This can be overridden by providing the `-s` parameters to the script.

The example below will accomodate vulnerabilities with a sum of `1500`.

```shell
$ python cs_scanimage.py --clientid FALCON_CLIENT_ID --repo <repo> --tag <tag> \
    --cloud-region <cloud_region> -s 1500

```

The ```echo $?``` command can be utilized to review the return code, e.g:
```shell 
echo $?
1
```

The ```echo $?``` above displays the returned code with the following mappings:
```shell
VulnerabilityScoreExceeded = 1
Malware = 2
Secrets = 3
Success = 0
Misconfig = 0
ScriptFailure = 10
```

## Running the Scan using CICD

1. You can use the [container-image-scan](https://github.com/marketplace/actions/crowdstrike-container-image-scan) GitHub Action in your GitHub workflows. Checkout the action at [https://github.com/marketplace/actions/crowdstrike-container-image-scan](https://github.com/marketplace/actions/crowdstrike-container-image-scan)
2. You can run the scan as part of your Jenkins pipeline builds.
   - Requirements:
     - Jenkins must be able to run Docker commands and connect to the Docker socket
     - python3 and pip3 must be installed
   Sample Jenkins pipeline script with configuration options as Jenkins Secrets:
   ```
    pipeline {
        agent any
        environment {
            FALCON_CLIENT_ID     = credentials('FALCON_CLIENT_ID')
            FALCON_CLIENT_SECRET = credentials('FALCON_CLIENT_SECRET')
            FALCON_CLOUD_REGION  = credentials('FALCON_CLOUD_REGION')
            CONTAINER_REPO       = credentials('CONTAINER_REPO')
            CONTAINER_TAG        = credentials('CONTAINER_TAG')
        }
        stages {
            stage('Container Image Scan') {
                steps {
                    sh '''
                    if [ ! -d container-image-scan ] ; then
                        git clone https://github.com/crowdstrike/container-image-scan
                    fi
                    pip3 install docker-py
                    python3 container-image-scan/cs_scanimage.py
                    '''
                }
            }
        }
    }
   ```
   Sample Jenkins pipeline script with only `FALCON_CLIENT_SECRET` as a Jenkins Secret:
   ```
    pipeline {
        agent any
        environment {
            FALCON_CLIENT_SECRET = credentials('FALCON_CLIENT_SECRET')
        }
        stages {
            stage('Container Image Scan') {
                steps {
                    sh '''
                    if [ ! -d container-image-scan ] ; then
                        git clone https://github.com/crowdstrike/container-image-scan
                    fi
                    pip3 install docker-py
                    python3 container-image-scan/cs_scanimage.py -u <your_falcon_client_id> -r docker.io/busybox -t latest -c us-1
                    '''
                }
            }
        }
    }
   ```