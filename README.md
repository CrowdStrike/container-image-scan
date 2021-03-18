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

required arguments:
  -u CLIENT_ID, --clientid CLIENT_ID
                        Falcon OAuth2 API ClientID
  -r REPO, --repo REPO  Container image repository
  -t TAG, --tag TAG     Container image tag
  -c {us-1,us-2,eu-1}, --cloud-region {us-1,us-2,eu-1}
                        CrowdStrike cloud region
```

Note that CrowdStrike Falcon OAuth2 credentials may be supplied also by the means of environment variables: FALCON_CLIENT_ID, FALCON_CLIENT_SECRET, and FALCON_CLOUD_REGION. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.

## Example Scan
This requires your image to exist locally, e.g. run ``docker pull`` prior to executing this script.

```shell
$ python cs_scanimage.py --clientid FALCON_CLIENT_ID --repo <repo> --tag <tag> --cloud-region <cloud_regsion>

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

The ```echo $?``` command can be utilized to review the return code, e.g:
```shell 
echo $?
1
```

The ```echo $?``` above displays the returned code with the following mappings:
```shell
HighVulnerability = 1
Malware = 2
Success = 0
Secrets = 0
Misconfig = 0
ScriptFailure = 10
HighVulnerability and Malware = 3
```
