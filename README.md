# CrowdStrike Container Image Scan [![Flake8](https://github.com/CrowdStrike/container-image-scan/actions/workflows/linting.yml/badge.svg)](https://github.com/CrowdStrike/container-image-scan/actions/workflows/linting.yml)

This script will scan a container and return response codes indicating pass/fail status.

Specifically, this script:

1. Tags your image using `docker tag` or `podman tag`
2. Authenticates to CrowdStrike using your [OAuth2 API keys](https://falcon.crowdstrike.com/support/api-clients-and-keys)
3. Pushes your image to CrowdStrike for evaluation using `docker push`, after which CrowdStrike performs an Image Scan
4. Parses returned scan report, generating return error codes as needed

All output is sent to stdout/stderr.

## Prerequisites

This sample/demo script requires the [Docker Engine API python library](https://pypi.org/project/docker/) or the [Bindings for Podman RESTful API](https://pypi.org/project/podman/) and the [FalconPy SDK](https://github.com/CrowdStrike/falconpy). These can be installed via `pip`:

### OAuth2 API Key Prerequisites

A CrowdStrike [OAuth2 API keys](https://falcon.crowdstrike.com/support/api-clients-and-keys) with the following permissions is required:

| Permission             | Needed scopes      |
| ---------------------- | ------------------ |
| Falcon Container Image | `read` and `write` |

### Docker Python Prerequisites

```shell
$ pip3 install docker crowdstrike-falconpy
```

### Podman Python Prerequisites

```shell
$ pip3 install podman crowdstrike-falconpy
```

Once the Podman python dependencies are installed, configure the URI path for the service.

```shell
$ export CONTAINER_HOST="unix:///var/run/podman/podman.sock"
```

## Usage

```shell
$ python3 cs_scanimage.py --help
usage: cs_scanimage.py [-h] -u CLIENT_ID -r REPO [-t TAG]
                       [-c {us-1,us-2,eu-1}] [--json-report REPORT]
                       [--log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}]
                       [ -R RETRY_COUNT ]

Crowdstrike - scan your container image.

optional arguments:
  -h, --help            show this help message and exit
  --json-report REPORT  Export JSON report to specified file
  --log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                        Set the logging level
  -s SCORE --score_threshold
                        Vulnerability score threshold default 500
  -R RETRY_COUNT --retry_count
                        Retry fetching scan report default 10

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
INFO    Downloading Image Scan Report
INFO    Searching for vulnerabilities in scan report...
INFO    Searching for leaked secrets in scan report...
INFO    Searching for malware in scan report...
INFO    Searching for misconfigurations in scan report...
WARNING Alert: Misconfiguration found
INFO    Vulnerability score threshold not met: '0' out of '500'
```

### Example 2:

The script provided was built to score vulnerabilities on a scale show below.

```
critical_score = 2000
high_score = 500
medium_score = 100
low_score = 20
```

The default value to return a non-zero error code for vulnerabilties is one high vulnerabilty. This can be overridden by providing the `-s` parameters to the script.

The example below will accomodate vulnerabilities with a sum of 1500.

```shell
$ python cs_scanimage.py --clientid FALCON_CLIENT_ID --repo <repo> --tag <tag> \
    --cloud-region <cloud_region> -s 1500

```

The `echo $?` command can be utilized to review the return code, e.g:

```shell
echo $?
1
```

The `echo $?` above displays the returned code with the following mappings:

```shell
VulnerabilityScoreExceeded = 1
Malware = 2
Secrets = 3
Success = 0
Misconfig = 0
ScriptFailure = 10
```

## Running the Scan using CICD

- You can use the [container-image-scan](https://github.com/marketplace/actions/crowdstrike-container-image-scan) GitHub Action in your GitHub workflows. Checkout the action at [https://github.com/marketplace/actions/crowdstrike-container-image-scan](https://github.com/marketplace/actions/crowdstrike-container-image-scan)

- Pipeline examples, including the GitHub Action, can be found at the CrowdStrike [image-scan-example](https://github.com/CrowdStrike/image-scan-example) repository.
