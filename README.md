> [!WARNING]
> **DEPRECATED**: This repository is deprecated and will no longer receive updates. Please migrate to the new [CrowdStrike FCS Action](https://github.com/CrowdStrike/fcs-action) for future container image scanning needs.

# CrowdStrike Container Image Scan [![Flake8](https://github.com/CrowdStrike/container-image-scan/actions/workflows/linting.yml/badge.svg)](https://github.com/CrowdStrike/container-image-scan/actions/workflows/linting.yml)

This script will scan a container and return response codes indicating pass/fail status.

Specifically, this script:

1. Tags your image using `docker tag` or `podman tag`
2. Authenticates to CrowdStrike using your [OAuth2 API keys](https://falcon.crowdstrike.com/support/api-clients-and-keys)
3. Pushes your image to CrowdStrike for evaluation using `docker push`, after which CrowdStrike performs an Image Scan
4. Parses returned scan report, generating return error codes as needed

All output is sent to stdout/stderr.

## Prerequisites

- Docker or Podman installed and running
- Python3 and pip installed
- CrowdStrike OAuth2 API keys with appropriate permissions (see below)

### OAuth2 API Key Prerequisites

A CrowdStrike [OAuth2 API keys](https://falcon.crowdstrike.com/support/api-clients-and-keys) with the following permissions is required:

| Permission             | Needed scopes      |
| ---------------------- | ------------------ |
| Falcon Container Image | `read` and `write` |

## Installation

Choose ONE of the following installation methods based on your container runtime:

### Option 1: Docker Installation

If you're using Docker:

```shell
pip3 install docker crowdstrike-falconpy retry
```

### Option 2: Podman Installation

If you're using Podman:

```shell
pip3 install podman crowdstrike-falconpy retry
```

#### Important Podman Configuration Notes

1. For ***rootless*** Podman, ensure the podman socket is running:

   ```shell
   systemctl --user start podman.socket
   ```

2. For ***rootful*** Podman, ensure the following:

   ```shell
   # The socket is running
   systemctl start podman.socket
   # Set the container host environment variable
   export CONTAINER_HOST="unix:///var/run/podman/podman.sock"
   ```

### Option 3: Complete Installation

To install support for both Docker and Podman:

> [!NOTE]
> If using Podman, follow the [Podman Configuration Notes](#important-podman-configuration-notes) above after installing the requirements.

```shell
pip3 install -r requirements.txt
```

## Usage

```shell
$ python3 cs_scanimage.py --help
usage: cs_scanimage.py [-h] -u CLIENT_ID -r REPO [-t TAG]
                       [-c {us-1,us-2,eu-1,us-gov-1}] [-s SCORE]
                       [-st {low,medium,high,critical}] [-sm {default,cps}]
                       [--ignore-unfixed ] [--cve-ignore-file FILE]
                       [--json-report REPORT]
                       [--log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}]
                       [-R RETRY_COUNT] [--plugin] [--user-agent USERAGENT]
                       [--skip-push]

optional arguments:
  -h, --help            show this help message and exit
  --json-report REPORT  Export JSON report to specified file
  --log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                        Set the logging level
  --plugin              Prints the report as json to stdout
  --user-agent USERAGENT
                        HTTP User agent to use for API calls
  --skip-push           Skip image push

required arguments:
  -u CLIENT_ID, --clientid CLIENT_ID
                        Falcon OAuth2 API ClientID
  -r REPO, --repo REPO  Container image repository
  -t TAG, --tag TAG     Container image tag
  -c {us-1,us-2,eu-1,us-gov-1}, --cloud-region {us-1,us-2,eu-1,us-gov-1}
                        CrowdStrike cloud region
  -s SCORE, --score_threshold SCORE
                        Vulnerability score threshold
  -st {low,medium,high,critical}, --severity_threshold {low,medium,high,critical}
                        Vulnerability severity threshold (default: low)
  -sm {default,cps}, --severity_mode {default,cps}
                        Vulnerability severity compute mode (default: default)
  --ignore-unfixed
                        Ignore unfixed vulnerabilities
  --cve-ignore-file FILE
                        Path of the file containing CVEs to ignore
  -R RETRY_COUNT, --retry_count RETRY_COUNT
                        Scan report retry count
```

> [!NOTE]
> CrowdStrike Falcon API credentials may be supplied also by the means of environment variables:
>
> `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET`, and `FALCON_CLOUD_REGION`.
>
> Establishing and retrieving API credentials can be performed at <https://falcon.crowdstrike.com/support/api-clients-and-keys>.

## Advanced Configuration

The script provides several options to fine-tune vulnerability filtering:

### Severity Thresholds

Filter vulnerabilities based on severity level:

```shell
python cs_scanimage.py --clientid FALCON_CLIENT_ID --repo <repo> --tag <tag> \
    --severity_threshold high
```

Valid severity thresholds: `low`, `medium`, `high`, `critical` (default: `low`)

### Severity Mode

Choose how severity is determined:

```shell
python cs_scanimage.py --clientid FALCON_CLIENT_ID --repo <repo> --tag <tag> \
    --severity_mode cps
```

Valid severity modes: `default` (cvss v3 score), `cps` (CrowdStrike Priority Score)

### Ignoring Unfixed Vulnerabilities

Filter out vulnerabilities that don't have fixes available:

```shell
python cs_scanimage.py --clientid FALCON_CLIENT_ID --repo <repo> --tag <tag> \
    --ignore-unfixed
```

### CVE Ignore List

Specify a file containing CVEs to ignore:

```shell
python cs_scanimage.py --clientid FALCON_CLIENT_ID --repo <repo> --tag <tag> \
    --cve-ignore-file /path/to/ignore-list.txt
```

Sample ignore file content:
```
# No fix is available for these CVE
CVE-2024-2961
CVE-2024-2962

# Unable to fix missconfigurations on base image
cis-SetUIDBitFoundInImage

# False positive secrets, ignore all
secrets-ignore-all
```

The ignore file should contain one CVE ID per line. Lines starting with # are treated as comments.

### Skip Image Push

For workflows where the image has already been pushed:

```shell
python cs_scanimage.py --clientid FALCON_CLIENT_ID --repo <repo> --tag <tag> \
    --skip-push
```

This is useful in CI/CD pipelines where the image push step is handled separately.

## Example Scans

### Example 1

```shell
python cs_scanimage.py --clientid FALCON_CLIENT_ID --repo <repo> --tag <tag> --cloud-region <cloud_region>

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

### Example 2

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
python cs_scanimage.py --clientid FALCON_CLIENT_ID --repo <repo> --tag <tag> \
    --cloud-region <cloud_region> -s 1500

```

## Running the Scan using CICD

- You can use the [container-image-scan](https://github.com/marketplace/actions/crowdstrike-container-image-scan) GitHub Action in your GitHub workflows. Checkout the action at [https://github.com/marketplace/actions/crowdstrike-container-image-scan](https://github.com/marketplace/actions/crowdstrike-container-image-scan)

- Pipeline examples, including the GitHub Action, can be found at the CrowdStrike [image-scan-example](https://github.com/CrowdStrike/image-scan-example) repository.

## Using the `container-image-scan` Container

```shell
export FALCON_CLIENT_ID=<client_id>
export FALCON_CLIENT_SECRET=<client_secret>

docker run -it --rm -e FALCON_CLIENT_ID -e FALCON_CLIENT_SECRET \
    -v /var/run/docker.sock:/var/run/docker.sock \
    quay.io/crowdstrike/container-image-scan:latest --repo <repo> --tag <tag>
```

You can use any argument that is supported by the script. For example, to set the cloud region:

```shell
docker run -it --rm -e FALCON_CLIENT_ID -e FALCON_CLIENT_SECRET \
    -v /var/run/docker.sock:/var/run/docker.sock \
    quay.io/crowdstrike/container-image-scan:latest --repo <repo> --tag <tag> -c us-2
```
You can mount an ignore file to the container to ignore specific CVEs:

```shell
docker run -it --rm -e FALCON_CLIENT_ID -e FALCON_CLIENT_SECRET \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v ./.ignore-cve:/ignore  \
    quay.io/crowdstrike/container-image-scan:latest --repo <repo> --tag <tag> --cve-ignore-file /ignore

```

## Exit Codes and Failure Reasons

The script exits with specific codes to indicate the result of the scan. These codes can be used in CI/CD pipelines to determine the cause of a failure:

| Exit Code | Reason                                      | Description                                                                 |
|-----------|---------------------------------------------|-----------------------------------------------------------------------------|
| 0         | Success                                     | No critical issues found; scan passed.                                       |
| 1         | VulnerabilityScoreExceeded                  | The vulnerability score threshold was exceeded.                              |
| 2         | Malware                                     | Malware was detected in the container image.                                 |
| 3         | Secrets                                     | Leaked secrets were detected in the container image.                         |
| 4         | Misconfig                                   | Misconfigurations or CIS issues were found (treated as non-blocking by default). |
| 10        | ScriptFailure                               | A script or API error occurred, or scan report retries were exhausted.        |

You can use these exit codes in your CI/CD pipeline to take appropriate actions based on the scan results.

The `echo $?` command can be utilized to review the return code, e.g:

```shell
echo $?
1
```
