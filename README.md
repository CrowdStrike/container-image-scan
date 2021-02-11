# CI/CD Falcon Tutorial

This script will scan a container and return response codes indicating pass/fail status.

Specifically, this script:
1. Tags your image using ``docker tag``
2. Authenticats to CrowdStrike using your [OAuth2 API keys](https://falcon.crowdstrike.com/support/api-clients-and-keys)
3. Pushes your image to CrowdStrike for evaluation using ``docker push``, afterwhich CrowdStrike performs an Image Scan
4. Parses returned scan report, generating return error codes as needed

All output is sent to stdout/stderr.


## Prerequisites
This sample/demo script requires the [Docker Engine API python library](https://pypi.org/project/docker/) and the [``requests`` HTTP library](https://pypi.org/project/requests/). These can be installed via ``pip``:

```shell
$ sudo easy_install pip
$ pip install docker requests
```

## Usage
```shell
$ python cs_scanimage.py --help

usage: cs_scanimage.py [-h] --user USER --repo REPO --tag TAG
                       --cloud {us-1,us-2,eu-1}

Crowdstrike scan your docker image.

optional arguments:
  -h, --help            show this help message and exit

required arguments:
  --user USER           docker user
  --repo REPO           docker image repository
  --tag TAG             docker image tag
  --cloud {us-1,us-2,eu-1}
                        CS cloud name
```

## Example Scan
This requires your image to exist locally, e.g. run ``docker pull`` prior to executing this script.

```shell
$ python cs_scanimage.py --user <username> --repo <repo> --tag <tag> --cloud <cloud>

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
HighVulnerability | Malware = 3
```
