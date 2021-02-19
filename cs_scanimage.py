import argparse
import docker
import requests
import sys
from enum import Enum
import time
import getpass

registry_url_map = {
    'us-1': 'container-upload.us-1.crowdstrike.com',
    'us-2': 'container-upload.us-2.crowdstrike.com',
    'eu-1': 'container-upload.eu-1.crowdstrike.com',
}
auth_url_map = {
    'us-1': 'https://api.crowdstrike.com',
    'us-2': 'https://api.us-2.crowdstrike.com',
    'eu-1': 'https://api.eu-1.crowdstrike.com',
}

scanreport_endpoint = "/reports?"
param1 = "repository="
param2 = "tag="
auth_url_endpoint = "/oauth2/token"
retry_count = 10
sleep_seconds = 10
vuln_str_key_1 = 'Vulnerabilities'
vuln_str_key_2 = 'Vulnerability'
detect_str_key = 'Detections'
details_str_key = 'Details'
cvss_str_key = 'cvss_v2_score'
sev_str_key = 'severity'


# class to simulate scanning
class ScanImage(Exception):
    """Scanning Image Tasks"""

    type_malware = "malware"
    type_misconfig = 'misconfiguration'
    type_secret = "secret"
    type_cis = "cis"
    severity_high = "high"

    def __init__(self, client_id, client_secret, repo, tag, client, cloud):
        self.client_id = client_id
        self.client_secret = client_secret
        self.repo = repo
        self.tag = tag
        self.client = client
        self.server_domain = registry_url_map[cloud]
        self.auth_url = auth_url_map[cloud] + auth_url_endpoint

    # Step 1: perform docker tag to the registry corresponding to the cloud entered
    def docker_tag(self):
        print("performing docker tag", "repo", self.repo, "tag", self.tag)
        local_tag = self.repo + ":" + self.tag
        url_tag = self.server_domain + "/" + self.repo
        print("tagging " + local_tag + " to " + url_tag + ":" + self.tag)
        dock_api_client = docker.APIClient()
        dock_api_client.tag(local_tag, url_tag, self.tag, force=True)

    # Step 2: login using the credentials supplied
    def docker_login(self):
        print("performing docker login")
        self.client.login(username=self.client_id, password=self.client_secret, registry=self.server_domain)

    # Step 3: perform docker push using the repo and tag supplied
    def docker_push(self):
        print("performing docker push", "repo", self.repo, "tag", self.tag)
        image_str = self.server_domain + "/" + self.repo + ":" + self.tag
        for line in self.client.images.push(image_str, stream=True, decode=True):
            if 'error' in line:
                raise APIError('docker_push ' + line['error'])
            print(line)

    # Step 4: get the api token used for getting the scan report
    def get_api_token(self):
        print("Getting API Token")
        post_url = self.auth_url
        payload = {
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        resp = requests.post(post_url, data=payload, headers=headers)
        if resp.status_code == 200 or resp.status_code == 201:
            return resp.json()["access_token"]
        else:
            raise APIError('POST ' + post_url + ' {}'.format(resp.status_code))

    # Step 5: poll and get scanreport for specified amount of retries
    def get_scanreport(self, token):
        print("Getting Scan Report")
        server_url = "https://" + self.server_domain
        scanreport_url = server_url + scanreport_endpoint
        get_url = scanreport_url + param1 + self.repo + "&" + param2 + self.tag
        count = 0
        while count < retry_count:
            count += 1
            print("retry count", count)
            time.sleep(sleep_seconds)
            resp = requests.get(get_url, auth=BearerAuth(token))
            if resp.status_code != 200:
                print("report not generated yet, retrying ... ")
            else:
                return resp.json()
        print("retries exhausted")
        raise APIError('GET ' + get_url + ' {}'.format(resp.status_code))

    # Step 6: pass the vulnerabilities from scan report,
    # loop through and find high severity vulns
    # return HighVulnerability enum value
    def get_alerts_vuln(self, vulnerabilities):
        print("running get_alerts_vuln")
        vuln_code = 0
        if vulnerabilities is not None:
            for vulnerability in vulnerabilities:
                try:
                    severity = vulnerability[vuln_str_key_2][details_str_key][cvss_str_key][sev_str_key]
                    if severity.lower() == self.severity_high:
                        vuln_code = ScanStatusCode.HighVulnerability.value
                        print("Alert: High severity vulnerability found")
                        break
                except:
                    continue
        return vuln_code

    # Step 7: pass the detections from scan report,
    # loop through and find if detection type is malware
    # return Malware enum value
    def get_alerts_malware(self, detections):
        print("running get_alerts_malware")
        det_code = 0
        if detections is not None:
            for detection in detections:
                try:
                    if detection['Detection']['Type'].lower() == self.type_malware:
                        print("Alert: Malware found")
                        det_code = ScanStatusCode.Malware.value
                        break
                except:
                    continue
        return det_code

    # Step 8: pass the detections from scan report,
    # loop through and find if detection type is secret
    # return Success enum value but print to stderr
    def get_alerts_secrets(self, detections):
        print("running get_alerts_secrets")
        det_code = 0
        if detections is not None:
            for detection in detections:
                try:
                    if detection['Detection']['Type'].lower() == self.type_secret:
                        print >> sys.stderr, "Alert: Leaked secrets detected"
                        det_code = ScanStatusCode.Success.value
                        break
                except:
                    continue
        return det_code

    # Step 9: pass the detections from scan report,
    # loop through and find if detection type is misconfig
    # return Success enum value but print to stderr
    def get_alerts_misconfig(self, detections):
        print("running get_alerts_misconfig")
        det_code = 0
        if detections is not None:
            for detection in detections:
                try:
                    if detection['Detection']['Type'].lower() == self.type_misconfig:
                        print >> sys.stderr, "Alert: Misconfiguration found"
                        det_code = ScanStatusCode.Success.value
                        break
                except:
                    continue
        return det_code


# these statues are returned and bitwise or'ed
class ScanStatusCode(Enum):
    HighVulnerability = 1
    Malware = 2
    Success = 0
    ScriptFailure = 10


# api err generated by setting statuses
class APIError(Exception):
    """An API Error Exception"""

    def __init__(self, status):
        self.status = status

    def __str__(self):
        return "APIError: status={}".format(self.status)


class BearerAuth(requests.auth.AuthBase):
    def __init__(self, token):
        self.token = token

    def __call__(self, r):
        r.headers["authorization"] = "Bearer " + self.token
        return r


def parse_args():
    parser = argparse.ArgumentParser(description='Crowdstrike scan your docker image.')
    required = parser.add_argument_group('required arguments')
    required.add_argument('--clientid', action="store", dest="client_id", help="Falcon OAuth2 API ClientID", required=True)
    required.add_argument('--repo', action="store", dest="repo", help="docker image repository", required=True)
    required.add_argument('--tag', action="store", dest="tag", help="docker image tag", required=True)
    required.add_argument('--cloud', action="store", dest="cloud", required=True,
                          choices=['us-1', 'us-2', 'eu-1'],
                          help="CS cloud name")
    args = parser.parse_args()
    return args.__getattribute__("client_id"), args.__getattribute__("repo"), args.__getattribute__("tag"), args.__getattribute__("cloud")


def main():
    try:
        client_id, repo, tag, cloud = parse_args()
        client = docker.from_env()
        print("Please enter your Falcon OAuth2 API Secret")
        client_secret = getpass.getpass()
        scan_image = ScanImage(client_id, client_secret, repo, tag, client, cloud)
        scan_image.docker_tag()
        scan_image.docker_login()
        scan_image.docker_push()
        token = scan_image.get_api_token()
        scan_report = scan_image.get_scanreport(token)
        vuln_code = scan_image.get_alerts_vuln(scan_report[vuln_str_key_1])
        mal_code = scan_image.get_alerts_malware(scan_report[detect_str_key])
        sec_code = scan_image.get_alerts_secrets(scan_report[detect_str_key])
        mcfg_code = scan_image.get_alerts_misconfig(scan_report[detect_str_key])
        sys.exit(vuln_code | mal_code | sec_code | mcfg_code)
    except APIError as e:
        print("Unable to scan", e)
        sys.exit(ScanStatusCode.ScriptFailure.value)
    except Exception as e:
        print("Unknown error ", e)
        sys.exit(ScanStatusCode.ScriptFailure.value)


if __name__ == "__main__":
    main()
