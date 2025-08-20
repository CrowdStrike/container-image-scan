#!/usr/bin/env python3
r"""
MM''''''YMM                     dP            oo
M' .mmm. `M                     88
M  MMMMMooM .d8888b. 88d888b. d8888P .d8888b. dP 88d888b. .d8888b. 88d888b.
M  MMMMMMMM 88'  `88 88'  `88   88   88'  `88 88 88'  `88 88ooood8 88'  `88
M. `MMM' .M 88.  .88 88    88   88   88.  .88 88 88    88 88.  ... 88
MM.     .dM `88888P' dP    dP   dP   `88888P8 dP dP    dP `88888P' dP
MMMMMMMMMMM

            M''M
            M  M
            M  M 88d8b.d8b. .d8888b. .d8888b. .d8888b.
            M  M 88'`88'`88 88'  `88 88'  `88 88ooood8
            M  M 88  88  88 88.  .88 88.  .88 88.  ...
            M  M dP  dP  dP `88888P8 `8888P88 `88888P'
            MMMM                          .88
                                       d8888P

                    MP''''''`MM
                    M  mmmmm..M
                    M.      `YM .d8888b. .d8888b. 88d888b.
                    MMMMMMM.  M 88'  `"" 88'  `88 88'  `88
                    M. .MMM'  M 88.  ... 88.  .88 88    88
                    Mb.     .dM `88888P' `88888P8 dP    dP
                    MMMMMMMMMMM

            |)
            |/\_|  |
             \/  \/|/
                  (|

                 __
                / ()  ,_   _           _|   ()_|_  ,_  o |)   _
               |     /  | / \_|  |  |_/ |   /\ |  /  | | |/) |/
                \___/   |/\_/  \/ \/  \/|_//(_)|_/   |/|/| \/|_/
"""
from __future__ import print_function
import argparse
import json
import logging
import sys
from os import environ as env
from enum import Enum
import time
import getpass
from falconpy import FalconContainer, ContainerBaseURL
from tenacity import retry, stop_after_attempt, stop_after_delay


logging.basicConfig(stream=sys.stdout, format="%(levelname)-8s%(message)s")
log = logging.getLogger("cs_scanimage")

VERSION = "2.4.1"


class ScanImage(Exception):
    """Scanning Image Tasks"""

    # pylint:disable=too-many-instance-attributes
    def __init__(
        self, client_id, client_secret, repo, tag, client, runtime, cloud
    ):  # pylint:disable=too-many-positional-arguments
        self.client_id = client_id
        self.client_secret = client_secret
        self.repo = repo
        self.tag = tag
        self.client = client
        self.runtime = runtime
        self.server_domain = ContainerBaseURL[cloud.replace("-", "").upper()].value
        self.auth_config = None

    # Step 1: perform container tag to the registry corresponding to the cloud entered
    def container_tag(self):
        local_tag = "%s:%s" % (self.repo, self.tag)
        url_tag = "%s/%s" % (self.server_domain, self.repo)

        container_image = "".join(
            (
                "".join(img.attrs["RepoTags"])
                for img in self.client.images.list(filters={"reference": local_tag})
            )
        )

        if not container_image:
            log.info("Pulling container image: '%s'", local_tag)
            self.client.images.pull(local_tag)

        log.info("Tagging '%s' to '%s:%s'", local_tag, url_tag, self.tag)
        self.client.images.get(local_tag).tag(url_tag, self.tag, force=True)

    # Step 2: login using the credentials supplied
    def container_login(self):
        log.info("Performing login to CrowdStrike Image Assessment Service")
        if self.runtime == "docker":
            try:
                login = self.client.login(
                    username=self.client_id,
                    password=self.client_secret,
                    registry=self.server_domain,
                    reauth=True,
                )
                log.info(login["Status"])
            except Exception as e:
                log.error("Docker login failed: %s", str(e))
                raise
        else:  # podman
            try:
                auth_config = {
                    "username": self.client_id,
                    "password": self.client_secret,
                }
                response = self.client.login(registry=self.server_domain, **auth_config)
                # Store auth config for subsequent operations
                self.auth_config = auth_config
                log.info(response["Status"])
            except Exception as e:
                log.error("Podman login failed: %s", str(e))
                raise

    # Step 3: perform container push using the repo and tag supplied
    @retry(stop=(stop_after_delay(5) | stop_after_attempt(5)))
    def container_push(self):
        image_str = "%s/%s:%s" % (self.server_domain, self.repo, self.tag)
        log.info("Performing container push to %s", image_str)

        try:
            if self.runtime == "docker":
                image_push = self.client.images.push(
                    image_str, stream=True, decode=True
                )
            else:  # podman
                image_push = self.client.images.push(
                    image_str,
                    stream=True,
                    auth_config=getattr(self, "auth_config", None),
                )

            for line in image_push:
                if isinstance(line, str):
                    line = json.loads(line)

                if "error" in line:
                    raise APIError("container_push " + line["error"])

                if "status" in line and line["status"] == "Pushing":
                    print(
                        "Pushing {}".format(
                            [line.get(key) for key in ["progress", "progressDetails"]]
                        ),
                        end="\r",
                    )
                elif "status" in line:
                    log.info("%s: %s", self.runtime.capitalize(), line["status"])
                else:
                    log.debug(line)
        except Exception as e:
            log.error("Push failed: %s", str(e))
            raise


# Step 4: poll and get scanreport for specified amount of retries
def get_scanreport(
    client_id, client_secret, cloud, user_agent, repo, tag, retry_count
):  # pylint:disable=too-many-positional-arguments
    log.info("Downloading Image Scan Report")
    falcon = FalconContainer(
        client_id=client_id,
        client_secret=client_secret,
        base_url=cloud,
        user_agent=user_agent,
    )

    sleep_seconds = 10
    for count in range(retry_count):
        time.sleep(sleep_seconds)
        log.debug("retry count %s", count)
        resp = falcon.get_assessment(repository=repo, tag=tag)
        if resp["status_code"] != 200:
            log.info(
                "Scan report is not ready yet, retrying in %s seconds",
                sleep_seconds,
            )
        else:
            return ScanReport(resp["body"])
    raise RetryExhaustedError(
        f"Report was not completed after {retry_count} retries. Use -R or --retry_count to increase the number of retries"
    )


class ScanReport(dict):
    """Summary Report of the Image Scan"""

    vuln_str_key_1 = "Vulnerabilities"
    details_str_key = "Details"
    detect_str_key = "Detections"

    severity_high = "high"
    type_malware = "malware"
    type_secret = "secret"  # nosec
    type_misconfig = "misconfiguration"
    type_cis = "cis"

    def status_code(self):
        vuln_code = self.get_alerts_vuln()
        mal_code = self.get_alerts_malware()
        sec_code = self.get_alerts_secrets()
        mcfg_code = self.get_alerts_misconfig()
        return vuln_code | mal_code | sec_code | mcfg_code

    def export(self, filename):
        with open(filename, "w", encoding="utf-8") as f:
            f.write(json.dumps(self, indent=4))

    # Step 5: pass the vulnerabilities from scan report,
    # loop through and find high severity vulns
    # return HighVulnerability enum value
    def get_alerts_vuln(self):
        log.info("Searching for vulnerabilities in scan report...")
        critical_score = 2000
        high_score = 500
        medium_score = 100
        low_score = 20
        vuln_score = 0
        vulnerabilities = self[self.vuln_str_key_1]
        if vulnerabilities is not None:
            for vulnerability in vulnerabilities:
                vuln = vulnerability["Vulnerability"]
                cve = vuln.get("CVEID", "CVE-unknown")
                details = vuln.get("Details")

                if isinstance(details, dict):
                    severity = details.get("severity")
                    if severity is None:
                        cvss_v3 = details.get("cvss_v3_score", {})
                        severity = cvss_v3.get("severity")
                    if severity is None:
                        cvss_v2 = details.get("cvss_v2_score", {})
                        severity = cvss_v2.get("severity", "")
                else:
                    severity = ""

                product = vuln.get("Product", {})
                affects = product.get("PackageSource", product)
                log.warning(
                    "%-8s %-16s Vulnerability detected affecting %s",
                    severity,
                    cve,
                    affects,
                )
                if severity.lower() == "low":
                    vuln_score = vuln_score + low_score
                if severity.lower() == "medium":
                    vuln_score = vuln_score + medium_score
                if severity.lower() == "high":
                    vuln_score = vuln_score + high_score
                if severity.lower() == "critical":
                    vuln_score = vuln_score + critical_score
        return vuln_score

    # Step 6: pass the detections from scan report,
    # loop through and find if detection type is malware
    # return Malware enum value
    def get_alerts_malware(self):
        log.info("Searching for malware in scan report...")
        det_code = 0
        detections = self[self.detect_str_key]
        if detections is not None:
            for detection in detections:
                try:
                    if detection["Detection"]["Type"].lower() == self.type_malware:
                        log.warning("Alert: Malware found")
                        det_code = ScanStatusCode.Malware.value
                        break
                except KeyError:
                    continue
        return det_code

    # Step 7: pass the detections from scan report,
    # loop through and find if detection type is secret
    # return Success enum value
    def get_alerts_secrets(self):
        log.info("Searching for leaked secrets in scan report...")
        det_code = 0
        detections = self[self.detect_str_key]
        if detections is not None:
            for detection in detections:
                try:
                    if detection["Detection"]["Type"].lower() == self.type_secret:
                        log.error("Alert: Leaked secrets detected")
                        det_code = ScanStatusCode.Secrets.value
                        break
                except KeyError:
                    continue
        return det_code

    # Step 8: pass the detections from scan report,
    # loop through and find if detection type is misconfig
    # return Success enum value
    def get_alerts_misconfig(self):
        log.info("Searching for misconfigurations in scan report...")
        det_code = 0
        detections = self[self.detect_str_key]
        if detections is not None:
            for detection in detections:
                try:
                    if detection["Detection"]["Type"].lower() in [
                        self.type_misconfig,
                        self.type_cis,
                    ]:
                        log.warning("Alert: Misconfiguration found")
                        det_code = ScanStatusCode.Success.value
                        break
                except KeyError:
                    continue
        return det_code


# these statues are returned and bitwise or'ed
class ScanStatusCode(Enum):
    Vulnerability = 1
    Malware = 2
    Secrets = 3
    Success = 0
    ScriptFailure = 10


# api err generated by setting statuses


class APIError(Exception):
    """An API Error Exception"""

    def __init__(self, status):
        self.status = status

    def __str__(self):
        return "APIError: status={}".format(self.status)


class RetryExhaustedError(Exception):
    """Raised when get report retries are exhausted"""


# The following class was authored by Russell Heilling
# See https://stackoverflow.com/questions/10551117/setting-options-from-environment-variables-when-using-argparse/10551190#10551190
class EnvDefault(argparse.Action):
    def __init__(self, envvar, required=True, default=None, **kwargs):
        if envvar in env:
            default = env[envvar]
        if required and default:
            required = False
        super(EnvDefault, self).__init__(default=default, required=required, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, values)


# End code authored by Russell Heilling


def parse_args():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    required = parser.add_argument_group("required arguments")
    required.add_argument(
        "-u",
        "--clientid",
        action=EnvDefault,
        dest="client_id",
        envvar="FALCON_CLIENT_ID",
        help="Falcon OAuth2 API ClientID",
    )
    required.add_argument(
        "-r",
        "--repo",
        action=EnvDefault,
        dest="repo",
        envvar="CONTAINER_REPO",
        help="Container image repository",
    )
    required.add_argument(
        "-t",
        "--tag",
        action=EnvDefault,
        dest="tag",
        default="latest",
        envvar="CONTAINER_TAG",
        help="Container image tag",
    )
    required.add_argument(
        "-c",
        "--cloud-region",
        action=EnvDefault,
        dest="cloud",
        envvar="FALCON_CLOUD_REGION",
        default="us-1",
        choices=["us-1", "us-2", "eu-1", "us-gov-1"],
        help="CrowdStrike cloud region",
    )
    required.add_argument(
        "-s",
        "--score_threshold",
        action=EnvDefault,
        dest="score",
        default="500",
        envvar="SCORE",
        help="Vulnerability score threshold",
    )
    parser.add_argument(
        "--json-report",
        action=EnvDefault,
        dest="report",
        envvar="JSON_REPORT",
        default=None,
        required=False,
        help="Export JSON report to specified file",
    )
    parser.add_argument(
        "--log-level",
        action=EnvDefault,
        dest="log_level",
        envvar="LOG_LEVEL",
        default="INFO",
        required=False,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the logging level",
    )
    required.add_argument(
        "-R",
        "--retry_count",
        action=EnvDefault,
        dest="retry_count",
        default="100",
        envvar="RETRY_COUNT",
        type=int,
        help="Scan report retry count",
    )
    parser.add_argument(
        "--plugin",
        action="store_true",
        default=False,
        dest="plugin",
        required=False,
        help="Prints the report as json to stdout",
    )
    parser.add_argument(
        "--user-agent",
        default="container-image-scan",
        type=str,
        dest="useragent",
        help="HTTP User agent to use for API calls. Default is 'container-image-scan'",
    )
    parser.add_argument(
        "--skip-push", default=False, action="store_true", help="Skip image push"
    )

    args = parser.parse_args()
    logging.getLogger().setLevel(args.log_level)

    return (
        args.client_id,
        args.repo,
        args.tag,
        args.cloud,
        args.score,
        args.report,
        args.retry_count,
        args.plugin,
        args.useragent,
        args.skip_push,
    )


def detect_container_runtime():
    """Detect whether Docker or Podman is available and return the appropriate client"""
    try:
        import docker  # pylint:disable=C0415

        try:
            client = docker.from_env()
            client.ping()
            return client, "docker"
        except (docker.errors.APIError, docker.errors.DockerException):
            import podman  # pylint:disable=C0415

            client = podman.from_env()
            try:
                client.ping()
            except (ConnectionRefusedError, podman.errors.exceptions.APIError) as exc:
                raise RuntimeError(
                    "Could not connect to Podman socket. "
                    "If running rootless, ensure your podman.socket is running (systemctl --user start podman.socket). "
                    "If running as root, ensure the CONTAINER_HOST environment variable is set correctly "
                    "(e.g. unix:///var/run/podman/podman.sock)."
                ) from exc
            return client, "podman"
    except ImportError:
        try:
            import podman  # pylint:disable=C0415

            client = podman.from_env()
            try:
                client.ping()
            except (ConnectionRefusedError, podman.errors.exceptions.APIError) as exc:
                raise RuntimeError(
                    "Could not connect to Podman socket. "
                    "If running rootless, ensure your podman.socket is running (systemctl --user start podman.socket). "
                    "If running as root, ensure the CONTAINER_HOST environment variable is set correctly "
                    "(e.g. unix:///var/run/podman/podman.sock)."
                ) from exc
            return client, "podman"
        except ImportError as exc:
            raise RuntimeError(
                "Neither Docker nor Podman client libraries are available"
            ) from exc


def main():  # pylint:disable=R0915

    try:
        (
            client_id,
            repo,
            tag,
            cloud,
            score,
            json_report,
            retry_count,
            plugin,
            useragent,
            skip_push,
        ) = parse_args()
        client_secret = env.get("FALCON_CLIENT_SECRET")
        if client_secret is None:
            print("Please enter your Falcon OAuth2 API Secret")
            client_secret = getpass.getpass()

        client, runtime = detect_container_runtime()
        log.info("Using %s container runtime", runtime)

        if not skip_push:
            useragent = "%s/%s" % (useragent, VERSION)
            scan_image = ScanImage(
                client_id, client_secret, repo, tag, client, runtime, cloud
            )
            scan_image.container_tag()
            scan_image.container_login()
            scan_image.container_push()

        scan_report = get_scanreport(
            client_id, client_secret, cloud, useragent, repo, tag, retry_count
        )

        if plugin:
            print(json.dumps(scan_report, indent=4))
            sys.exit(0)

        if json_report:
            scan_report.export(json_report)
        f_vuln_score = int(scan_report.get_alerts_vuln())
        f_secrets = int(scan_report.get_alerts_secrets())
        f_malware = int(scan_report.get_alerts_malware())
        scan_report.get_alerts_misconfig()

        if f_secrets == ScanStatusCode.Secrets.value:
            log.error("Exiting: Secrets found in container image")
            sys.exit(ScanStatusCode.Secrets.value)
        if f_malware == ScanStatusCode.Malware.value:
            log.error("Exiting: Malware found in container image")
            sys.exit(ScanStatusCode.Malware.value)
        if f_vuln_score >= int(score):
            log.error(
                "Exiting: Vulnerability score threshold exceeded: '%s' out of '%s'",
                f_vuln_score,
                score,
            )
            sys.exit(ScanStatusCode.Vulnerability.value)
        else:
            log.info(
                "Vulnerability score threshold not met: '%s' out of '%s'",
                f_vuln_score,
                score,
            )
            sys.exit(ScanStatusCode.Success.value)

    except APIError:
        log.exception("Unable to scan")
        sys.exit(ScanStatusCode.ScriptFailure.value)
    except RetryExhaustedError:
        log.exception("Retries exhausted")
        sys.exit(ScanStatusCode.ScriptFailure.value)
    except Exception:  # pylint: disable=broad-except
        log.exception("Unknown error")
        sys.exit(ScanStatusCode.ScriptFailure.value)


if __name__ == "__main__":
    main()
