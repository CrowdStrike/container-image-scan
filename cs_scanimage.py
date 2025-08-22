# !/usr/bin/env python3
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
import argparse
import json
import logging
import sys
import os
from enum import Enum
import time
import getpass
from falconpy import FalconContainer, ContainerBaseURL
from tenacity import retry, wait_fixed, stop_after_attempt, stop_after_delay

logging.basicConfig(stream=sys.stdout, format="%(levelname)-8s%(message)s")
log = logging.getLogger("cs_scanimage")

VERSION = "2.5.0"


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
    def container_tag(self) -> None:
        local_tag = f"{self.repo}:{self.tag}"
        url_tag = f"{self.server_domain}/{self.repo}"

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
    def container_login(self) -> None:
        log.info("Performing login to CrowdStrike Image Assessment Service")
        try:
            auth_config = {
                "username": self.client_id,
                "password": self.client_secret,
            }
            login = self.client.login(
                registry=self.server_domain,
                reauth=self.runtime == "docker",
                **auth_config)
            log.info(login["Status"])
            if self.runtime == "podman":
                self.auth_config = auth_config
        except Exception as e:
            log.error("%s login failed: %s", self.runtime.title(), str(e))
            raise

    # Step 3: perform container push using the repo and tag supplied
    @retry(wait=wait_fixed(5), stop=(stop_after_attempt(5) | stop_after_delay(600)))
    def container_push(self) -> None:
        image_str = f"{self.server_domain}/{self.repo}:{self.tag}"
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
                    log.debug("%s: %s", self.runtime.capitalize(), line["status"])
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

    severity_low = "low"
    severity_medium = "medium"
    severity_high = "high"
    severity_critical = "critical"
    type_malware = "malware"
    type_secret = "secret"  # nosec
    type_misconfig = "misconfiguration"
    type_cis = "cis"

    def export(self, filename):
        with open(filename, "w", encoding="utf-8") as f:
            f.write(json.dumps(self, indent=4))

    # Step 5: pass the vulnerabilities from scan report,
    # loop through and find high severity vulns
    # return HighVulnerability enum value
    def get_alerts_vuln(self, severity_threshold: str, severity_mode: str, ignore_unfixed: bool, cve_ignore_list: []):
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
                ignore_cve_detected = cve.lower() in cve_ignore_list
                ignore_unfixed_detected = ignore_unfixed and not vuln.get("Remediation", [])
                ignore_vuln = ignore_cve_detected or ignore_unfixed_detected
                severity = self.get_severity_score(vuln, severity_mode)
                if not ignore_vuln:
                    if severity == self.severity_low and severity_threshold == self.severity_low:
                        vuln_score += low_score
                    elif severity == self.severity_medium and severity_threshold in [self.severity_low,
                                                                                     self.severity_medium]:
                        vuln_score += medium_score
                    elif severity == self.severity_high and severity_threshold in [self.severity_low,
                                                                                   self.severity_medium,
                                                                                   self.severity_high]:
                        vuln_score += high_score
                    elif severity == self.severity_critical:
                        vuln_score += critical_score
                    else:
                        ignore_vuln = True
                if ignore_vuln:
                    log.info(
                        "%-8s %-16s Vulnerability detected but %s",
                        severity,
                        cve,
                        "ignored (in ignore list)" if ignore_cve_detected else "ignored (unfixed)" if ignore_unfixed_detected else "ignored (severity)"
                    )
                else:
                    details = vuln.get("Details", {})
                    log.warning(
                        "%-8s %-16s Vulnerability detected affecting %s\n        %s",
                        severity,
                        cve,
                        vuln.get("Product", {}).get("PackageSource", vuln.get("Product", {})),
                        details.get("description", "").replace("\n\n", "\n").replace("\n", "\n        "))
        return vuln_score

    def get_severity_score(self, vuln, severity_mode: str):
        severity = ""
        details = vuln.get("Details")
        if isinstance(details, dict):
            if severity_mode == "cps":
                # Use the CPS score to determine severity
                cps_rating = details.get("cps_rating", {})
                if cps_rating:
                    current_rating = cps_rating.get("CurrentRating", {})
                    severity = current_rating.get("Rating", "")
            # severity_mode default
            if not severity:
                cvss_v3 = details.get("cvss_v3_score", {})
                severity = cvss_v3.get("severity")
            if not severity:
                cvss_v2 = details.get("cvss_v2_score", {})
                severity = cvss_v2.get("severity", "")
        return severity.lower() if severity else ""

    # Step 6: pass the detections from scan report
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
                        return ScanStatusCode.Malware.value
                except KeyError:
                    continue
        return ScanStatusCode.Success.value

    # Step 7: pass the detections from scan report,
    # loop through and find if detection type is secret
    # return Success enum value
    def get_alerts_secrets(self, ignore_list: []):
        log.info("Searching for leaked secrets in scan report...")
        detections = self[self.detect_str_key]
        if detections is not None:
            for detection in detections:
                try:
                    if detection["Detection"]["Type"].lower() == self.type_secret:
                        if not "secrets-ignore-all" in ignore_list:
                            log.warning("Alert: Leaked secrets detected")
                            return ScanStatusCode.Secrets.value
                        else:
                            log.info(
                                "Alert: Leaked secrets detected but ignored due to secrets-ignore-all in ignore file")
                        break
                except KeyError:
                    continue
        return ScanStatusCode.Success.value

    # Step 8: pass the detections from scan report,
    # loop through and find if detection type is misconfig
    # return Success enum value
    def get_alerts_misconfig(self, ignore_list: []):
        log.info("Searching for misconfigurations in scan report...")
        detections = self[self.detect_str_key]
        names = []
        if detections is not None:
            for detection in detections:
                try:
                    det = detection["Detection"]
                    type_detection = det["Type"].lower()
                    if type_detection in [
                        self.type_misconfig,
                        self.type_cis,
                    ]:
                        name = det.get("Name", "")
                        if name in names:
                            continue
                        names.append(name)
                        key = f"{type_detection}-{name}"
                        if key.lower() in ignore_list:
                            log.info("Ignoring %s whitelisted on the ignore file", key)
                            continue
                        severity = det.get("Severity", "")
                        description = (det.get("Title", "") + "\n        " + det.get("Description", "")
                                       .replace("\n", "\n        "))
                        log.warning("Misconfiguration %s '%s'\n        %s", severity, key, description)
                        return ScanStatusCode.Misconfig.value
                except KeyError:
                    continue
        return ScanStatusCode.Success.value


# these statues are returned and bitwise or'ed
class ScanStatusCode(Enum):
    Success = 0
    Vulnerability = 1
    Malware = 2
    Secrets = 3
    Misconfig = 4
    ScriptFailure = 10


# api err generated by setting statuses


class APIError(Exception):
    """An API Error Exception"""

    def __init__(self, status):
        self.status = status

    def __str__(self):
        return f"APIError: status={self.status}"


class RetryExhaustedError(Exception):
    """Raised when get report retries are exhausted"""


# The following class was authored by Russell Heilling
# See https://stackoverflow.com/questions/10551117/setting-options-from-environment-variables-when-using-argparse/10551190#10551190
class EnvDefault(argparse.Action):
    def __init__(self, envvar, required=True, default=None, **kwargs):
        if envvar in os.environ:
            default = os.environ[envvar]
        if required and default:
            required = False
        super(EnvDefault, self).__init__(default=default, required=required, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, values)


# End code authored by Russell Heilling


def parse_args() -> argparse.Namespace:
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
        dest="score_threshold",
        default="500",
        envvar="SCORE",
        help="Vulnerability score threshold (default 500)",
    )
    required.add_argument(
        "-st",
        "--severity_threshold",
        action=EnvDefault,
        dest="severity_threshold",
        default="low",
        envvar="SEVERITY_THRESHOLD",
        help="Vulnerability severity threshold (default low)",
    )
    required.add_argument(
        "-sm",
        "--severity_mode",
        action=EnvDefault,
        dest="severity_mode",
        default="default",
        envvar="SEVERITY_MODE",
        help="Vulnerability severity compute mode (default cps)"
    )
    required.add_argument(
        "--ignore-unfixed",
        action="store_true",
        dest="ignore_unfixed",
        default=False,
        help="Ignore unfixed vulnerabilities",
    )
    required.add_argument(
        "--cve-ignore-file",
        action=EnvDefault,
        dest="ignore_file",
        envvar="IGNORE_FILE",
        default=None,
        required=False,
        help="Path of the file containing CVEs to ignore",
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
    if args.severity_threshold.lower() not in [
        "low",
        "medium",
        "high",
        "critical",
    ]:
        raise ValueError(
            "Invalid severity threshold. Must be one of: low, medium, high, critical"
        )
    if args.severity_mode.lower() not in [
        "default",
        "cps",
    ]:
        raise ValueError(
            "Invalid severity mode. Must be one of: [default, cps]"
        )
    return (
        args.client_id,
        args.repo,
        args.tag,
        args.cloud,
        int(args.score_threshold),
        args.severity_threshold.lower(),
        args.severity_mode.lower(),
        args.ignore_unfixed,
        args.ignore_file,
        args.report,
        args.retry_count,
        args.plugin,
        args.useragent,
        args.skip_push,
    )


def detect_container_runtime():
    """Detect whether Docker or Podman is available and return the appropriate client"""
    docker_available = True
    podman_available = True
    try:
        import docker
    except ImportError:
        docker_available = False
    try:
        import podman
    except ImportError:
        podman_available = False

    # Fail early if neither library is available
    if not docker_available and not podman_available:
        raise RuntimeError("Neither Docker nor Podman libraries are available")
    # Try Docker first if available
    if docker_available:
        try:
            client = docker.from_env()
            client.ping()
            return client, "docker"
        except (docker.errors.APIError, docker.errors.DockerException) as exc:
            if not podman_available:
                raise RuntimeError("Could not connect to Docker.") from exc

    # Try Podman if available
    if podman_available:
        try:
            client = podman.from_env()
            client.ping()
            return client, "podman"
        except (ConnectionRefusedError, podman.errors.exceptions.APIError) as exc:
            raise RuntimeError(
                "Could not connect to Docker or Podman socket.\n"
                "About podman: "
                "If running rootless, ensure your podman.socket is running (systemctl --user start podman.socket). "
                "If running as root, ensure the CONTAINER_HOST environment variable is set correctly "
                "(e.g. unix:///var/run/podman/podman.sock)."
            ) from exc

    # If we reach here, something unexpected happened
    raise RuntimeError("Could not connect to Docker or Podman socket.")


def main() -> None:
    try:
        (
            client_id,
            repo,
            tag,
            cloud,
            score_threshold,
            severity_threshold,
            severity_mode,
            ignore_unfixed,
            ignore_file,
            json_report,
            retry_count,
            plugin,
            useragent,
            skip_push,
        ) = parse_args()
        client_secret = os.environ.get("FALCON_CLIENT_SECRET") or getpass.getpass("Enter Falcon OAuth2 API Secret: ")
        client, runtime = detect_container_runtime()
        log.info("Using %s container runtime", runtime)
        ignore_list = []
        if ignore_file and os.path.exists(ignore_file):
            log.debug("Cve ignore file found %s", ignore_file)
            with open(ignore_file, "r", encoding="utf-8") as f:
                ignore_list = [
                    line.strip().lower() for line in f if line.strip() and not line.lstrip().startswith("#")
                ]
        elif ignore_file:
            log.warning("Cve ignore file not found %s", ignore_file)
        if not skip_push:
            useragent = f"{useragent}/{VERSION}"
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

        f_vuln_score = int(scan_report.get_alerts_vuln(severity_threshold, severity_mode, ignore_unfixed, ignore_list))
        f_secrets = int(scan_report.get_alerts_secrets(ignore_list))
        f_malware = int(scan_report.get_alerts_malware())
        f_misconfig = scan_report.get_alerts_misconfig(ignore_list)

        if f_vuln_score >= score_threshold:
            log.error(
                "Exiting %s: Vulnerability score threshold exceeded: '%s' out of '%s'",
                ScanStatusCode.Vulnerability.value,
                f_vuln_score,
                score_threshold,
            )
            sys.exit(ScanStatusCode.Vulnerability.value)
        elif f_vuln_score > 0:
            log.info(
                "Vulnerability score threshold not met: '%s' out of '%s'",
                f_vuln_score,
                score_threshold,
            )
        if f_malware == ScanStatusCode.Malware.value:
            log.error("Exiting %s: Malware found in container image", f_malware)
            sys.exit(ScanStatusCode.Malware.value)
        if f_secrets == ScanStatusCode.Secrets.value:
            log.error("Exiting %s: Secrets found in container image", f_secrets)
            sys.exit(ScanStatusCode.Secrets.value)
        if f_misconfig == ScanStatusCode.Misconfig.value:
            log.error("Exiting %s: Misconfig found in container image", f_misconfig)
            sys.exit(ScanStatusCode.Misconfig.value)

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
