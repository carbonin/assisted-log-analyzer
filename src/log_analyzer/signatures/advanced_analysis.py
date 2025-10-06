"""
Advanced analysis signatures for OpenShift Assisted Installer logs.
These signatures perform complex analysis across multiple log sources.
"""
import json
import logging
import os
import re
from collections import OrderedDict
from typing import Optional, List, Dict, Any, Callable

import yaml

from .base import Signature, SignatureResult
from log_analyzer.log_analyzer import NEW_LOG_BUNDLE_PATH, OLD_LOG_BUNDLE_PATH


def operator_statuses_from_controller_logs(controller_log: str, include_empty: bool = False):
    operator_regex = re.compile(r"Operator ([a-z\-]+), statuses: \[(.*)\].*")
    conditions_regex = re.compile(r"\{(.+?)\}")
    condition_regex = re.compile(
        r"([A-Za-z]+) (False|True) ([0-9a-zA-Z\-]+ [0-9a-zA-Z\:]+ [0-9a-zA-Z\-\+]+ [A-Z]+) (.*)"
    )
    operator_statuses = {}

    for operator_name, operator_status in operator_regex.findall(controller_log):
        if include_empty:
            operator_statuses[operator_name] = {}
        operator_conditions = operator_statuses.setdefault(operator_name, {})
        for operator_conditions_raw in conditions_regex.findall(operator_status):
            for (
                condition_name,
                condition_result,
                condition_timestamp,
                condition_reason,
            ) in condition_regex.findall(operator_conditions_raw):
                operator_conditions[condition_name] = {
                    "result": condition_result == "True",
                    "timestamp": condition_timestamp,
                    "reason": condition_reason,
                }

    return operator_statuses


def condition_has_result(operator_conditions, expected_condition_name: str, expected_condition_result: bool) -> bool:
    return any(
        condition_values["result"] == expected_condition_result
        for condition_name, condition_values in operator_conditions.items()
        if condition_name == expected_condition_name
    )


def filter_operators(operator_statuses, required_conditions, aggregation_function: Callable[[list], bool]):
    return {
        operator_name: operator_conditions
        for operator_name, operator_conditions in operator_statuses.items()
        if aggregation_function(
            condition_has_result(operator_conditions, required_condition_name, expected_condition_result)
            for required_condition_name, expected_condition_result in required_conditions
        )
    }

logger = logging.getLogger(__name__)

class EventsInstallationAttempts(Signature):
    """Inspects events file to check for multiple installation attempts."""

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        """Analyze multiple installation attempts."""
        try:
            metadata = log_analyzer.metadata
            cluster = metadata["cluster"]

            # Get all cluster events and partition them by reset events
            all_events = log_analyzer.get_all_cluster_events()
            partitions = log_analyzer.partition_cluster_events(all_events)
            installation_attempts = len(partitions)

            if installation_attempts != 1:
                current_events = log_analyzer.get_last_install_cluster_events()
                if current_events:
                    last_attempt_first_event = current_events[0]
                    content = (
                        f"The events file for this cluster contains events from {installation_attempts} installation attempts.\n"
                        f"When reading the events for this ticket, make sure you look only at the events for the last installation attempt,\n"
                        f"the first event in that attempt happened around {last_attempt_first_event['event_time']}."
                    )

                    return SignatureResult(
                        signature_name=self.name,
                        title="Multiple Installation Attempts in Events File",
                        content=content,
                        severity="warning"
                    )

        except Exception as e:
            logger.error(f"Error in EventsInstallationAttempts: {e}")

        return None


class MissingMustGatherLogs(Signature):
    """Checks if must-gather logs are missing when they should be collected."""

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        """Analyze for missing must-gather logs."""
        try:
            metadata = log_analyzer.metadata
            cluster_hosts = metadata["cluster"]["hosts"]
            bootstrap_node = [host for host in cluster_hosts if host.get("bootstrap", False)]

            if not bootstrap_node:
                return None

            bootstrap_node = bootstrap_node[0]

            eligible_bootstrap_stages = ["Rebooting", "Configuring", "Joined", "Done"]
            if len(cluster_hosts) <= 1:
                # In SNO when the bootstrap node goes to reboot the controller is still not running
                eligible_bootstrap_stages.remove("Rebooting")

            if bootstrap_node["progress"]["current_stage"] not in eligible_bootstrap_stages:
                return None

            cluster = metadata["cluster"]
            if cluster["logs_info"] in ("timeout", "completed"):
                try:
                    log_analyzer.get_must_gather()
                    return None  # Must-gather exists, no issue
                except FileNotFoundError:
                    content = "This cluster's collected logs are missing must-gather logs although it should be collected, why is it missing?"

                    return SignatureResult(
                        signature_name=self.name,
                        title="Missing Must-Gather Logs",
                        content=content,
                        severity="error"
                    )

        except Exception as e:
            logger.error(f"Error in MissingMustGatherLogs: {e}")

        return None


class FlappingValidations(Signature):
    """Analyzes flapping validation states."""

    validation_name_regexp = re.compile(r"Host .+: validation '(.+)'.+")
    succeed_to_failing_regexp = re.compile(r"Host .+: validation '.+' that used to succeed is now failing")
    now_fixed_regexp = re.compile(r"Host .+: validation '.+' is now fixed")

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        """Analyze flapping validations."""
        try:
            from collections import Counter

            events_by_host = log_analyzer.get_events_by_host()

            host_tables = {}
            for host_id, events in events_by_host.items():
                succeed_to_failing_counter = Counter(
                    self.validation_name_regexp.match(event["message"]).groups()[0]
                    for event in events
                    if self.succeed_to_failing_regexp.match(event["message"])
                )

                now_fixed = Counter(
                    self.validation_name_regexp.match(event["message"]).groups()[0]
                    for event in events
                    if self.now_fixed_regexp.match(event["message"])
                )

                table = [
                    OrderedDict(
                        validation=validation_name,
                        failed=f"This went from succeeding to failing {succeed_to_failing_occurrences} times",
                        fixed=f"This validation was fixed {now_fixed.get(validation_name, 0)} times",
                    )
                    for validation_name, succeed_to_failing_occurrences in succeed_to_failing_counter.items()
                ]

                if table:
                    host_tables[host_id] = self.generate_table(table)

            if host_tables:
                content = "\n".join(f"Host ID {host_id}:\n{table}" for host_id, table in host_tables.items())

                return SignatureResult(
                    signature_name=self.name,
                    title="Flapping Validations",
                    content=content,
                    severity="warning"
                )

        except Exception as e:
            logger.error(f"Error in FlappingValidations: {e}")

        return None

class NodeStatus(Signature):
    """Dump node statuses from installer gather nodes.json."""

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        for base in (NEW_LOG_BUNDLE_PATH, OLD_LOG_BUNDLE_PATH):
            path = f"{base}/resources/nodes.json"
            try:
                nodes_json = log_analyzer.logs_archive.get(path)
            except FileNotFoundError:
                continue
            try:
                nodes = json.loads(nodes_json)
            except json.JSONDecodeError:
                continue
            nodes_table = []
            for node in nodes.get("items", []):
                conds = node.get("status", {}).get("conditions", [])
                def get_by_type(t):
                    c = next((c for c in conds if c.get("type") == t), None)
                    if not c:
                        return "(Condition not found)"
                    return f"Status {c['status']} with reason {c['reason']}, message {c['message']}"
                nodes_table.append(
                    OrderedDict(
                        name=node.get("metadata", {}).get("name"),
                        MemoryPressure=get_by_type("MemoryPressure"),
                        DiskPressure=get_by_type("DiskPressure"),
                        PIDPressure=get_by_type("PIDPressure"),
                        Ready=get_by_type("Ready"),
                    )
                )
            if nodes_table:
                return SignatureResult(
                    signature_name=self.name,
                    title="Collected nodes.json from installer gather",
                    content=self.generate_table(nodes_table),
                    severity="info",
                )
            else:
                return SignatureResult(
                    signature_name=self.name,
                    title="Collected nodes.json from installer gather",
                    content=(
                        "The nodes.json file doesn't have any node resources in it. You should probably check the kubelet logs for the 2 non-bootstrap control-plane hosts"
                    ),
                    severity="warning",
                )
        return None


class ControllerWarnings(Signature):
    """Search for warnings in controller logs."""

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        try:
            controller_logs = log_analyzer.get_controller_logs()
        except FileNotFoundError:
            return None
        warnings = re.findall(r'time=".*" level=warning msg=".*', controller_logs)
        if warnings:
            shown = warnings[:10]
            content = "\n".join(shown)
            if len(warnings) > 10:
                content += f"\nThere are {len(warnings) - 10} additional warnings not shown"
            return SignatureResult(
                signature_name=self.name,
                title="Controller warning logs",
                content=content,
                severity="warning",
            )
        return None


class UserHasLoggedIntoCluster(Signature):
    """Detect user login to cluster nodes during installation."""

    USER_LOGIN_PATTERN = re.compile(r"pam_unix\((sshd|login):session\): session opened for user .+ by")

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        cluster = log_analyzer.metadata.get("cluster", {})
        msgs = []
        for host in cluster.get("hosts", []):
            host_id = host["id"]
            try:
                journal_logs = log_analyzer.get_host_log_file(host_id, "journal.logs")
            except FileNotFoundError:
                continue
            if self.USER_LOGIN_PATTERN.findall(journal_logs):
                msgs.append(
                    f"Host {host_id}: found evidence of a user login during installation. This might indicate that some settings have been changed manually; if incorrect they could contribute to failure."
                )
        if msgs:
            return SignatureResult(
                signature_name=self.name,
                title="User has logged into cluster nodes during installation",
                content="\n".join(msgs),
                severity="warning",
            )
        return None


class FailedRequestTriggersHostTimeout(Signature):
    """Look for failed requests that could have caused host timeout."""

    LOG_PATTERN = re.compile(
        r'time="(?P<time>.+)" level=(?P<severity>[a-z]+) msg="(?P<message>.*api\.openshift\.com/api/assisted-install.*Service Unavailable)" file=.+'
    )
    HOST_TIMED_OUT_STATUS_INFO = "Host failed to install due to timeout while connecting to host"

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        cluster = log_analyzer.metadata.get("cluster", {})
        failed_requests_hosts = set()
        timed_out_hosts = {h["id"] for h in cluster.get("hosts", []) if h.get("status_info") == self.HOST_TIMED_OUT_STATUS_INFO}
        for host in cluster.get("hosts", []):
            try:
                agent_logs = log_analyzer.get_host_log_file(host["id"], "agent.logs")
            except FileNotFoundError:
                continue
            if len(self.LOG_PATTERN.findall(agent_logs)) > 0:
                failed_requests_hosts.add(host["id"])
        intersect = failed_requests_hosts & timed_out_hosts
        if intersect:
            content = "\n".join(
                f"Host {host_id} has request failures and timed out. Did the request cause the host to timeout?" for host_id in sorted(intersect)
            )
            return SignatureResult(
                signature_name=self.name,
                title="Failed request triggering host timeout",
                content=content,
                severity="warning",
            )
        if failed_requests_hosts and timed_out_hosts:
            return SignatureResult(
                signature_name=self.name,
                title="Failed request triggering host timeout",
                content=(
                    f"Cluster has at least one host that failed requests ({', '.join(sorted(failed_requests_hosts))}) and at least one host that timed out ({', '.join(sorted(timed_out_hosts))})"
                ),
                severity="warning",
            )
        return None


class ControllerFailedToStart(Signature):
    """Looks for controller readiness in pods.json when bootstrap is 'Waiting for controller'."""

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        cluster = log_analyzer.metadata.get("cluster", {})
        bootstrap = [h for h in cluster.get("hosts", []) if h.get("bootstrap")] or []
        if not bootstrap:
            return None
        if bootstrap[0]["progress"]["current_stage"] != "Waiting for controller":
            return None
        for base in (NEW_LOG_BUNDLE_PATH, OLD_LOG_BUNDLE_PATH):
            path = f"{base}/resources/pods.json"
            try:
                pods_json = log_analyzer.logs_archive.get(path)
            except FileNotFoundError:
                continue
            try:
                pods = json.loads(pods_json)
                controller_pod = [
                    pod for pod in pods.get("items", []) if pod.get("metadata", {}).get("namespace") == "assisted-installer"
                ][0]
            except Exception:
                continue
            try:
                ready = [
                    condition.get("status") == "True"
                    for condition in controller_pod.get("status", {}).get("conditions", {})
                    if condition.get("type") == "Ready"
                ][0]
            except Exception:
                ready = False
            conditions_tbl = self.generate_table(controller_pod.get("status", {}).get("conditions", []))
            containers_tbl = self.generate_table(controller_pod.get("status", {}).get("containerStatuses", []))
            content = (
                f"The controller pod {'is' if ready else 'is not'} ready.\n"
                f"Conditions:\n{conditions_tbl}\n\nContainer Statuses:\n{containers_tbl}"
            )
            return SignatureResult(
                signature_name=self.name,
                title="Assisted Installer Controller failed to start",
                content=content,
                severity="warning",
            )
        return None


class MachineConfigDaemonErrorExtracting(Signature):
    """Looks for MCD firstboot extraction error (OCPBUGS-5352)."""

    mco_error = re.compile(r"must be empty, pass --confirm to overwrite contents of directory$", re.MULTILINE)

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        for base in (NEW_LOG_BUNDLE_PATH, OLD_LOG_BUNDLE_PATH):
            path = f"{base}/control-plane/*/journals/machine-config-daemon-firstboot.log"
            try:
                mcd_logs = log_analyzer.logs_archive.get(path)
            except FileNotFoundError:
                continue
            if self.mco_error.search(mcd_logs):
                return SignatureResult(
                    signature_name=self.name,
                    title="machine-config-daemon could not extract machine-os-content",
                    content=(
                        "machine-config-daemon-firstboot logs indicate a node may be hitting OCPBUGS-5352"
                    ),
                    severity="warning",
                )
        return None


class BootkubeAttempts(Signature):
    """Counts the number of times bootkube attempted to run."""

    def __init__(self):
        """Initialize the signature."""
        super().__init__()

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        """Analyze bootkube attempts from bootkube.json file."""
        try:
            bootkube_json_path = f"{NEW_LOG_BUNDLE_PATH}/bootstrap/services/bootkube.json"
            
            try:
                bootkube_content = log_analyzer.logs_archive.get(bootkube_json_path)
            except FileNotFoundError:
                return None
            
            # Parse the JSON content
            try:
                bootkube_events = json.loads(bootkube_content)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse bootkube.json: {e}")
                return None
            
            # Count "service start" phases to determine number of attempts
            # Deduplicate by timestamp since there can be multiple entries with the same timestamp
            service_start_timestamps = set()
            for event in bootkube_events:
                if event.get("phase") == "service start":
                    timestamp = event.get("timestamp")
                    if timestamp:
                        service_start_timestamps.add(timestamp)
            
            service_start_count = len(service_start_timestamps)
            
            if service_start_count == 0:
                return None
            
            # Create content with attempt details
            content = f"Bootkube attempted to run {service_start_count} time(s).\n\n"
            
            if service_start_count > 1:
                content += "Multiple bootkube attempts detected. This may indicate:\n"
                content += "- Previous attempts failed and bootkube was restarted\n"
                content += "- System instability during bootstrap process\n"
                content += "- Resource constraints or timing issues\n\n"
                content += "Review the bootkube.json file for detailed attempt information and failure reasons."
                severity = "warning"
            else:
                content += "Single bootkube attempt detected."
                severity = "info"
            
            return SignatureResult(
                signature_name=self.name,
                title="Bootkube Attempts Analysis",
                content=content,
                severity=severity
            )
            
        except Exception as e:
            logger.error(f"Error in BootkubeAttempts: {e}", exc_info=True)
            return None


class ContainerCrashAnalysis(Signature):
    """Analyzes container crashes in the last 30 minutes of the install from kubelet logs."""

    def __init__(self):
        """Initialize the signature."""
        super().__init__()

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        """Analyze container crashes from kubelet logs in control plane nodes."""
        try:
            from collections import defaultdict
            from datetime import datetime, timedelta
            import dateutil.parser

            logger.debug("Starting ContainerCrashAnalysis")

            # Pattern to match container crash errors in kubelet logs
            crash_pattern = re.compile(
                r'(\w{3} \d{1,2} \d{2}:\d{2}:\d{2}) .* "Error syncing pod, skipping" err="failed to \\"StartContainer\\" for \\"([^"]+)\\" with CrashLoopBackOff'
            )

            container_crashes = defaultdict(int)
            host_container_crashes = defaultdict(lambda: defaultdict(int))
            crash_details = []

            try:
                # Get control-plane directory
                control_plane_dir = log_analyzer.logs_archive.get(f"{NEW_LOG_BUNDLE_PATH}/control-plane/")
                logger.debug(f"Found control-plane directory: {NEW_LOG_BUNDLE_PATH}/control-plane/")
                
                # First pass: collect all log entries and find the latest timestamp
                all_log_entries = []
                latest_timestamp = None
                
                # Traverse each control plane node directory
                for node_dir in getattr(control_plane_dir, "iterdir", lambda: [])():
                    node_ip = os.path.basename(node_dir)
                    logger.debug(f"Processing control plane node: {node_ip}")
                    
                    # Look for kubelet.log in this node
                    kubelet_log_path = f"{NEW_LOG_BUNDLE_PATH}/control-plane/{node_ip}/journals/kubelet.log"
                    try:
                        kubelet_logs = log_analyzer.logs_archive.get(kubelet_log_path)
                        logger.debug(f"Found kubelet.log for node {node_ip}, size: {len(kubelet_logs)} characters")
                    except FileNotFoundError:
                        logger.debug(f"kubelet.log not found for node {node_ip} at path: {kubelet_log_path}")
                        continue
                    
                    # Parse all log lines to find timestamps and crash patterns
                    line_count = 0
                    crash_matches_found = 0
                    for line in kubelet_logs.split('\n'):
                        line_count += 1
                        if not line.strip():
                            continue
                            
                        # Extract timestamp from any log line (format: "Sep 17 14:40:15")
                        timestamp_match = re.match(r'(\w{3} \d{1,2} \d{2}:\d{2}:\d{2})', line)
                        if timestamp_match:
                            timestamp_str = timestamp_match.group(1)
                            try:
                                # Parse the timestamp (format: "Sep 17 14:40:15")
                                log_time = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
                                
                                # Track the latest timestamp
                                if latest_timestamp is None or log_time > latest_timestamp:
                                    latest_timestamp = log_time
                                    
                            except ValueError as e:
                                logger.debug(f"Failed to parse timestamp '{timestamp_str}': {e}")
                                continue
                        
                        # Check for crash patterns
                        crash_match = crash_pattern.search(line)
                        if crash_match:
                            crash_matches_found += 1
                            timestamp_str = crash_match.group(1)
                            container_name = crash_match.group(2)
                            logger.debug(f"Found crash match: {container_name} at {timestamp_str}")
                            all_log_entries.append({
                                'timestamp_str': timestamp_str,
                                'container_name': container_name,
                                'node_ip': node_ip,
                                'line': line
                            })
                    
                    logger.debug(f"Node {node_ip}: processed {line_count} lines, found {crash_matches_found} crash matches")
                
                logger.debug(f"Total crash entries found: {len(all_log_entries)}")
                logger.debug(f"Latest timestamp found: {latest_timestamp}")
                
                # If we found a latest timestamp, filter crashes to last 30 minutes
                if latest_timestamp:
                    thirty_minutes_before_latest = latest_timestamp - timedelta(minutes=30)
                    logger.debug(f"Filtering crashes from {thirty_minutes_before_latest} to {latest_timestamp}")
                    
                    for entry in all_log_entries:
                        try:
                            # Parse the crash timestamp
                            crash_time = datetime.strptime(entry['timestamp_str'], "%b %d %H:%M:%S")
                            
                            # Check if this crash is within the last 30 minutes of the latest log entry
                            if crash_time >= thirty_minutes_before_latest:
                                logger.debug(f"Including crash: {entry['container_name']} at {entry['timestamp_str']}")
                                container_crashes[entry['container_name']] += 1
                                host_container_crashes[entry['node_ip']][entry['container_name']] += 1
                                crash_details.append({
                                    'timestamp': entry['timestamp_str'],
                                    'container': entry['container_name'],
                                    'node': entry['node_ip']
                                })
                            else:
                                logger.debug(f"Excluding crash (too old): {entry['container_name']} at {entry['timestamp_str']}")
                        except ValueError as e:
                            logger.debug(f"Failed to parse crash timestamp '{entry['timestamp_str']}': {e}")
                            # If timestamp parsing fails, still count the crash
                            container_crashes[entry['container_name']] += 1
                            host_container_crashes[entry['node_ip']][entry['container_name']] += 1
                            crash_details.append({
                                'timestamp': entry['timestamp_str'],
                                'container': entry['container_name'],
                                'node': entry['node_ip']
                            })
                else:
                    logger.debug("No latest timestamp found, counting all crashes")
                    # If we couldn't determine the latest timestamp, count all crashes
                    for entry in all_log_entries:
                        container_crashes[entry['container_name']] += 1
                        host_container_crashes[entry['node_ip']][entry['container_name']] += 1
                        crash_details.append({
                            'timestamp': entry['timestamp_str'],
                            'container': entry['container_name'],
                            'node': entry['node_ip']
                        })
            
            except FileNotFoundError as e:
                logger.debug(f"Control-plane directory not found: {e}")

            logger.debug(f"Final container crashes: {dict(container_crashes)}")
            logger.debug(f"Final crash details count: {len(crash_details)}")

            # If no crashes found, return None
            if not container_crashes:
                logger.debug("No container crashes found, returning None")
                return None

            # Generate content with crash summary grouped by host
            content = "Container crashes detected in the last 30 minutes:\n\n"
            
            # Sort hosts by total crash count (descending)
            host_totals = {host: sum(containers.values()) for host, containers in host_container_crashes.items()}
            sorted_hosts = sorted(host_totals.items(), key=lambda x: x[1], reverse=True)
            
            for host_ip, total_crashes in sorted_hosts:
                content += f"Host {host_ip} ({total_crashes} total crashes):\n"
                
                # Sort containers by crash count for this host
                sorted_containers = sorted(host_container_crashes[host_ip].items(), key=lambda x: x[1], reverse=True)
                
                for container_name, crash_count in sorted_containers:
                    content += f"  • {container_name}: {crash_count} crash(es)\n"
                    
                    # Try to find and include the last 20 logs for this container
                    try:
                        container_logs_list = self._get_container_logs(log_analyzer, host_ip, container_name)
                        if container_logs_list:
                            content += f"    Last 20 container logs:\n"
                            for log_file_name, log_lines in container_logs_list:
                                if len(container_logs_list) > 1:
                                    content += f"      --- {log_file_name} ---\n"
                                for log_line in log_lines:
                                    content += f"      {log_line}\n"
                                if len(container_logs_list) > 1:
                                    content += f"      --- end {log_file_name} ---\n"
                        else:
                            content += f"    (Container logs not found)\n"
                    except Exception as e:
                        logger.debug(f"Failed to get logs for {container_name} on {host_ip}: {e}")
                        content += f"    (Error retrieving container logs)\n"
                
                content += "\n"
            
            # Determine severity based on crash count
            total_crashes = sum(container_crashes.values())
            if total_crashes >= 10:
                severity = "error"
            elif total_crashes >= 5:
                severity = "warning"
            else:
                severity = "info"

            return SignatureResult(
                signature_name=self.name,
                title="Container Crash Analysis (Last 30 Minutes)",
                content=content,
                severity=severity
            )

        except Exception as e:
            logger.error(f"Error in ContainerCrashAnalysis: {e}", exc_info=True)
            return None

    def _get_container_logs(self, log_analyzer, host_ip: str, container_name: str) -> List[tuple]:
        """Get the last 20 lines from all container log files for a given container."""
        try:
            # Look for container log files in the containers directory
            containers_dir_path = f"{NEW_LOG_BUNDLE_PATH}/control-plane/{host_ip}/containers/"
            
            try:
                containers_dir = log_analyzer.logs_archive.get(containers_dir_path)
            except FileNotFoundError:
                logger.debug(f"Containers directory not found: {containers_dir_path}")
                return []
            
            # Find all container log files (they have a random hash component)
            # Pattern: {container_name}-{hash}.log (exact match, not substring)
            container_log_files = []
            for item in getattr(containers_dir, "iterdir", lambda: [])():
                item_path = str(item) if hasattr(item, '__str__') else item
                # Extract just the filename from the full path
                item_name = os.path.basename(item_path)
                logger.debug(f"evaluating item name {item_name} from path {item_path}")
                # Use regex to ensure exact container name match followed by hyphen and hash
                import re
                pattern = re.compile(rf"^{re.escape(container_name)}-[a-f0-9]{{64}}\.log$")
                if pattern.match(item_name):
                    container_log_files.append(item_name)
            
            if not container_log_files:
                logger.debug(f"No log files found for container {container_name} on {host_ip}")
                return []
            
            logger.debug(f"Found {len(container_log_files)} log files for container {container_name} on {host_ip}")
            
            # Process each log file
            all_logs = []
            for log_file_name in sorted(container_log_files):  # Sort for consistent ordering
                log_file_path = f"{containers_dir_path}/{log_file_name}"
                
                try:
                    container_log_content = log_analyzer.logs_archive.get(log_file_path)
                except FileNotFoundError:
                    logger.debug(f"Container log file not found: {log_file_path}")
                    continue
                
                # Get the last 20 lines from this log file
                log_lines = container_log_content.split('\n')
                # Filter out empty lines and get last 20 non-empty lines
                non_empty_lines = [line for line in log_lines if line.strip()]
                last_20_lines = non_empty_lines[-20:] if len(non_empty_lines) > 20 else non_empty_lines
                
                if last_20_lines:  # Only include if there are actual log lines
                    all_logs.append((log_file_name, last_20_lines))
                    logger.debug(f"Retrieved {len(last_20_lines)} log lines from {log_file_name}")
            
            return all_logs
            
        except Exception as e:
            logger.debug(f"Error getting container logs for {container_name} on {host_ip}: {e}")
            return []


# TODO: Add more advanced analysis signatures here:
# - AllInstallationAttemptsSignature (requires JIRA integration)
# - MustGatherAnalysis
# - NodeStatus
# - UserManagedNetworkingLoadBalancer
# - FailedRequestTriggersHostTimeout
# - ControllerWarnings
# - UserHasLoggedIntoCluster
# - OSTreeCommitMismatch
# - ControllerFailedToStart
# - MachineConfigDaemonErrorExtracting
