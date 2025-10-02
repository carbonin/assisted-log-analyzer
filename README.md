# OpenShift Assisted Installer Log Analyzer

A standalone tool for analyzing OpenShift Assisted Installer cluster logs without requiring JIRA integration.

## Features

- Downloads cluster logs directly from the OpenShift API using presigned URLs
- Analyzes various aspects of the installation process:
  - Host status and progress
  - Component versions
  - Agent step failures
  - Image download performance
  - Media disconnection issues
  - OS installation timing
  - And more...
- Outputs analysis results to stdout in a human-readable format
- No dependency on JIRA or external ticket systems

## Installation

1. Clone or download this tool
2. Install with uv (recommended):
   ```bash
   uv sync
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

## Usage

### Basic Usage

```bash
# Using the installed console script
analyze-openshift-logs <cluster-uuid>

# Or using the development runner
./analyze-logs <cluster-uuid>
```

### With Authentication Token

```bash
analyze-openshift-logs <cluster-uuid> --auth-token <your-token>
```

Or set the environment variable:
```bash
export OPENSHIFT_AUTH_TOKEN=<your-token>
analyze-openshift-logs <cluster-uuid>
```

### Run Specific Signatures

```bash
analyze-openshift-logs <cluster-uuid> --signatures HostsStatusSignature AgentStepFailureSignature
```

### List Available Signatures

```bash
analyze-openshift-logs --list-signatures
```

### Verbose Output

```bash
analyze-openshift-logs <cluster-uuid> --verbose
```

## API Endpoint

The tool fetches logs using the OpenShift API endpoint:
```
GET https://api.openshift.com/api/assisted-install/v2/clusters/{cluster_id}/downloads/files-presigned?file_name=logs
```

This returns a JSON response with a presigned URL:
```json
{
  "expires_at": "0001-01-01T00:00:00.000Z",
  "url": "https://s3.us-east-1.amazonaws.com/assisted-installer/..."
}
```

## Architecture

- **API Client** (`api_client.py`): Handles API communication and log downloading
- **Log Analyzer** (`log_analyzer.py`): Core log parsing and data extraction
- **Signatures** (`signatures.py`): Analysis modules for different aspects of the logs
- **Main** (`main.py`): CLI interface and orchestration

## Supported Log Archive Formats

The tool handles both old and new log archive formats:
- New format: `*_bootstrap_*.tar/*_bootstrap_*.tar.gz/logs_host_*/log-bundle-*.tar.gz/log-bundle-*`
- Old format: `*_bootstrap_*.tar.gz/logs_host_*/log-bundle-*.tar.gz/log-bundle-*`

## Available Signatures

Use `analyze-openshift-logs --list-signatures` to see exactly which signatures are enabled in your installation. The following catalog lists the signatures that ship with this repository today.

### Basic Information

- `HostsStatusSignature`: Summarizes host status and installation progress.
- `ComponentsVersionSignature`: Reports Assisted Installer component versions.
- `FailureDescription`: Produces a cluster-level failure summary table.
- `HostsExtraDetailSignature`: Shows additional inventory information for each host.
- `HostsInterfacesSignature`: Lists per-host network interfaces and addresses.
- `StorageDetailSignature`: Details disks discovered on each host.

### Performance and Resource Usage

- `SlowImageDownloadSignature`: Detects slow assisted installer image downloads.
- `OSInstallationTimeSignature`: Flags hosts with long "Writing image to disk" stages.
- `InstallationDiskFIOSignature`: Surfaces slow installation disks from FIO metrics.

### Networking

- `SNOMachineCidrSignature`: Validates machine CIDR configuration for SNO clusters.
- `NonstandardNetworkType`: Warns about non-standard cluster network types.
- `DuplicateVIP`: Finds API/ingress VIP collisions across hosts.
- `NameserverInClusterNetwork`: Detects nameservers that overlap cluster networks.
- `NetworksMtuMismatch`: Reports MTU mismatches between interfaces and the overlay.
- `DualStackBadRoute`: Surfaces BZ 2088346 default gateway issues in dual-stack setups.
- `DualstackrDNSBug`: Flags kube-apiserver address-family validation errors (MGMT-11651).
- `UserManagedNetworkingLoadBalancer`: Warns about UMN clusters missing load-balancer operators.

### Error Detection

- `MasterFailedToPullIgnitionSignature`: Identifies masters that failed to pull ignition.
- `EmptyManifest`: Detects suspiciously small manifests (MGMT-15243).
- `SNOHostnameHasEtcd`: Validates that SNO hostnames do not contain "etcd" (OCPBUGS-15852).
- `ApiInvalidCertificateSignature`: Highlights invalid SAN values on Assisted Installer API certificates.
- `ApiExpiredCertificateSignature`: Detects expired or not-yet-valid kube-apiserver certificates.
- `ReleasePullErrorSignature`: Reports bootstrap nodes that cannot pull the release image.
- `ErrorOnCleanupInstallDevice`: Notes non-fatal cleanupInstallDevice warnings.
- `MissingMC`: Detects missing rendered MachineConfig resources.
- `ErrorCreatingReadWriteLayer`: Surfaces pods failing with "error creating read-write layer" (BZ 1993243).
- `InsufficientLVMCleanup`: Warns about LVM cleanup issues (MGMT-11695).
- `SkipDisks`: Reports hosts configured to skip disk formatting.

### Advanced Analysis

- `AgentStepFailureSignature`: Summarizes agent step failures per host.
- `EventsInstallationAttempts`: Detects multiple installation attempts in the events log.
- `MissingMustGatherLogs`: Warns when must-gather logs are missing but expected.
- `FlappingValidations`: Tracks validation states that oscillate during install.
- `ControllerOperatorStatus`: Surfaces unhealthy operators from controller logs.
- `NodeStatus`: Summarizes node condition data from installer gather artifacts.
- `ControllerWarnings`: Extracts warning-level entries from controller logs.
- `UserHasLoggedIntoCluster`: Notes evidence of interactive logins during install.
- `FailedRequestTriggersHostTimeout`: Correlates failed API requests with host timeouts.
- `ControllerFailedToStart`: Reports Assisted Controller pod readiness issues.
- `MachineConfigDaemonErrorExtracting`: Detects firstboot extraction errors (OCPBUGS-5352).

### Platform-Specific

- `LibvirtRebootFlagSignature`: Flags potential libvirt `_on_reboot` issues (MGMT-2840).
- `IpChangedAfterReboot`: Detects IP address changes after host reboots.

## Requirements

- Python 3.8+
- Network access to OpenShift API and S3 storage
- Valid authentication token (if required for the cluster)

## License

Apache License 2.0
