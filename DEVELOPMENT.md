# Development Guide

## Quick Start

1. Set up the environment:
   ```bash
   uv sync
   source .venv/bin/activate
   ```

2. Run the tool:
   ```bash
   # Using the console script (installed by uv sync)
   analyze-openshift-logs --list-signatures
   analyze-openshift-logs <cluster-uuid>
   
   # Or using the development runner
   ./analyze-logs --list-signatures
   ./analyze-logs <cluster-uuid>
   ```

## Project Structure

```
log-analyzer/
├── src/log_analyzer/          # Main source code
│   ├── __init__.py           # Package initialization
│   ├── api_client.py         # API client for downloading logs
│   ├── log_analyzer.py       # Core log parsing and extraction
│   ├── signatures.py         # Analysis signatures
│   └── main.py              # CLI interface
├── analyze-logs              # Development runner script
├── pyproject.toml           # Project configuration and dependencies
└── README.md                # User documentation
```

## Adding New Signatures

1. Create a new class in `signatures.py` that inherits from `Signature`
2. Implement the `analyze()` method
3. Add the class to the `ALL_SIGNATURES` list
4. Test with `./analyze-logs --signatures YourNewSignature <cluster-uuid>`

Example:
```python
class YourNewSignature(Signature):
    def analyze(self, log_analyzer: LogAnalyzer) -> Optional[SignatureResult]:
        try:
            # Your analysis logic here
            metadata = log_analyzer.metadata
            # ... analyze logs ...
            
            if issue_found:
                return SignatureResult(
                    signature_name=self.name,
                    title="Your Analysis Title",
                    content="Description of what was found",
                    severity="error"  # or "warning" or "info"
                )
        except Exception as e:
            logger.error(f"Error in {self.name}: {e}")
        
        return None
```

## Testing

- Use `./analyze-logs --list-signatures` to verify signatures load
- Use a real cluster UUID to test full functionality
- Check verbose output with `-v` flag for debugging

## Log Archive Structure

The tool handles nested tar archives with these common patterns:
- `metadata.json` - Cluster metadata
- `cluster_{id}_events.json` - Installation events
- `controller_logs.tar.gz/` - Controller logs
- `{hostname}.tar.gz/logs_host_{host_id}/` - Per-host logs
- Log bundle paths (new/old formats supported)

## Dependency Management

This project uses [uv](https://docs.astral.sh/uv/) for dependency management. All dependencies are defined in `pyproject.toml`.

### Key Commands

```bash
# Install all dependencies and the project in development mode
uv sync

# Install with development dependencies
uv sync --extra dev

# Add a new dependency
uv add requests

# Add a development dependency
uv add --dev pytest

# Update dependencies
uv sync --upgrade
```

### Dependencies

- `requests` - HTTP client for API calls
- `nestedarchive` - Handling nested tar/gz archives
- `python-dateutil` - Date parsing
- `pyyaml` - YAML parsing for install-config
- `colorlog` - Colored logging (optional)
- `tabulate` - Table formatting

### Development Dependencies

- `pytest` - Testing framework
- `black` - Code formatting
- `isort` - Import sorting
- `mypy` - Type checking
