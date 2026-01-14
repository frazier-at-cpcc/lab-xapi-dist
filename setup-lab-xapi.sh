#!/bin/bash
#
# setup-lab-xapi.sh - Single-file installer for lab-xapi
#
# This script installs the lab-xapi wrapper which captures grading results
# and submits them as xAPI statements to a Learning Record Store.
#
# Usage:
#   curl -sSL <url>/setup-lab-xapi.sh | bash
#   or
#   ./setup-lab-xapi.sh
#
# Uninstall:
#   ./setup-lab-xapi.sh --uninstall
#

set -e

# Configuration
INSTALL_DIR="${HOME}/.local/share/lab-xapi"
CONFIG_DIR="${HOME}/.config/lab-xapi"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_step() {
    echo -e "${BLUE}==>${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}!${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Handle uninstall
if [ "$1" = "uninstall" ] || [ "$1" = "--uninstall" ]; then
    print_step "Uninstalling lab-xapi..."

    if [ -d "$INSTALL_DIR" ]; then
        rm -rf "$INSTALL_DIR"
        print_success "Removed $INSTALL_DIR"
    fi

    for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
        if [ -f "$rc" ] && grep -q "lab-xapi" "$rc"; then
            grep -v "lab-xapi" "$rc" > "$rc.tmp" && mv "$rc.tmp" "$rc"
            print_success "Removed alias from $rc"
        fi
    done

    echo ""
    print_success "Uninstallation complete!"
    echo "Note: Configuration in ~/.config/lab-xapi was preserved."
    echo "Remove it manually if you want to delete all data."
    exit 0
fi

# Check prerequisites
check_prereqs() {
    print_step "Checking prerequisites..."

    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is required but not installed."
        exit 1
    fi
    print_success "Python 3 found: $(python3 --version)"

    if [ ! -x /usr/local/bin/lab ]; then
        print_error "Original lab command not found at /usr/local/bin/lab"
        exit 1
    fi
    print_success "Original lab command found"

    print_step "Checking Python dependencies..."
    python3 -c "import requests" 2>/dev/null || {
        print_warning "Installing requests module..."
        pip3 install --user requests 2>/dev/null || print_warning "Could not install requests."
    }
    python3 -c "import yaml" 2>/dev/null || {
        print_warning "Installing pyyaml module..."
        pip3 install --user pyyaml 2>/dev/null || print_warning "Could not install pyyaml."
    }
}

# Create all files
install_files() {
    print_step "Installing files to $INSTALL_DIR..."
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$CONFIG_DIR/queue"

    # Create lab-xapi shell wrapper
    cat > "$INSTALL_DIR/lab-xapi" << 'SHELL_WRAPPER'
#!/bin/bash
#
# lab-xapi - Wrapper for the lab command with xAPI integration
#

LAB_XAPI_DIR="$(dirname "$(readlink -f "$0")")"
PYTHON_EXEC="python3"

if [ "$1" = "grade" ] && [ -n "$2" ]; then
    exec "$PYTHON_EXEC" "$LAB_XAPI_DIR/lab_wrapper.py" "$@"
elif [ "$1" = "start" ] && [ -n "$2" ]; then
    exec "$PYTHON_EXEC" "$LAB_XAPI_DIR/lab_wrapper.py" "$@"
elif [ "$1" = "xapi-config" ] || [ "$1" = "xapi" ]; then
    shift
    exec "$PYTHON_EXEC" "$LAB_XAPI_DIR/lab_wrapper.py" "xapi-config" "$@"
else
    exec /usr/local/bin/lab "$@"
fi
SHELL_WRAPPER
    chmod +x "$INSTALL_DIR/lab-xapi"

    # Create config.py
    cat > "$INSTALL_DIR/config.py" << 'CONFIG_PY'
"""
Configuration management for lab-xapi integration.
"""

import os
import re
from pathlib import Path
from typing import Optional

try:
    import yaml
except ImportError:
    yaml = None

CONFIG_DIR = Path.home() / ".config" / "lab-xapi"
CONFIG_FILE = CONFIG_DIR / "config.yaml"

DEFAULT_CONFIG = {
    "actor_email": "",
    "lrs_endpoint": "https://lrs.labsconnect.org/xapi",
    "lrs_auth_token": "MDliNWE5MzA4Y2M4ZDZiZGJjMjYwMDg5MDJjZGU2MTM4NTJhZTQyNmJlNGQ3NGZhZGNlMzQwMGM5NDUzNGJiODo5NjRjYzc4MzA5ZmNmOGUyN2U3M2FmOTIxOWUzYWQ5M2U5ZWJmNTE2MTZlNGFkNGNhZTRhYTljNDY5MWM3Y2Rl",
    "enabled": True,
}


def ensure_config_dir():
    """Create config directory if it doesn't exist."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def load_config() -> dict:
    """Load configuration from file, returning defaults if not found."""
    ensure_config_dir()

    if not CONFIG_FILE.exists():
        return DEFAULT_CONFIG.copy()

    try:
        with open(CONFIG_FILE, "r") as f:
            if yaml:
                config = yaml.safe_load(f) or {}
            else:
                config = {}
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and ":" in line:
                        key, value = line.split(":", 1)
                        value = value.strip().strip('"').strip("'")
                        if value.lower() == "true":
                            value = True
                        elif value.lower() == "false":
                            value = False
                        config[key.strip()] = value

        merged = DEFAULT_CONFIG.copy()
        merged.update(config)
        return merged
    except Exception as e:
        print(f"Warning: Could not load config: {e}")
        return DEFAULT_CONFIG.copy()


def save_config(config: dict):
    """Save configuration to file."""
    ensure_config_dir()

    try:
        with open(CONFIG_FILE, "w") as f:
            if yaml:
                yaml.dump(config, f, default_flow_style=False)
            else:
                for key, value in config.items():
                    if isinstance(value, bool):
                        value = str(value).lower()
                    f.write(f"{key}: {value}\n")

        os.chmod(CONFIG_FILE, 0o600)
    except Exception as e:
        print(f"Warning: Could not save config: {e}")


def validate_email(email: str) -> bool:
    """Validate email format."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def prompt_for_email() -> str:
    """Prompt user for their email address."""
    print("\n" + "=" * 50)
    print("xAPI Grade Reporting Setup")
    print("=" * 50)
    print("\nYour lab grades will be reported to the Learning")
    print("Record Store (LRS) for tracking your progress.\n")

    while True:
        try:
            email = input("Enter your email address: ").strip()
            if validate_email(email):
                print(f"\nEmail saved: {email}")
                print("Your grades will now be reported automatically.\n")
                return email
            else:
                print("Invalid email format. Please try again.")
        except (KeyboardInterrupt, EOFError):
            print("\n\nSetup cancelled. xAPI reporting disabled.")
            return ""


def prompt_for_lrs_config() -> tuple:
    """Prompt for LRS endpoint and credentials."""
    print("\nLRS Configuration")
    print("-" * 30)

    try:
        endpoint = input("LRS Endpoint URL: ").strip()
        auth_token = input("LRS Auth Token (Base64): ").strip()
        return endpoint, auth_token
    except (KeyboardInterrupt, EOFError):
        print("\n\nLRS configuration cancelled.")
        return "", ""


def get_config() -> dict:
    """Get configuration, prompting for missing values."""
    config = load_config()

    if not config.get("actor_email"):
        email = prompt_for_email()
        if email:
            config["actor_email"] = email
            save_config(config)

    return config


def is_configured() -> bool:
    """Check if xAPI reporting is properly configured."""
    config = load_config()
    return bool(
        config.get("actor_email") and
        config.get("lrs_endpoint") and
        config.get("enabled", True)
    )


def set_email(email: str) -> bool:
    """Set the actor email in configuration."""
    if not validate_email(email):
        return False

    config = load_config()
    config["actor_email"] = email
    save_config(config)
    return True


def set_lrs(endpoint: str, auth_token: str):
    """Set LRS endpoint and credentials."""
    config = load_config()
    config["lrs_endpoint"] = endpoint
    config["lrs_auth_token"] = auth_token
    save_config(config)


def set_enabled(enabled: bool):
    """Enable or disable xAPI reporting."""
    config = load_config()
    config["enabled"] = enabled
    save_config(config)


def has_email() -> bool:
    """Check if email is configured (without prompting)."""
    config = load_config()
    return bool(config.get("actor_email"))


def ensure_email_configured() -> bool:
    """Ensure email is configured, prompting if needed."""
    config = load_config()

    if config.get("actor_email"):
        return True

    email = prompt_for_email()
    if email:
        config["actor_email"] = email
        save_config(config)
        return True

    return False
CONFIG_PY

    # Create output_parser.py
    cat > "$INSTALL_DIR/output_parser.py" << 'OUTPUT_PARSER_PY'
"""
Output parser for lab grading results.
Extracts PASS/FAIL steps from lab grade command output.
"""

import re
from datetime import datetime, timezone
from typing import List, Dict, Optional


def strip_ansi(text: str) -> str:
    """Remove ANSI escape codes from text."""
    ansi_pattern = r'\x1b\[[0-9;?]*[a-zA-Z]'
    text = re.sub(ansi_pattern, '', text)
    text = text.replace('\r', '')
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text


def parse_grade_output(output: str) -> List[Dict]:
    """
    Parse lab grade output and extract grading steps.
    Returns list of dicts with keys: label, passed, result, messages, timestamp
    """
    clean_output = strip_ansi(output)
    lines = clean_output.split('\n')

    steps = []
    current_step = None
    step_pattern = re.compile(r'^(PASS|FAIL)\s+(.+)$')
    message_pattern = re.compile(r'^\s+[-•]\s*(.+)$')

    for line in lines:
        step_match = step_pattern.match(line)
        if step_match:
            if current_step:
                steps.append(current_step)

            result = step_match.group(1)
            label = step_match.group(2).strip()

            current_step = {
                'label': label,
                'passed': result == 'PASS',
                'result': result,
                'messages': [],
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        elif current_step:
            msg_match = message_pattern.match(line)
            if msg_match:
                current_step['messages'].append(msg_match.group(1).strip())

    if current_step:
        steps.append(current_step)

    return steps


def parse_overall_result(output: str) -> Optional[bool]:
    """Extract overall lab grade from output."""
    clean_output = strip_ansi(output)
    match = re.search(r'Overall lab grade:\s*(PASS|FAIL)', clean_output, re.IGNORECASE)
    if match:
        return match.group(1).upper() == 'PASS'
    return None


def extract_grading_section(output: str) -> str:
    """Extract just the grading section from lab output."""
    clean_output = strip_ansi(output)
    lines = clean_output.split('\n')

    grading_lines = []
    in_grading = False

    for line in lines:
        if 'Grading lab' in line or 'Grading the lab' in line:
            in_grading = True
        if in_grading:
            grading_lines.append(line)
        if 'Overall lab grade' in line:
            break

    return '\n'.join(grading_lines)
OUTPUT_PARSER_PY

    # Create xapi_reporter.py
    cat > "$INSTALL_DIR/xapi_reporter.py" << 'XAPI_REPORTER_PY'
"""
xAPI statement builder and reporter.
Generates xAPI statements from grading results and sends to LRS.
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Optional, Tuple

try:
    import requests
except ImportError:
    requests = None

VERBS = {
    "passed": {
        "id": "http://adlnet.gov/expapi/verbs/passed",
        "display": {"en-US": "passed"}
    },
    "failed": {
        "id": "http://adlnet.gov/expapi/verbs/failed",
        "display": {"en-US": "failed"}
    },
    "completed": {
        "id": "http://adlnet.gov/expapi/verbs/completed",
        "display": {"en-US": "completed"}
    },
    "incomplete": {
        "id": "http://adlnet.gov/expapi/verbs/incomplete",
        "display": {"en-US": "incomplete"}
    },
    "attempted": {
        "id": "http://adlnet.gov/expapi/verbs/attempted",
        "display": {"en-US": "attempted"}
    }
}

BASE_IRI = "https://training.redhat.com/labs"


def get_current_sku() -> str:
    """Get current course SKU from grading config."""
    config_path = Path.home() / ".grading" / "config.yaml"
    if config_path.exists():
        try:
            with open(config_path) as f:
                for line in f:
                    if line.strip().startswith("sku:"):
                        return line.split(":", 1)[1].strip().strip('"').strip("'")
        except Exception:
            pass
    return "unknown"


def build_statement(email: str, step: Dict, slug: str, task_index: int) -> Dict:
    """Build a single xAPI statement for a grading task."""
    verb_key = "passed" if step.get("passed") else "failed"
    task_id = f"{BASE_IRI}/{slug}/task-{task_index}"

    statement = {
        "id": str(uuid.uuid4()),
        "actor": {
            "mbox": f"mailto:{email}",
            "objectType": "Agent"
        },
        "verb": VERBS[verb_key],
        "object": {
            "id": task_id,
            "objectType": "Activity",
            "definition": {
                "name": {"en-US": step.get("label", f"Task {task_index}")},
                "description": {"en-US": "; ".join(step.get("messages", []))[:500]},
                "type": "http://adlnet.gov/expapi/activities/assessment"
            }
        },
        "result": {
            "success": step.get("passed", False),
            "completion": True
        },
        "context": {
            "contextActivities": {
                "parent": [{
                    "id": f"{BASE_IRI}/{slug}",
                    "objectType": "Activity",
                    "definition": {
                        "name": {"en-US": f"Lab: {slug}"},
                        "type": "http://adlnet.gov/expapi/activities/assessment"
                    }
                }]
            }
        },
        "timestamp": step.get("timestamp", datetime.now(timezone.utc).isoformat())
    }

    return statement


def build_lab_completion_statement(email: str, slug: str,
                                    passed_count: int, total_count: int) -> Dict:
    """Build a lab completion statement with overall score."""
    all_passed = passed_count == total_count
    verb_key = "passed" if all_passed else "incomplete"

    statement = {
        "id": str(uuid.uuid4()),
        "actor": {
            "mbox": f"mailto:{email}",
            "objectType": "Agent"
        },
        "verb": VERBS[verb_key],
        "object": {
            "id": f"{BASE_IRI}/{slug}",
            "objectType": "Activity",
            "definition": {
                "name": {"en-US": f"Lab: {slug}"},
                "type": "http://adlnet.gov/expapi/activities/assessment"
            }
        },
        "result": {
            "success": all_passed,
            "completion": all_passed,
            "score": {
                "scaled": passed_count / total_count if total_count > 0 else 0,
                "raw": passed_count,
                "min": 0,
                "max": total_count
            }
        },
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    return statement


def send_statement(statement: Dict, lrs_endpoint: str, auth_token: str) -> bool:
    """Send a single xAPI statement to the LRS."""
    if not requests:
        print("Warning: requests library not available, cannot send to LRS")
        return False

    url = f"{lrs_endpoint.rstrip('/')}/statements"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Basic {auth_token}",
        "X-Experience-API-Version": "1.0.3"
    }

    try:
        response = requests.post(url, json=statement, headers=headers, timeout=10)
        if response.status_code in (200, 204):
            return True
        else:
            print(f"Warning: LRS returned status {response.status_code}: {response.text[:200]}")
            return False
    except requests.RequestException as e:
        print(f"Warning: Failed to send statement: {e}")
        return False


def send_statements(steps: List[Dict], slug: str, email: str,
                    lrs_endpoint: str, auth_token: str, verbose: bool = False) -> Tuple[int, int]:
    """Send all statements for a lab grading session."""
    if not steps:
        return 0, 0

    if not email:
        print("Warning: No email configured, cannot send xAPI statements")
        return 0, len(steps)

    successful = 0
    total = len(steps)

    if verbose:
        print(f"\nSending xAPI statements... ", end="", flush=True)

    for i, step in enumerate(steps, 1):
        statement = build_statement(email, step, slug, i)
        if send_statement(statement, lrs_endpoint, auth_token):
            successful += 1

    passed_count = sum(1 for s in steps if s.get("passed"))
    completion_stmt = build_lab_completion_statement(
        email, slug, passed_count, total
    )
    if send_statement(completion_stmt, lrs_endpoint, auth_token):
        successful += 1

    if verbose:
        if successful == total + 1:
            print(f"Done ({total} tasks reported)")
        else:
            print(f"Partial ({successful}/{total + 1} statements sent)")

    return successful, total + 1


def save_statements_locally(steps: List[Dict], slug: str, email: str) -> Optional[Path]:
    """Save statements to local queue for later submission."""
    if not steps or not email:
        return None

    statements = []

    for i, step in enumerate(steps, 1):
        statements.append(build_statement(email, step, slug, i))

    passed_count = sum(1 for s in steps if s.get("passed"))
    statements.append(build_lab_completion_statement(
        email, slug, passed_count, len(steps)
    ))

    queue_dir = Path.home() / ".config" / "lab-xapi" / "queue"
    queue_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{slug}_{timestamp}.json"
    filepath = queue_dir / filename

    with open(filepath, "w") as f:
        json.dump(statements, f, indent=2)

    return filepath
XAPI_REPORTER_PY

    # Create lab_wrapper.py
    cat > "$INSTALL_DIR/lab_wrapper.py" << 'LAB_WRAPPER_PY'
#!/usr/bin/env python3
"""
Lab wrapper script with xAPI integration.
"""

import os
import sys
import subprocess
from pathlib import Path

LAB_XAPI_DIR = Path(__file__).parent
sys.path.insert(0, str(LAB_XAPI_DIR))

from config import load_config, save_config, prompt_for_email, get_config, ensure_email_configured, validate_email
from xapi_reporter import send_statements, save_statements_locally
from output_parser import parse_grade_output, parse_overall_result

ORIGINAL_LAB = "/usr/local/bin/lab"


def run_lab_command(args: list) -> int:
    """Run the original lab command and return exit code."""
    cmd = [ORIGINAL_LAB] + args
    result = subprocess.run(cmd)
    return result.returncode


def run_grade_with_xapi(slug: str, extra_args: list) -> int:
    """Run lab grade command with xAPI reporting."""
    config = get_config()
    grade_args = ["grade", slug] + extra_args
    cmd = [ORIGINAL_LAB] + grade_args

    import pty
    import select
    import io

    output_buffer = io.StringIO()

    def read_and_display(fd):
        data = os.read(fd, 1024)
        if data:
            text = data.decode('utf-8', errors='replace')
            sys.stdout.write(text)
            sys.stdout.flush()
            output_buffer.write(text)
        return data

    pid, master_fd = pty.fork()

    if pid == 0:
        os.execv(ORIGINAL_LAB, [ORIGINAL_LAB] + grade_args)
    else:
        exit_status = None
        try:
            while True:
                ready, _, _ = select.select([master_fd], [], [], 0.1)
                if ready:
                    data = read_and_display(master_fd)
                    if not data:
                        break
                else:
                    wpid, status = os.waitpid(pid, os.WNOHANG)
                    if wpid != 0:
                        exit_status = status
                        while True:
                            try:
                                data = read_and_display(master_fd)
                                if not data:
                                    break
                            except OSError:
                                break
                        break
        except OSError:
            pass
        finally:
            os.close(master_fd)

        if exit_status is None:
            _, exit_status = os.waitpid(pid, 0)

        exit_code = os.WEXITSTATUS(exit_status) if os.WIFEXITED(exit_status) else 1

    output = output_buffer.getvalue()
    steps = parse_grade_output(output)

    if steps and config.get("enabled", True):
        email = config.get("actor_email", "")
        lrs_endpoint = config.get("lrs_endpoint", "")
        auth_token = config.get("lrs_auth_token", "")

        if email:
            if lrs_endpoint and auth_token:
                send_statements(
                    steps=steps,
                    slug=slug,
                    email=email,
                    lrs_endpoint=lrs_endpoint,
                    auth_token=auth_token,
                    verbose=True
                )
            else:
                saved_path = save_statements_locally(steps, slug, email)
                if saved_path:
                    print(f"\nGrades saved locally: {saved_path}")
                    print("Configure LRS to submit: lab xapi-config lrs")

    return exit_code


def run_start_with_email_check(slug: str, extra_args: list) -> int:
    """Run lab start command, prompting for email if not configured."""
    if not ensure_email_configured():
        print("\nNote: xAPI grade reporting is disabled until email is configured.")
        print("Run 'lab xapi-config email' to configure later.\n")

    start_args = ["start", slug] + extra_args
    return run_lab_command(start_args)


def run_finish_with_xapi(slug: str, extra_args: list) -> int:
    """Run lab finish command."""
    finish_args = ["finish", slug] + extra_args
    return run_lab_command(finish_args)


def handle_config_command(args: list):
    """Handle xAPI configuration commands."""
    if not args or args[0] in ("-h", "--help", "help"):
        print("""
xAPI Configuration Commands:

  lab xapi-config show        Show current configuration
  lab xapi-config email       Set your email address
  lab xapi-config lrs         Configure LRS endpoint
  lab xapi-config enable      Enable xAPI reporting
  lab xapi-config disable     Disable xAPI reporting
""")
        return 0

    config = load_config()
    subcmd = args[0]

    if subcmd == "show":
        print("\nxAPI Configuration:")
        print("-" * 40)
        print(f"  Email:        {config.get('actor_email') or '(not set)'}")
        print(f"  LRS Endpoint: {config.get('lrs_endpoint') or '(not set)'}")
        print(f"  Auth Token:   {'(configured)' if config.get('lrs_auth_token') else '(not set)'}")
        print(f"  Enabled:      {config.get('enabled', True)}")
        print()
        return 0

    elif subcmd == "email":
        if len(args) > 1:
            email = args[1]
            if validate_email(email):
                config["actor_email"] = email
                save_config(config)
                print(f"Email set to: {email}")
            else:
                print("Invalid email format.")
                return 1
        else:
            email = prompt_for_email()
            if email:
                config["actor_email"] = email
                save_config(config)
        return 0

    elif subcmd == "lrs":
        print("\nLRS Configuration")
        print("-" * 40)
        try:
            endpoint = input("LRS Endpoint URL: ").strip()
            auth_token = input("LRS Auth Token (Base64): ").strip()
            if endpoint:
                config["lrs_endpoint"] = endpoint
            if auth_token:
                config["lrs_auth_token"] = auth_token
            save_config(config)
            print("\nLRS configuration saved.")
        except (KeyboardInterrupt, EOFError):
            print("\nCancelled.")
        return 0

    elif subcmd == "enable":
        config["enabled"] = True
        save_config(config)
        print("xAPI reporting enabled.")
        return 0

    elif subcmd == "disable":
        config["enabled"] = False
        save_config(config)
        print("xAPI reporting disabled.")
        return 0

    else:
        print(f"Unknown config command: {subcmd}")
        return 1


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        return run_lab_command([])

    command = sys.argv[1]
    remaining_args = sys.argv[2:]

    if command == "xapi-config":
        return handle_config_command(remaining_args)

    if command == "grade":
        if not remaining_args:
            return run_lab_command(["grade"])
        slug = remaining_args[0]
        extra_args = remaining_args[1:] if len(remaining_args) > 1 else []
        return run_grade_with_xapi(slug, extra_args)

    if command == "start":
        if not remaining_args:
            return run_lab_command(["start"])
        slug = remaining_args[0]
        extra_args = remaining_args[1:] if len(remaining_args) > 1 else []
        return run_start_with_email_check(slug, extra_args)

    if command == "finish":
        if not remaining_args:
            return run_lab_command(["finish"])
        slug = remaining_args[0]
        extra_args = remaining_args[1:] if len(remaining_args) > 1 else []
        return run_finish_with_xapi(slug, extra_args)

    return run_lab_command(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
LAB_WRAPPER_PY
    chmod +x "$INSTALL_DIR/lab_wrapper.py"

    print_success "Files installed"
}

# Configure shell alias
configure_alias() {
    print_step "Configuring shell alias..."

    ALIAS_LINE="alias lab='$INSTALL_DIR/lab-xapi'"

    if [ -n "$ZSH_VERSION" ] || [ -f "$HOME/.zshrc" ]; then
        SHELL_RC="$HOME/.zshrc"
    else
        SHELL_RC="$HOME/.bashrc"
    fi

    if grep -q "lab-xapi" "$SHELL_RC" 2>/dev/null; then
        print_warning "Removing existing lab-xapi alias"
        grep -v "lab-xapi" "$SHELL_RC" > "$SHELL_RC.tmp" && mv "$SHELL_RC.tmp" "$SHELL_RC"
    fi

    echo "" >> "$SHELL_RC"
    echo "# lab-xapi wrapper for xAPI grade reporting" >> "$SHELL_RC"
    echo "$ALIAS_LINE" >> "$SHELL_RC"

    print_success "Alias added to $SHELL_RC"
}

# Main installation
main() {
    echo ""
    echo "========================================"
    echo "  lab-xapi Installer"
    echo "  xAPI Grade Reporting for Lab Command"
    echo "========================================"
    echo ""

    check_prereqs
    install_files
    configure_alias

    echo ""
    echo "========================================"
    echo -e "${GREEN}Installation complete!${NC}"
    echo "========================================"
    echo ""
    echo "To activate in your current shell, run:"
    echo ""
    echo -e "    ${BLUE}source ~/.bashrc${NC}"
    echo ""
    echo "Or open a new terminal."
    echo ""
    echo "When you first run 'lab start <slug>', you'll be"
    echo "prompted to enter your email for grade reporting."
    echo ""
    echo "Commands:"
    echo "    lab xapi-config show    # View config"
    echo "    lab xapi-config lrs     # Configure LRS"
    echo "    lab xapi-config help    # All options"
    echo ""
}

main "$@"
