#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$PROJECT_ROOT/.venv"
REQUIREMENTS_FILE="$PROJECT_ROOT/src/requirements.txt"

if [[ ! -f "$REQUIREMENTS_FILE" ]]; then
  echo "Requirements file not found: $REQUIREMENTS_FILE" >&2
  exit 1
fi

if [[ ! -d "$VENV_DIR" ]]; then
  python3 -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

python -m pip install --upgrade pip
python -m pip install -r "$REQUIREMENTS_FILE"

echo
printf "✅ Environment ready.\n\n"
printf "Next steps:\n"
printf "1) Activate the virtual environment:\n   source %s/bin/activate\n" "$VENV_DIR"
printf "2) Run the script:\n   python %s/src/enginsight_tag_manager.py --help\n" "$PROJECT_ROOT"
