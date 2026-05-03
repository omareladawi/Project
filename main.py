import sys
from pathlib import Path


project_root = Path(__file__).resolve().parent
src_path = project_root / "src"
sys.path.insert(0, str(src_path))


from web_scanner.main import run_scanner


if __name__ == "__main__":
    run_scanner()