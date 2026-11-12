import argparse
import json
from pathlib import Path
from .core import audit

def main():
    parser=argparse.ArgumentParser(description="Conservative allowlist-driven IT inventory auditor")
    parser.add_argument("--config",default="/config/scope.json")
    parser.add_argument("--output",default="/output")
    parser.add_argument("--dry-run",action="store_true")
    args=parser.parse_args()
    scope=json.loads(Path(args.config).read_text(encoding="utf-8"))
    results=audit(scope,args.output,args.dry_run)
    print(json.dumps({"count":len(results),"dry_run":args.dry_run,"report_json":str(Path(args.output)/"report.json"),"report_markdown":str(Path(args.output)/"report.md")},ensure_ascii=False))
if __name__ == "__main__": main()
