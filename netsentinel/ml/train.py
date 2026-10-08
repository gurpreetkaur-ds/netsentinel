"""Training entry point:  python -m netsentinel.ml.train v0"""

import argparse
import logging
import sys

from .data import ROOT


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="netsentinel.ml.train")
    p.add_argument("version", choices=["v0", "v1", "v2"])
    p.add_argument("--n-jobs", type=int, default=-1)
    p.add_argument("--skip-e2", action="store_true", help="v1: skip the leave-one-family-out evaluation")
    a = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    if a.version == "v0":
        from . import baseline_v0
        baseline_v0.run(ROOT / "artifacts" / "v0", n_jobs=a.n_jobs)
    elif a.version == "v1":
        from . import train_v1
        train_v1.run(ROOT / "artifacts" / "v1", skip_e2=a.skip_e2)
    elif a.version == "v2":
        from . import train_v2
        train_v2.run(ROOT / "artifacts" / "v2", skip_e2=a.skip_e2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
