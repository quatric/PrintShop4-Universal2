"""Set Finder icon positions in a volume's .DS_Store.

usage: dmg_layout.py <path/.DS_Store> "<name>=<x>,<y>" ...

Positions are icon centres in window points, as Finder stores them (Iloc).
Every other record (window size, background picture, view options) is kept.
"""
import sys

import ds_store.store
from ds_store import DSStore

# Only decode icon positions. Everything else (window bounds, view options and
# the background bookmark, which MacKiev's image stores in a form mac_alias
# rejects) is copied through as raw bytes.
for _code in list(ds_store.store.codecs):
    if _code != b"Iloc":
        del ds_store.store.codecs[_code]


def main():
    path, specs = sys.argv[1], sys.argv[2:]
    with DSStore.open(path, "r+") as d:
        for spec in specs:
            name, xy = spec.rsplit("=", 1)
            x, y = (int(v) for v in xy.split(","))
            d[name]["Iloc"] = (x, y)
            print(f"{name}: ({x}, {y})")


if __name__ == "__main__":
    main()
