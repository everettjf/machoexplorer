# C++ oracle

The golden baselines in `../baseline/` were produced by the last C++
implementation (release line `v2.0.x`). That code is no longer in the tree;
this directory keeps the one extra source file needed to rebuild the oracle
tool, `moex-dump`, from it.

`moex_dump_main.cpp` is a Qt-free command-line front end for the C++
`ViewNodeDumper` (the same code path as the old `MachOExplorer --cli`).

## Rebuilding the oracle

```bash
# 1. Check out the C++ tree (tag v2.0.17 or the commit before the removal).
git worktree add ../moex-cpp v2.0.17

# 2. Build moex-dump against libmoex, with Capstone enabled (Homebrew 5.0.x
#    was used for the checked-in baselines).
cd ../moex-cpp/src
clang++ -std=c++14 -O2 -w -I. -I/opt/homebrew/include -DMOEX_HAS_CAPSTONE=1 \
  $(find libmoex -name '*.cpp') \
  /path/to/this/repo/tests/golden/oracle/moex_dump_main.cpp \
  -L/opt/homebrew/lib -lcapstone -o /path/to/this/repo/build/moex-dump
```

Then `tests/golden/make_baseline.sh` regenerates the baselines and
`tests/golden/compare_live.py` runs differential comparisons on arbitrary
files. Both look for the oracle at `build/moex-dump` (override with
`MOEX_ORACLE`).
