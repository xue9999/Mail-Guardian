# Docker maintenance entrypoints

The scheduled implementation is [docker/updater.py](docker/updater.py), with
[its owning guide](docker/README.md). Shared libraries remain under
`auto-updates/docker`; their old experimental CLI is not the scheduled owner.
See [the dependency map](../../README.md) before moving/removing a module.
