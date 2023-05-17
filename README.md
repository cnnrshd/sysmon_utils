# sysmon_utils

## NOTICE - In Development

This library is still in development and subject to change. Some commands are a WIP, file and folder structure will be modified. Be sure to use `sysmon_utils --help` to get a list of all commands.

Utilities for working with and testing Sysmon configs against Windows Event Logs. Works in combination with my [atomic-datasets-utils](https://github.com/cnnrshd/atomic-datasets-utils) to support my [sysmon-modular](https://github.com/cnnrshd/sysmon-modular) work. My goal is to make it easier to modify, verify, and test Sysmon configs. Development is sponsored by my (Connor Shade) employer [QOMPLX](https://www.qomplx.com/).

## Commands

### atomictests

Checks for techniques found or overruled. Designed to run against the output of [atomic-datasets-utils](https://github.com/cnnrshd/atomic-datasets-utils) to test Sysmon Config functionality.

### emulate

Parses a provided log file as if it was just collected with the provided Sysmon config. Useful for determining the amount of "noise" you can remove from logs.

### merge

A better implementation of my [merge_sysmon_configs](https://github.com/cnnrshd/sysmon-modular/blob/3267eb11045491300bad32875e6022f01ea3dfa2/merge_sysmon_configs.py) script, originally designed for Sysmon-Modular. This merge script organizes rules by priority.

### overruled

Detects if an improperly-ordered rule overrules a specific pattern. I've seen this a lot with rules detecting PowerShell execution instead of focusing on what PowerShell was calling - it's more important to log `Image is malware` than `ParentImage is PowerShell`.

### secdatasets :construction: WIP

Runs through a local copy of [Security-Datasets](https://github.com/OTRF/Security-Datasets), parses the metadata files for techniques, then runs `verify` and `overruled` on each.

### techniques

Returns a list of techniques and their count in a provided Sysmon config. Useful for building a MITRE ATT&CK matrix.

### verify

Filters LOGFILE with CONFIG, look for PATTERN within any RuleNames that pass the input.
