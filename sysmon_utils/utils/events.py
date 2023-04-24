# Event lookup list - no hashing required.
EVENT_LOOKUP = [
    None,  # 0 (not a valid Event ID)
    "ProcessCreate",
    "FileCreateTime",
    "NetworkConnect",
    None,  # 4 (Sysmon service state change, cannot be filtered)
    "ProcessTerminate",
    "DriverLoad",
    "ImageLoad",
    "CreateRemoteThread",
    "RawAccessRead",
    "ProcessAccess",
    "FileCreate",
    "RegistryEvent",
    "RegistryEvent",
    "RegistryEvent",
    "FileCreateStreamHash",
    None,  # 16 (Sysmon configuration change, cannot be filtered)
    "PipeEvent",
    "PipeEvent",
    "WmiEvent",
    "WmiEvent",
    "WmiEvent",
    "DnsQuery",
    "FileDelete",
    "ClipboardChange",
    "ProcessTampering",
    "FileDeleteDetected",
    "FileBlockExecutable",
    "FileBlockShredding",
]
