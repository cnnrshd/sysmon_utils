from typer import Argument, FileText, FileTextWrite, Option

# Arguments/Options definitions


SYSMON_CONFIG: FileText = Argument(
    ..., help="Valid Sysmon Config to extract rules from"
)
WEL_LOGFILE: FileText = Argument(
    ...,
    help="JSONL of Windows Event Logs to test against, see "
    "[Security-Datasets](https://securitydatasets.com/introduction.html) for examples of valid JSONL files.",
)
OUTFILE: FileTextWrite = Option("-", help="File to output to.")
