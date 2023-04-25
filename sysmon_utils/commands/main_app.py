import json
import pathlib
import pdb
import re
from enum import Enum

from config import config
from lxml import etree
from rich.progress import Progress
from typer import Argument, BadParameter, FileText, FileTextWrite, Option, Typer
from utils.arg_definitions import OUTFILE, SYSMON_CONFIG, WEL_LOGFILE
from utils.dataset import (
    extract_json_file,
    filter_files_by_pattern,
    get_working_datasets,
)
from utils.events import EVENT_LOOKUP
from utils.merge import (
    detect_file_format,
    merge_sysmon_configs,
    merge_with_base_config,
    read_file_list,
)
from utils.rules import Rule, extract_rules, get_techniques, rule_generator

console = config.console

app = Typer(
    rich_markup_mode="markdown",
)

# TODO: Move the FileText -> Path


def validate_regex(value: str) -> re.Pattern:
    """Callback used to validate that a provided value is a valid Regex pattern"""
    try:
        pattern = re.compile(value)
        return pattern
    except Exception as e:
        raise BadParameter("Provided Pattern does not compile.")


def validate_directory(value: str) -> pathlib.Path:
    """Callback used to validate that a provided value is a path"""
    path = pathlib.Path(value)
    if path.is_dir():
        return path
    raise BadParameter(f"Invalid directory value {value}")


#########
# Emulate
#########

HELP_EMULATE = (
    ":construction: Run LOGS against CONFIG returning filtered and tagged logs"
)


@app.command(name="emulate", short_help=HELP_EMULATE)
def emulate(
    config: pathlib.Path = SYSMON_CONFIG,
    logfile: FileText = WEL_LOGFILE,
    outfile: FileTextWrite = OUTFILE,
):
    """:construction: WIP :construction: Entered emulate main - this section is WIP

    Longer-form help goes here i think"""
    rules = extract_rules(config)
    for line in logfile:
        event = json.loads(line)
        # filter
        event_id = event.get("EventID")
        # TODO: Fix the lookup - also check for SourceName Sysmon
        if (event_id > len(EVENT_LOOKUP) - 1) or (
            event.get("SourceName") != "Microsoft-Windows-Sysmon"
        ):
            continue
        event_type = EVENT_LOOKUP[event_id]
        # check includes
        try:
            include_rules: list[Rule] = rules[(event_type, "include")]
            if first_matching_rule := next(
                (rule for rule in rule_generator(include_rules, event)), None
            ):
                event["RuleName"] = first_matching_rule.name
            else:
                continue
        except KeyError:  # No includes for this event type
            continue
        # check excludes
        try:
            exclude_rules = rules[(event_type, "exclude")]
            if first_matching_rule := next(
                (rule for rule in rule_generator(exclude_rules, event)), None
            ):
                # it is excluded
                continue
        except KeyError:
            pass

        outfile.write(
            json.dumps(
                event,
                indent=None,
            )
            + "\n"
        )
    pass


############
# Techniques
############


class TechniquesOutputFormat(str, Enum):
    json = "json"
    terminal = "terminal"


_TECHNIQUES_OUTPUT_FORMAT: TechniquesOutputFormat = Option(
    TechniquesOutputFormat.json, help="Output format style."
)

HELP_TECHNIQUES = "Return techniques and their count from provided CONFIG."


@app.command(
    name="techniques",
    short_help=HELP_TECHNIQUES,
    help="Extract all references of MITRE ATT&CK Techniques from provided CONFIG - only checks Rule and Filter names. Does not parse comments.",
)
def techniques(
    config: FileText = SYSMON_CONFIG,
    outfile: FileTextWrite = OUTFILE,
    outformat: TechniquesOutputFormat = _TECHNIQUES_OUTPUT_FORMAT,
):
    """Extract all references of MITRE ATT&CK Techniques from provided CONFIG - only checks Rule and Filter names. Does not parse comments.

    Args:
        config (FileText, optional): Config file to parse
        outfile (FileTextWrite, optional): File to write to, defaults to stdout
        outformat (OutputFormat, optional): Output format, defaults to JSON

    Example JSON output:
        [ {"techniqueID": "T1036", "score": 66}, {"techniqueID": "T1059", "score": 12} ]
    """
    rules = extract_rules(config)
    techs = get_techniques(rules)
    if outformat == TechniquesOutputFormat.json:
        output = [{"techniqueID": k, "score": v} for k, v in techs.items()]
        output.sort(key=(lambda x: x.get("score")), reverse=True)
        output = json.dumps(output, indent=2)
    elif outformat == TechniquesOutputFormat.terminal:
        output = "\n".join([f"{score}\t{tid}" for tid, score in techs.items()])
    outfile.write(output)


########
# Verify
########


class VerifyMethod(str, Enum):
    boolean = "boolean"
    count = "count"
    exitcode = "exitcode"


class VerifyOutputFormat(str, Enum):
    json = "json"
    terminal = "terminal"


_VERIFY_OUTPUT_FORMAT: VerifyOutputFormat = Option(
    VerifyOutputFormat.terminal, help="Output format style."
)

HELP_VERIFY = ":construction: Parse LOGFILE with CONFIG, determine if PATTERN is found in any rule that passes the CONFIG filter."


def true_verify(
    rules,
    logfile: pathlib.Path,
    pattern: re.Pattern,
    method: VerifyMethod = VerifyMethod.boolean,
) -> int:
    """Returns the number of times PATTERN is found in the provided logfile.
    If VerifyMethod is boolean or exitcode, it will return on first match"""
    match_count = 0
    with open(logfile, mode="r") as f:
        for line in f:
            event = json.loads(line)
            event_id = event.get("EventID", 0)
            if 0 < event_id > len(EVENT_LOOKUP) - 1 or (
                event.get("SourceName") != "Microsoft-Windows-Sysmon"
            ):
                continue
            event_type = EVENT_LOOKUP[event_id]
            try:
                include_rules: list[Rule] = rules[(event_type, "include")]
                if first_matching_rule := next(
                    (rule for rule in rule_generator(include_rules, event)), None
                ):
                    event["RuleName"] = first_matching_rule.name
                else:
                    continue
            except KeyError:  # No includes for this event type
                continue
            # check excludes
            try:
                exclude_rules = rules[(event_type, "exclude")]
                if first_matching_rule := next(
                    (rule for rule in rule_generator(exclude_rules, event)), None
                ):
                    # it is excluded
                    continue
            except KeyError:  # no excludes for this event
                pass
            # check for pattern
            if pattern.match(event["RuleName"]):
                match_count += 1
            if (
                method == VerifyMethod.boolean or method == VerifyMethod.exitcode
            ) and match_count > 0:
                return match_count
        return match_count


@app.command(name="verify", short_help=HELP_VERIFY)
def verify(
    config: FileText = SYSMON_CONFIG,
    outfile: FileTextWrite = OUTFILE,
    outformat: VerifyOutputFormat = _VERIFY_OUTPUT_FORMAT,
    logfile: FileText = WEL_LOGFILE,
):
    pass


#########
# Overlap
#########

HELP_OVERLAP = ":construction: Returns any logs and rules where a PATTERN matching rule is hit AFTER a non-matching rule."


@app.command(name="overlap", short_help=HELP_OVERLAP)
def overlap(
    config: FileText = SYSMON_CONFIG,
    logfile: FileText = WEL_LOGFILE,
    outfile: FileTextWrite = OUTFILE,
    pattern: str = Option(".*(technique_id=T\d{4}).*", callback=validate_regex),
):
    """Runs LOGS against CONFIG and searches for areas where a specified PATTERN (Defaulting to regex for MITRE ATT&CK Technique IDs) is hit AFTER a rule that does not match the pattern
    Expected output would be:
        LOG Line 5 OVERLAP:
            #1  PowerShell DragNet
            #2  Invoke-Mimikatz
    """
    console.print(pattern)
    for line in config:
        if match := pattern.match(line):
            console.print(f"Match found: {match}")
    pass


######
# Test
######


HELP_TEST_SECDATASETS = ":construction: Tests CONFIG against data from [Security-Datasets](https://securitydatasets.com/introduction.html) Datasets"


@app.command(
    name="secdatasets",
    short_help=HELP_TEST_SECDATASETS,
    help="""Tests CONFIG against data from [Security-Datasets](https://securitydatasets.com/introduction.html).
    Be sure to specify outfile
    This will essentially run `verify` against each matching dataset.
    First, this extracts rules from CONFIG. Then it parses the `SD-WIN*` metadata files in the **dataset** path.
    It determines which datasets to test against based on technique names found in CONFIG.
    Once the datasets are identified, the program will verify coverage of each technique with the dataset.
    """,
)
def secdatasets(
    config: FileText = SYSMON_CONFIG,
    datasets: pathlib.Path = Argument(
        ...,
        help="Path to Security-Datasets _metadata folder, example is `./Security-Datasets/datasets/atomic/_metadata/` if running from the current directory",
        callback=validate_directory,
    ),
    outfile: FileTextWrite = OUTFILE,
    path_filter_pattern: str = Option(
        "SDWIN.*",
        callback=validate_regex,
        help="A filter to run against files in the **datasets** directory. Defaults to the SecurityDatasets convention for Windows.",
    ),
    status_to_stderr: bool = Option(
        True,
        help="Output status messages, like progress bar, to stderr. Useful for redirecting stdout output to other files. Set to false and give a separate outfile for pretty printing.",
    ),
):
    rules = extract_rules(config)
    target_techniques = set(get_techniques(rules).keys())
    console.stderr = status_to_stderr
    console.print(f"Datasets: {datasets}")

    filtered_files = filter_files_by_pattern(datasets, path_filter_pattern)
    # filter again for all that have the correct files

    base_atomic_path = str(datasets).split("/atomic/")[0]

    working_datasets = get_working_datasets(
        filtered_files, target_techniques, base_atomic_path
    )
    # check files
    with Progress(console=console) as progress:
        task = progress.add_task(
            description="Checking that JSON files exist...", total=len(working_datasets)
        )
        for dataset in working_datasets:
            for json_path, zip_path in zip(
                dataset.get("host_json_paths"), dataset.get("host_zip_paths")
            ):
                if not json_path.exists():
                    console.print(f"Found missing JSON {json_path}")
                    extract_json_file(zip_path, json_path)
                progress.advance(task)
    dataset_tests = []
    with Progress(console=console) as progress:
        task = progress.add_task(
            description="Testing against datasets...", total=len(working_datasets)
        )
        for dataset in working_datasets:
            test = {"dataset": dataset["title"], "techniques": []}
            for technique in dataset.get("techniques"):
                # test["techniques"] = technique
                temp_technique = {"technique_id": technique, "matches": 0, "files": []}
                for json_path in dataset.get("host_json_paths"):
                    match_count = true_verify(
                        rules,
                        json_path,
                        re.compile(f".*{technique}.*"),
                        method=VerifyMethod.count,
                    )
                    if match_count < 1:
                        console.print(
                            f":exclamation: Found 0 hits for {technique} in {dataset.get('title')}"
                        )
                    else:
                        console.print(
                            f"Found {match_count} hits for {technique} in {dataset.get('title')}"
                        )
                    temp_technique["files"].append(
                        {"filename": str(json_path), "matches": match_count}
                    )
                    temp_technique["matches"] += match_count
                test["techniques"].append(temp_technique)
            dataset_tests.append(test)
            progress.advance(task)
    outfile.write(json.dumps(dataset_tests, indent=2))


#######
# Merge
#######

HELP_MERGE = ":construction: Merge the provided baseconfig with config files."


@app.command(
    name="merge",
    short_help=HELP_MERGE,
    help="""
:construction:Merge multiple Sysmon configuration files based on their priority - highest at top. configlist should contain two columns, `filepath` and `priority`

Slightly modified implementation of [merge_sysmon_configs.py](https://github.com/cnnrshd/sysmon-modular/blob/bfa7ad51e21b02ae6bc0ec0705969641567e4b48/merge_sysmon_configs.py)
""",
)
def merge(
    baseconfig: pathlib.Path = Argument(
        ...,
        help="Base config - template that other configs are merged into. Use for banners or top-level Sysmon options",
    ),
    configlist: pathlib.Path = Argument(
        ..., help="CSV/TSV that holds columns of filepath and priority"
    ),
    outfile: FileTextWrite = OUTFILE,
    force_grouprelation_or: bool = Option(
        True,
        help="Force GroupRelation setting to 'or', helpful for incorrectly-formatted xml files.",
    ),
    base_dir: pathlib.Path = Option(
        "./", help="Base directory prepended to all filepaths in the configlist"
    ),
):
    file_list = read_file_list(configlist, detect_file_format(configlist), base_dir)
    merged_sysmon = merge_sysmon_configs(file_list, force_grouprelation_or)
    full_sysmon_config = merge_with_base_config(merged_sysmon, baseconfig)
    outfile.write(etree.tostring(full_sysmon_config, pretty_print=True).decode())
