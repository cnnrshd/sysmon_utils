import json
import logging
import os
import pathlib
import re
import zipfile
from dataclasses import dataclass, field
from enum import Enum

import yaml
from config import config
from rich.progress import Progress
from typer import Argument, BadParameter, FileText, FileTextWrite, Option, Typer
from utils.arg_definitions import OUTFILE, SYSMON_CONFIG, WEL_LOGFILE
from utils.events import EVENT_LOOKUP
from utils.rules import Rule, get_techniques, rule_generator

console = config.console
from utils.rules import extract_rules

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
    config: FileText = SYSMON_CONFIG,
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
        if event_id > len(EVENT_LOOKUP) - 1:
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
            event_id = event.get("EventID")
            if event_id > len(EVENT_LOOKUP) - 1:
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


class DatasetFileTypes(str, Enum):
    host = "Host"
    network = "Network"


@dataclass
class DatasetFile:
    github_link: str
    file_type: DatasetFileTypes
    local_path: pathlib.Path
    local_zip: pathlib.Path


# def _parse_dataset_file(f : dict[str, str]) -> DatasetFile:
#     """Parse the file object in a Security Dataset-formatted YAML file. Assumes that the dataset folder is
#     in the same location as the atomic folder.

#     Ex: ../Security-Datasets/datasets/atomic/_metadata/SDWIN-201018195009.yaml
#         ../Security-Datasets/master/datasets/atomic/windows/discovery/host/empire_shell_net_local_users.zip
#     Split
#     """
#     local_path =


@dataclass
class Dataset:
    metadata_path: pathlib.Path
    title: str
    files: list[DatasetFile] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)


def extract_json_file(zip_file_path, json_file_path):
    with zipfile.ZipFile(zip_file_path, "r") as zip_ref:
        for file in zip_ref.namelist():
            if file.endswith(".json") and not file.startswith("."):
                with zip_ref.open(file) as json_file:
                    with open(json_file_path, "wb") as output_file:
                        output_file.write(json_file.read())


@app.command(
    name="secdatasets",
    short_help=HELP_TEST_SECDATASETS,
    help="""Tests CONFIG against data from [Security-Datasets](https://securitydatasets.com/introduction.html).
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
):
    rules = extract_rules(config)
    target_techniques = set(get_techniques(rules).keys())
    console.print(f"Datasets: {datasets}")
    filtered_files = [
        file_path
        for file_path in datasets.iterdir()
        if path_filter_pattern.match(file_path.name)
    ]
    # console.print(filtered_files)
    # filter again for all that have the correct files
    working_datasets = []
    base_atomic_path = str(datasets).split("/atomic/")[0]
    for file_path in filtered_files:
        with open(file_path, mode="r") as f:
            dataset_dict = yaml.load(f, Loader=yaml.BaseLoader)
            # if any technique matches, grab the whole dataset
            techniques = [
                f"{mapping.get('technique')}{'.' + mapping.get('sub-technique') if mapping.get('sub-technique') else ''}"
                for mapping in dataset_dict.get("attack_mappings", [])
            ]
            if any(tech in target_techniques for tech in techniques):
                working_datasets.append(
                    {
                        "title": dataset_dict.get("title"),
                        "techniques": techniques,
                        "host_zip_paths": [
                            pathlib.Path(
                                base_atomic_path
                                + "/atomic/"
                                + f.get("link").split("/atomic/")[1]
                            )
                            for f in dataset_dict.get("files")
                            if f.get("type") == "Host"
                        ],
                        "host_json_paths": [
                            pathlib.Path(
                                base_atomic_path
                                + "/atomic/"
                                + f.get("link")
                                .split("/atomic/")[1]
                                .replace(".zip", ".json")
                            )
                            for f in dataset_dict.get("files")
                            if f.get("type") == "Host"
                        ],
                    }
                )

    files_to_unzip = []
    p = pathlib.Path
    p.exists
    for dataset in working_datasets:
        # check if the json exists - if it doesn't add the zip file to a list of files to unzip
        for json_path, zip_path in zip(
            dataset.get("host_json_paths"), dataset.get("host_zip_paths")
        ):
            if not json_path.exists():
                files_to_unzip.append(zip_path)
    with Progress(console=console) as progress:
        task = progress.add_task(
            description="Unzipping files...", total=len(files_to_unzip)
        )
        for zipped_file in files_to_unzip:
            extract_json_file(
                zipped_file, pathlib.Path(str(zipped_file).replace(".zip", ".json"))
            )
            progress.advance(task)
    # console.print(target_techniques)
    # all files are unzipped
    for dataset in working_datasets:
        for technique in dataset.get("techniques"):
            for json_path in dataset.get("host_json_paths"):
                try:
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
                except Exception as e:
                    console.print(f"ERROR PROCESSING DATASET {dataset} : {e}")
    # console.print(working_datasets)
