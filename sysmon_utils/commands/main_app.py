import json
import os
import pathlib
import re
from dataclasses import asdict, dataclass
from enum import Enum

from sysmon_utils.config import config
from lxml import etree
from rich.progress import Progress
from typer import Argument, BadParameter, FileText, FileTextWrite, Option, Typer
from sysmon_utils.utils.arg_definitions import OUTFILE, SYSMON_CONFIG, WEL_LOGFILE
from sysmon_utils.utils.dataset import (
    extract_json_file,
    filter_files_by_pattern,
    get_working_datasets,
)
from sysmon_utils.utils.events import EVENT_LOOKUP
from sysmon_utils.utils.merge import (
    detect_file_format,
    merge_sysmon_configs,
    merge_with_base_config,
    read_file_list,
)
from sysmon_utils.utils.rules import Rule, extract_rules, get_techniques, rule_generator

console = config.console
DEBUG = config.debug

app = Typer(
    rich_markup_mode="markdown",
)

# TODO: Move the FileText -> Path
# TODO: generalize the verify -> overruled -> print chunks, make it a function


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


def _get_event(line: str) -> dict:
    """Helper function to extract event details from a JSON string and return a dict"""
    event = json.loads(line)
    if isinstance(event, str):
        raise ValueError("Improper conversion - JSON returned string")
    return event


def _valid_sysmon_event(event: dict) -> bool:
    """Helper function to determine if a Windows Event is Sysmon."""
    if event.get("EventSourceName") != "Microsoft-Windows-Sysmon":
        return False
    if event.get("EventID", 100) > len(EVENT_LOOKUP) - 1:
        return False
    return True


#########
# Emulate
#########

HELP_EMULATE = (
    "Run LOGS against CONFIG returning filtered and tagged logs"
)


@app.command(name="emulate", short_help=HELP_EMULATE)
def emulate(
    config: pathlib.Path = SYSMON_CONFIG,
    logfile: pathlib.Path = WEL_LOGFILE,
    outfile: FileTextWrite = OUTFILE,
):
    """Emulate - Runs LOGS through CONFIG, setting rule names and excluding/including
    data as Sysmon would. Suggested use case is for comparing raw Sysmon Event Log sizes
    to filtered sizes for an idea of how many events can be excluded.
    
    Example: sysmon_utils emulate sysmon_config.xml atomic-redteam-t1003-01.json --outfile filtered-t1003-01.json"""
    rules = extract_rules(config)
    if DEBUG:
        console.print(f"Opening logfile {logfile}")
    with open(logfile, mode="r") as f:
        for line in f:
            event = _get_event(line)
            # filter
            event_id = event.get("EventID")
            if not _valid_sysmon_event(event):
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


############
# Techniques
############


class TechniquesOutputFormat(str, Enum):
    json = "json"
    terminal = "terminal"


_TECHNIQUES_OUTPUT_FORMAT: TechniquesOutputFormat = Option(
    TechniquesOutputFormat.json, help="Output format style."
)

HELP_TECHNIQUES = "Return techniques and their count from provided CONFIG. Useful for building an ATT&CK Matrix."


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


HELP_VERIFY = "Parse LOGFILE with CONFIG, determine if PATTERN is found in any rule that passes the CONFIG filter."


def verify(
    rules: dict[tuple, list[Rule]],
    logfile: pathlib.Path,
    pattern: re.Pattern,
    method: VerifyMethod = VerifyMethod.boolean,
) -> int:
    """Returns the number of times PATTERN is found in the provided logfile.
    If VerifyMethod is boolean or exitcode, it will return on first match"""
    match_count = 0
    with open(logfile, mode="r") as f:
        for line in f:
            try:
                event = _get_event(line)
            except ValueError as e:
                # console.stderr = True
                console.print(f"Error with logfile {logfile}")
                continue
            if not _valid_sysmon_event(event):
                continue
            event_type = EVENT_LOOKUP[event.get("EventID", 0)]
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
def entry_verify(
    config: pathlib.Path = SYSMON_CONFIG,
    outfile: FileTextWrite = OUTFILE,
    logfile: pathlib.Path = WEL_LOGFILE,
    pattern: str = Argument(
        ...,
        callback=validate_regex,
        help="""A valid regular expression. If targeting a specific technique_id, try `.*TXXXX.*`, where TXXXX is replaced by the
         technique ID. Some shells might interpret your wildcards as a glob, use debug or auto-wildcard options if there's an issue.""",
    ),
    verify_method: VerifyMethod = Option(
        VerifyMethod.count,
        help=f"""How to check for the technique. {VerifyMethod.exitcode} and {VerifyMethod.boolean} will exit as soon as a hit 
        is found. **{VerifyMethod.exitcode}** will return 0 if found, 1 if not found (found is seen as success/normal operation
        , return is in the exit code) while **{VerifyMethod.boolean}** returns 0 if not found, 1 if found, return is printed 
        to outfile - essentially **{VerifyMethod.count}** with a max of 1. 
        **{VerifyMethod.count}** returns the count of hits, and parses the entire log file.""",
    ),
    wildcard_pattern: bool = Option(
        False,
        help="Wraps the provided pattern in wildcard characters. Useful when dealing with shell escapes.",
    ),
):
    """verify - Parses LOGFILE with CONFIG as Sysmon would (similar to `emulate`) and returns if
    PATTERN has been found in any non-excluded events."""
    if DEBUG:
        console.print(f"Working with pattern: {pattern.pattern}")
    if wildcard_pattern:
        pattern = re.compile(pattern=f".*{pattern.pattern}.*")
        if DEBUG:
            console.print(f"Pattern has been wild-carded to {pattern.pattern}")
    rules = extract_rules(config)
    code = verify(rules, logfile, pattern, verify_method)
    if verify_method == VerifyMethod.exitcode:
        if code == 1:
            exit(0)
        exit(1)
    else:
        outfile.write(str(code))


#########
# Overlap
#########

HELP_OVERLAP = "Returns any logs and rules where a PATTERN matching rule is hit AFTER a non-matching rule."


@dataclass
class OverruledReturn:
    event: dict
    overrules: list[Rule]
    hit_rule: Rule
    exclude_rule: Rule


def overruled(
    rules: dict[tuple, list[Rule]],
    logfile: pathlib.Path,
    pattern: re.Pattern,
):
    with open(logfile, mode="r") as f:
        for line in f:
            event = _get_event(line)
            if not _valid_sysmon_event(event):
                continue
            event_type = EVENT_LOOKUP[event.get("EventID", 0)]
            try:
                overrules = []
                exclude_rule = None
                goal_rule = None
                include_rules: list[Rule] = rules[(event_type, "include")]
                # grab all matching rules
                if matching_rules := list(
                    rule for rule in rule_generator(include_rules, event)
                ):
                    # check if any have a key name
                    pattern_matching_rules_mask = list(
                        bool(pattern.match(r.name)) for r in matching_rules
                    )
                    if any(pattern_matching_rules_mask):
                        # if it's the first, continue. If it's not the first, add all overrules to a list
                        for i, m in enumerate(pattern_matching_rules_mask):
                            if not m:
                                overrules.append(matching_rules[i])
                            if m:
                                goal_rule = m
                                break
                        # check excludes
                        try:
                            exclude_rules = rules[(event_type, "exclude")]
                            if first_matching_rule := next(
                                (rule for rule in rule_generator(exclude_rules, event)),
                                None,
                            ):
                                exclude_rule = first_matching_rule
                        except KeyError:  # no excludes for this event
                            pass
                        if overrules or exclude_rule:
                            return OverruledReturn(
                                event, overrules, goal_rule, exclude_rule
                            )
                    else:
                        continue
            except KeyError:  # No includes for this event type
                continue
    return None


@app.command(name="overruled", short_help=HELP_OVERLAP)
def entry_overruled(
    config: pathlib.Path = SYSMON_CONFIG,
    logfile: pathlib.Path = WEL_LOGFILE,
    outfile: FileTextWrite = OUTFILE,
    pattern: str = Option(".*(technique_id=T\d{4}).*", callback=validate_regex),
    wildcard_pattern: bool = Option(
        False,
        help="Wraps the provided pattern in wildcard characters. Useful when dealing with shell escapes.",
    ),

):
    """Runs LOGS against CONFIG and searches for areas where a specified PATTERN (Defaulting to regex for 
    MITRE ATT&CK Technique IDs) is hit AFTER a rule that does not match the pattern
    """
    # console.print(pattern)
    rules = extract_rules(config)
    if wildcard_pattern:
        pattern = re.compile(pattern=f".*{pattern.pattern}.*")
    overruled_ret: OverruledReturn = overruled(
                    rules, logfile, pattern
                )
    if overruled_ret.hit_rule:
        console.print(f"[green]FOUND pattern {pattern} in {logfile}")
        for r in overruled_ret.overrules:
            console.print(f"[red]OVERRULED by {asdict(r)}")
        if overruled_ret.exclude_rule:
            console.print(f"[red]EXCLUDED by {asdict(overruled_ret.hit_rule)}")
    else:
        console.print(f"[red]MISSING pattern {pattern} in {logfile}")


######
# Test
######


HELP_TEST_SECDATASETS = ":construction: WIP :construction: Tts CONFIG against data from [Security-Datasets](https://securitydatasets.com/introduction.html) Datasets"


@app.command(
    name="secdatasets",
    short_help=HELP_TEST_SECDATASETS,
    help=""":construction: WIP :construction: Tests CONFIG against data from [Security-Datasets](https://securitydatasets.com/introduction.html).
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
                    # TODO: First check verify - if false, check overlap
                    match_count = verify(
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

HELP_MERGE = "Merge the provided baseconfig with config files."


@app.command(
    name="merge",
    short_help=HELP_MERGE,
    help="""
Merge multiple Sysmon configuration files based on their priority - highest at top. configlist should contain two columns, `filepath` and `priority`

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


@app.command(
    name="atomictests",
    short_help="Checks for techniques found or overruled. Used for testing configs.",
    help="""
Run against the directory of my [auto_art_collection](https://github.com/cnnrshd/atomic-datasets-utils#auto_art_collectionps1) tool.
Iterates through the provided directory, looks for status files, extracts all "successful" tests. For each test:
1. Extracts the technique being tested
2. Runs the logs against the Sysmon config, looking to validate the technique
3. If technique is not found, checks for overlaps
4. Outputs data on techniques tested, test numbers, whether an event was detected or overruled.
Calls `verify` and `overruled` functions.""",
)
def atomictests(
    config: pathlib.Path = SYSMON_CONFIG,
    successful_tests: pathlib.Path = Argument(
        ..., help="Path to the successful_tests.json file"
    ),
):
    rules = extract_rules(config)
    with open(successful_tests, mode="r") as f:
        tests_list = json.load(f)
    list_detected = []
    list_missing = []
    list_overruled = []
    list_excluded = []
    with Progress(console=console) as progress:
        task = progress.add_task(
            description="Checking for techniques in files...", total=len(tests_list)
        )
        for test in tests_list:
            working_log_file = next(
                (
                    f"{test['FilePath']}{l}"
                    for l in os.listdir(test["FilePath"])
                    if "logs_" in l
                ),
                None,
            )
            if working_log_file is None:
                console.print(
                    f"[red]Missing log file for filepath {test['FilePath']}, skipping"
                )
                continue
            working_pattern = re.compile(pattern=f".*{test['Technique']}.*")
            hit_count = verify(
                rules, working_log_file, working_pattern, VerifyMethod.boolean
            )
            if not hit_count:
                console.print(
                    f"[yellow]NOT FOUND {test['Technique']} Test {test['TestNumber']} - checking overruled"
                )
                overruled_ret: OverruledReturn = overruled(
                    rules, working_log_file, working_pattern
                )
                if overruled_ret:
                    if overruled_ret.overrules:
                        # list_overruled.append({"TestNumber" : test["TestNumber"], "event" : overruled_ret.event, "overruled_ret" : overruled_ret})
                        console.print(
                            f"[orange]OVERRULED {test['Technique']} Test {test['TestNumber']} in {working_log_file}"
                        )
                        console.print("OVERRULING RULES:")
                        console.print_json(
                            json.dumps([asdict(r) for r in overruled_ret.overrules])
                        )
                        console.print("EVENT")
                        console.print_json(json.dumps(overruled_ret.event))
                    elif overruled_ret.exclude_rule:
                        # list_excluded.append({"TestNumber" : test["TestNumber"], "event" : overruled_ret.event, "overruled_ret" : overruled_ret})
                        console.print(
                            f"[orange]EXCLUDED {test['Technique']} Test {test['TestNumber']} in {working_log_file}"
                        )
                        console.print("EXCLUDE RULE:")
                        console.print_json(
                            json.dumps(asdict(overruled_ret.exclude_rule))
                        )
                        console.print("EVENT")
                        console.print_json(json.dumps(overruled_ret.event))
                else:
                    # list_missing.append(test["TestNumber"])
                    console.print(
                        f"[red]MISSING {test['Technique']} Test {test['TestNumber']} in {working_log_file}"
                    )
            else:
                # list_detected.append(test["TestNumber"])
                console.print(
                    f"[blue]FOUND {test['Technique']} Test {test['TestNumber']} in {working_log_file}"
                )
            progress.advance(task)
    # make a markdown doc
