# functions used for the merge command
import csv
import logging
import os
import pathlib
from typing import Union

import packaging.version
from lxml import etree


def detect_file_format(file_path: str) -> str:
    """
    Detect file format based on file extension.

    Args:
        file_path: Path to the input file.

    Returns:
        Detected file format (tsv, csv, or json).
    """
    _, ext = os.path.splitext(file_path)
    file_format = ext[1:].lower()
    if file_format not in ["tsv", "csv"]:
        logging.exception(f"Received file format {file_format}")
        raise ValueError("Unsupported file format")
    return file_format


def read_file_list(
    file_path: str, file_format: str, base_dir: pathlib.Path
) -> list[dict[str, Union[str, int]]]:
    """
    Read a file containing filepaths and priorities in TSV, CSV, or JSON format.

    Args:
        file_path: Path to the input file.
        file_format: Format of the input file (tsv, csv, or json).
        base_dir: Path to prepend to all filepaths

    Returns:
        A list of dictionaries containing filepaths and priorities.
    """
    file_list = []
    if file_format == "tsv":
        logging.info(f"Reading file {file_path} as 'tsv'")
        with open(file_path, "r") as file:
            reader = csv.DictReader(file, delimiter="\t")
            file_list = [row for row in reader]
    elif file_format == "csv":
        logging.info(f"Reading file {file_path} as 'csv'")
        with open(file_path, "r") as file:
            reader = csv.DictReader(file)
            file_list = [row for row in reader]
    logging.info(f"Detected {len(file_list)} items in {file_path}")
    for d in file_list:
        d["filepath"] = str(base_dir / pathlib.Path(d["filepath"]))
    return file_list


def merge_sysmon_configs(
    file_list: list[dict[str, Union[str, int]]], force_grouprelation_or: bool
) -> etree.Element:
    """
    Merge Sysmon config files based on their type, subtype, and priority.

    Args:
        file_list: A list of dictionaries containing filepaths and priorities.

    Returns:
        An lxml.etree.Element representing the merged Sysmon configuration.
    """
    merged_sysmon = etree.Element("Sysmon")
    merged_event_filtering = etree.SubElement(merged_sysmon, "EventFiltering")
    event_dict: dict[tuple[str, str], etree.Element] = {}
    versions_set = set()

    for file_info in sorted(file_list, key=lambda x: int(x["priority"]), reverse=True):
        logging.debug(f"Working with {file_info}")
        file_path = file_info["filepath"]
        if pathlib.Path(file_path).is_file():
            tree = etree.parse(
                file_path, parser=etree.XMLParser(remove_blank_text=True)
            )
            # grab schema version
            version = tree.getroot().get("schemaversion")
            try:
                versions_set.add(packaging.version.parse(version))
            except Exception as e:
                logging.exception(
                    f"Error parsing version {version} in file {file_path}, skipping file"
                )
                continue
            rule_group = tree.find(".//RuleGroup")
            if force_grouprelation_or:
                rule_group.set("groupRelation", "or")
            for event in rule_group:
                event_type = event.tag
                onmatch = event.get("onmatch")
                key = (event_type, onmatch)

                if key not in event_dict:
                    event_dict[key] = event
                    merged_event_filtering.append(rule_group)
                else:
                    for child in event:
                        event_dict[key].append(child)
        else:
            logging.warning(f"Provided invalid path {file_path}, will not be merged")

    versions_list = list(versions_set)
    versions_list.sort(reverse=True)
    logging.debug(
        f"Versions found across all files: {[str(vers) for vers in versions_list]}"
    )
    merged_sysmon.set("schemaversion", str(versions_list[0]))

    return merged_sysmon


def merge_with_base_config(
    merged_sysmon: etree.Element, base_config_file: str
) -> etree.Element:
    """
    Merge the base config with the merged Sysmon configurations.

    Args:
        merged_sysmon: Merged Sysmon configurations.
        base_config_file: Path to the base config file.

    Returns:
        Merged Sysmon configurations with the base config.
    """
    base_tree = etree.parse(
        base_config_file, parser=etree.XMLParser(remove_blank_text=True)
    )
    base_root = base_tree.getroot()
    base_event_filtering = base_root.find("EventFiltering")

    if base_event_filtering is not None:
        base_root.remove(base_event_filtering)

    new_event_filtering = etree.Element("EventFiltering")
    for rule_group in merged_sysmon.findall("EventFiltering/RuleGroup"):
        new_event_filtering.append(rule_group)

    base_root.set("schemaversion", merged_sysmon.get("schemaversion"))

    base_root.append(new_event_filtering)

    return base_root
