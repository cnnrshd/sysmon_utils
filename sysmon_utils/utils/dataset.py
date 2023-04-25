# Definitions and functions for the datasets command
import pathlib
import re
import tarfile
import zipfile
from typing import Union

import yaml


def _valid_host_file(filename: str) -> bool:
    if filename.startswith("."):
        return False
    elif "MACOS" in filename:
        return False
    elif "/" in filename:
        return False
    elif filename.endswith(".json"):
        return True
    else:
        return False


def extract_json_file(archive_file_path: pathlib.Path, json_file_path: pathlib.Path):
    if str(archive_file_path).endswith(".tar.gz"):
        with tarfile.open(archive_file_path, "r:gz") as tar_ref:
            for file in tar_ref.getmembers():
                if _valid_host_file(file.name):
                    with open(json_file_path, mode="wb") as json_file:
                        json_file.write(tar_ref.extractfile(file).read())
    elif str(archive_file_path).endswith(".zip"):
        with zipfile.ZipFile(archive_file_path, "r") as zip_ref:
            for file in zip_ref.namelist():
                if _valid_host_file(file):
                    with zip_ref.open(file) as json_file:
                        with open(json_file_path, "wb") as output_file:
                            output_file.write(json_file.read())
    else:
        raise ValueError(f"Unsupported archive format for path {archive_file_path}")


def filter_files_by_pattern(
    datasets: pathlib.Path, path_filter_pattern: re.Pattern
) -> list[pathlib.Path]:
    """Iterates through the datasets directory and returns every file that matches the provided pattern

    Args:
        datasets (pathlib.Path): Directory to check for files
        path_filter_pattern (re.Pattern): Filter to apply to patterns

    Returns:
        list[pathlib.Path]: List of paths that pass the pattern
    """
    return [
        file_path
        for file_path in datasets.iterdir()
        if path_filter_pattern.match(file_path.name)
    ]


def get_working_datasets(
    filepaths: list[pathlib.Path],
    target_techniques: set[str],
    base_atomic_path: str,
) -> list[dict[str, Union[str, pathlib.Path, list[str], list[pathlib.Path]]]]:
    working_datasets = []
    for file_path in filepaths:
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
                            if f.get("type") == "Host" and "host" in f.get("link")
                        ],
                        "host_json_paths": [
                            pathlib.Path(
                                base_atomic_path
                                + "/atomic/"
                                + f.get("link")
                                .split("/atomic/")[1]
                                .replace(".zip", ".json")  # find a better method
                                .replace(".tar.gz", ".json")
                            )
                            for f in dataset_dict.get("files")
                            if f.get("type") == "Host" and "host" in f.get("link")
                        ],
                    }
                )
    return working_datasets
