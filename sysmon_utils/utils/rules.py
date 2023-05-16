# Definitions and functions for working with Sysmon rules
import logging
import pathlib
import re
from dataclasses import dataclass, field
from typing import Iterator

import lxml.etree

from .filters import Filter
from .filters import parse as parse_filter

_TECHNIQUE_PATTERN: re.Pattern = re.compile("technique_id=((?:T\d{4})(?:\.\d{3})?)")


@dataclass
class Rule:
    """Rule class - representation for Sysmon Rule

    filter_relation: str  - valid types are "or" and "and"
    event_type: str  - ex. ImageLoad, ProcessCreate
    onmatch: str  - include or exclude
    number: int  - tracks the order of rules
    name: str  - name of rule or filter
    filters: list[Filter] - list of Filter objects
    """

    filter_relation: str
    event_type: str
    onmatch: str
    number: int
    name: str
    filters: list[Filter] = field(default_factory=list)

    def passes(self, event: dict) -> bool:
        """A filter function that determines if a provided event would pass this rule
        Note that "passing" is relative. This means being included by an include and
        being excluded by an exclude.

        Args:
            event (dict): A dictionary representing a Sysmon event from Windows Event Logs

        Returns:
            bool: True if the event would pass the filter(s)
        """
        try:
            if self.filter_relation == "or":
                return any(f.passes(event) for f in self.filters)
            return all(f.passes(event) for f in self.filters)
        except TypeError as e:
            logging.error(
                f"Error with rule {self.name}:\n\tEvent:\t{event}\n\tRule:\t{self}"
            )


def rule_generator(rules: list[Rule], event: dict) -> Iterator[Rule]:
    """Simple generator that returns all matching rules

    Args:
        rules (list[Rule]): List of rules to test against. Can be include or exclude
        event (dict): A Sysmon event

    Yields:
        Iterator[Rule]: Iterator that generates passing rules.
    """
    for rule in rules:
        if rule.passes(event):
            yield rule


def extract_rules(config: pathlib.Path) -> dict[tuple, list[Rule]]:
    """Extracts sysmon rules, ensuring that they are numbered in order of precedence

    Args:
        config (FileText): A valid Sysmon Config

    Returns:
        dict: A dictionary with keys (EventType,FilterType) and values [Rule] - ex:
                {("CreateRemoteThread","include") : [Rule(filter_relation='or', event_type='CreateRemoteThread',
                    onmatch='include', number=1, filters=[Filter(field='SourceImage',
                    name='technique_id=T1055,technique_name=Process Injection', condition='begin with'
                    , value='C:\\')]]
                }
    """
    tree: lxml.etree.ElementTree = lxml.etree.parse(
        config,
        parser=lxml.etree.XMLParser(remove_blank_text=True, remove_comments=True),
    )
    rule_groups = tree.findall(".//RuleGroup")
    rules_dict = dict()
    for rule_group in rule_groups:
        for event in rule_group:
            onmatch = event.get("onmatch")
            event_type = event.tag
            rules = list()

            logging.debug(f"Working with {event_type} {onmatch}")
            for rule_number, filter in enumerate(event, start=1):
                if filter.tag == "Rule":
                    filter_name = filter.get("name", "")
                    logging.debug(f"\tDiscovered explicit rule {filter_name}")
                    sub_filters = list()
                    for subfilter in filter:
                        sub_filters.append(parse_filter(subfilter))
                    rule = Rule(
                        filter_relation=filter.get("groupRelation"),
                        event_type=event_type,
                        onmatch=onmatch,
                        number=rule_number,
                        name=filter_name,
                        filters=sub_filters,
                    )
                    logging.debug(f"\tFound rule: {rule}")
                else:
                    # implied rules have a groupRelation of or
                    filter_name = filter.get("name", "")
                    rule = Rule(
                        filter_relation="or",
                        event_type=event_type,
                        onmatch=onmatch,
                        number=rule_number,
                        name=filter_name,
                        filters=[parse_filter(filter)],
                    )
                    logging.debug(f"\tFound implied rule: {rule}")
                rules.append(rule)
            rules_dict[(event_type, onmatch)] = rules
    return rules_dict


def get_techniques(rules: dict[tuple, list[Rule]]) -> dict[str, int]:
    """Parses rules dictionary (output of extract_rules) for any *include* rules with a
    MITRE ATT&CK Technique ID in them

    Args:
        rules (Dict[tuple, list[Rule]]): Output of extract_rules function

    Returns:
        set[str]: Set of rules that exist in the config parsed by extract_rules
    """
    techniques = {}
    for event_subtype, rule_list in rules.items():
        if "include" in event_subtype:
            matches = [
                re.match(_TECHNIQUE_PATTERN, rule.name)
                for rule in rule_list
                if rule.name
            ]
            for match in matches:
                if match:
                    technique_name = match.group(1)
                    techniques[technique_name] = techniques.get(technique_name, 0) + 1

    return techniques
