# Definitions and functions for a Sysmon Filter
from dataclasses import dataclass

from lxml.etree import Element


@dataclass
class Filter:
    """Representation of a Sysmon Filter

    field: str - Image - used for lookup
    name: str  - Extracted from a filter name or empty "technique_id=T1055"
    condition: str - the comparison function to use "begin with"
    value: str  - what is filtered, ex. "C:\Temp"

    Raises:
        ValueError: On invalid condition

    """

    field: str
    name: str
    condition: str
    value: str

    def passes(self, event: dict) -> bool:
        # event is a dict holding Sysmon event field and values
        # name is not needed
        # condition changes logic
        if self.condition == "is":
            return event.get(self.field) == self.value
        elif self.condition == "is any":
            return event.get(self.field) in self.value.split(";")
        elif self.condition == "is not":
            return not (event.get(self.field) == self.value)
        elif self.condition == "contains":
            return self.value in event.get(self.field)
        elif self.condition == "contains any":
            return any(val in event.get(self.field) for val in self.value.split(";"))
        elif self.condition == "contains all":
            return all(val in event.get(self.field) for val in self.value.split(";"))
        elif self.condition == "excludes":
            return self.value not in event.get(self.field)
        elif self.condition == "excludes any":
            return not any(
                val in event.get(self.field) for val in self.value.split(";")
            )
        elif self.condition == "excludes all":
            return all(
                val not in event.get(self.field) for val in self.value.split(";")
            )
        elif self.condition == "begin with":
            return event.get(self.field).startswith(self.value)
        elif self.condition == "end with":
            return event.get(self.field).endswith(self.value)
        elif self.condition == "not begin with":
            return not event.get(self.field).startswith(self.value)
        elif self.condition == "not end with":
            return not event.get(self.field).endswith(self.value)
        elif self.condition == "less than":
            return self.value < event.get(self.field)
        elif self.condition == "more than":
            return self.value > event.get(self.field)
        elif self.condition == "image":
            return self.value == event.get(self.field).split("\\")[-1]
        else:
            raise ValueError(f"Invalid value for Filter.condition: {self.condition}")


def parse(elem: Element) -> Filter:
    """Parses a valid Element into a Filter

    Args:
        elem (Element): lxml Element that represents a Sysmon Filter against a specific condition
        ex: <ParentImage name="technique_id=T1548.002,technique_name=Bypass User Access Control" condition="image">fodhelper.exe</ParentImage>

    Returns:
        Filter: A Filter that has the properties of the element in a dataclass representation
    """
    attribute_dict = dict(elem.attrib)
    field = elem.tag
    value = elem.text
    condition = attribute_dict.get("condition", "is")
    return Filter(
        field=field,
        name=attribute_dict.get("name", ""),
        condition=condition,
        value=value,
    )
