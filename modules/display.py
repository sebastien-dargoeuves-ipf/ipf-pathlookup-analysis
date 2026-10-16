"""
# display.py
Printing the parts of a lookup that are not per-hop: the events summary, the pivot
outcome, the raw edge dump and the flat table. Per-hop walking and enrichment live in
`pathgraph.py`.
"""

from rich import print
from rich.markup import escape
from rich.table import Table

from .pathgraph import note_text, path_rows
from .utilis import SEVERITY_TEXT, display_severity

GREEN = "0"
BLUE = "10"
AMBER = "20"
RED = "30"
COLOUR_DICT = {"Green": GREEN, "Blue": BLUE, "Amber": AMBER, "Red": RED}


def show_pivot(info, src_ip: str):
    """Tell the user what the pivot found (`info` is a lookup.PivotInfo)."""
    if info.auto:
        print(
            f"[blue][italic][bold]Info: [/bold][/blue][/italic]DEFAULT_GW_NOT_FOUND for `{src_ip}`, auto-pivot: using `{info.via}` to find where it is connected"
        )
    if info.entry:
        print(
            f"[blue][italic][bold]Info: [/bold][/blue][/italic]Entry point for the source `{src_ip} is: `{info.entry['hostname']}@{info.entry['iface']}`"
        )
    else:
        print(
            f"[yellow][italic][bold]Warning: [/bold][/yellow][/italic]Pivot `{info.via}` will not be used. From the pivot to the source `({src_ip})` there is no transit: {escape(info.why_not)}"
        )


def display_summary_topics(pathlookup_result: dict):
    """
    Display summary information, highlighting issues with NAT, ACL, etc.

    Parameters:
    pathlookup_result (dict): res.pathlookup.model_dump(by_alias=True)

    Returns:
    None
    """
    # Initialize a dictionary to store the summary information for each topic
    topics_results = {}

    # Print the Summary header
    print("[bold]  - Summary[/bold]")

    # Iterate over each topic in the eventsSummary dictionary
    for topic, topic_data in pathlookup_result["eventsSummary"]["topics"].items():
        if not topic_data:
            continue
        topics_results[topic] = []

        # Iterate over each color in the COLOUR_DICT dictionary
        for colour, colour_key in COLOUR_DICT.items():
            value = topic_data.get(colour_key, 0)
            # If the color value is not zero, add it to the list of results for this topic
            if value != 0:
                topics_results[topic].append(f"      - {colour}: {value}")

    # Display the summary information for each topic
    if not any(topics_results.values()):
        print("No summary information for this path")
    else:
        for topic, topic_results in topics_results.items():
            if topic_results:
                print(f"    - {topic}")
                print("\n".join(f"{result}" for result in topic_results))


def display_summary_global(pathlookup_result: dict):
    """
    Display information related to the Global key.

    Parameters:
    pathlookup_result (dict): res.pathlookup.model_dump(by_alias=True)

    Returns:
    None
    """
    # Check if there is any Global information to display
    if len(pathlookup_result["eventsSummary"]["global"]) > 0:
        global_info = pathlookup_result["eventsSummary"]["global"]

        # Print the Global information header
        print("[bold]  - Global[/bold]")

        # Print each piece of Global information
        for info in global_info:
            message = [info["name"]]
            message.extend(info["details"])
            message.append(str(info["severity"]))
            message = " | ".join(message)
            print(f"{message}")


def display_all_edges(pathlookup_edges: dict):
    """
    Display all edges in the path, highlighting when multiple egress points exist.
    Debug view (--verbose): the enriched tree from pathgraph.show() is the real
    output, this is the unfiltered adjacency it was built from.

    Parameters:
    pathlookup_edges (dict): res.edges

    Returns:
    list: A list of all edges involved in the path.
    """
    # Collect all next edge IDs in a list
    next_edge_ids = [next(iter(pathlookup_edges.values())).id]
    for edge in pathlookup_edges.values():
        if len(edge.nextEdgeIds) > 1:
            next_edge_ids.extend(
                f"{path}--multiple-egress" for path in edge.nextEdgeIds
            )
        elif len(edge.nextEdgeIds) == 1:
            next_edge_ids.append(edge.nextEdgeIds[0])

    # Process each edge ID to extract the relevant information
    processed_edges = []
    for edge in next_edge_ids:
        processed_edge = edge.split("--")
        processed_edge = [
            (
                f"{e.split('!')[1]}"
                if "!" in e
                else f"{e.split('@')[1]}"
                if "@" in e
                else e
            )
            for e in processed_edge
        ]
        processed_edges.append("--".join(processed_edge))

    # Print the list of edges, highlighting multiple egress points
    final_all_edges = []
    prev_device_src = ""
    for edge in processed_edges:
        if edge not in final_all_edges:
            final_all_edges.append(edge)
            device_src = edge.split("@")[0] if edge.split("@") else ""
            if device_src == prev_device_src:
                (
                    print("".join([" └ ", edge]))
                    if "multiple-egress" in edge
                    else print(edge)
                )
            else:
                print(edge)
            prev_device_src = device_src

    return final_all_edges


def display_table(structure, first_path: bool = False):
    """
    Render the enriched path as a table, one row per hop. Forks and rejoins get a
    note row (see pathgraph.path_rows) and branch hops are indented under it.
    Columns that would be empty for the whole path are left out.

    Parameters:
    structure: pathgraph.enrich() output
    first_path (bool): follow one branch at each fork instead of all of them

    Returns:
    None
    """
    columns = ["#", "Ingress", "Device", "Egress", "Protocol", "VRF", "Security"]
    rows, hop_number = [], 0
    for depth, hop in path_rows(structure, first_only=first_path):
        if isinstance(hop, tuple):
            rows.append(("note", "  " * depth + note_text(hop)))
            continue
        hop_number += 1
        vrf = hop["vrf"] if isinstance(hop["vrf"], str) else ",".join(hop["vrf"] or [])
        rows.append(
            (
                "hop",
                [
                    str(hop_number),
                    ",".join(hop["ingress"] or ["-"]),
                    "  " * depth + hop["device"],
                    ",".join(hop["egress"] or ["-"]),
                    hop["protocol"],
                    vrf,
                    _security_text(hop),
                ],
            )
        )

    hops = [cells for kind, cells in rows if kind == "hop"]
    keep = [i for i in range(len(columns)) if i < 4 or any(c[i] for c in hops)]
    table = Table(box=None, pad_edge=False)
    for i in keep:
        table.add_column(
            columns[i],
            style={0: "dim", 2: "cyan", 4: "green"}.get(i),
            no_wrap=(i == 2),
        )
    for kind, cells in rows:
        if kind == "note":
            table.add_row(*([""] * (keep.index(2))), f"[dim]{escape(cells)}[/dim]")
        else:
            # The security cell is already rich markup (coloured severity), escaped inside.
            table.add_row(*(cells[i] if i == 6 else escape(cells[i]) for i in keep))
    print(table)


def _security_text(hop) -> str:
    """One cell (rich markup) for the security verdict, the deciding policy and the zone."""
    text = ""
    if hop["blocked"]:
        text = f"{SEVERITY_TEXT[30]} {escape(hop['drop_reason'] or '')}".strip()
    if hop["security"]:
        top = hop["security"][0]
        text = f"{display_severity(top['severity'], text=True)} {escape(top['policy'] or '')}".strip()
    if hop["zonefw"]:
        text = f"{text} (zone {escape(str(hop['zonefw']))})".strip()
    return text
