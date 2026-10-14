"""
Pivot support: a first path lookup from a pivot IP towards the real source, used
to discover where that source is actually attached, so the real lookup can be
pinned to that entry point instead of relying on auto-select.

Functions:
-  return_entry_point_pivot(res): entry-point sn / interface / hostname, or None.
"""

from .pathgraph import node_id


def return_entry_point_pivot(res) -> dict:
    """
    Retrieve the device serial number, interface name, and hostname for the entry
    point device — the device where the pivot->source path leaves the fabric.

    Parameters:
    - res (PathLookupResult): result of the pivot path lookup.

    Returns:
    - dict or None: {"sn", "iface", "hostname"} of the entry point device.
                    None if no transit edge is found.
    """
    for edge_id, edge in res.edges.items():
        if "--transit" in edge_id:
            node = res.nodes[node_id(edge.source)]
            return {
                "sn": node.sn,
                "iface": edge.sourceIfaceName,
                "hostname": node.label,
            }
    return None
