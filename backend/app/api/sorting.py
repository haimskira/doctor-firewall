"""Server-side sorting of paged tables: a whitelisted column and a direction from the query.

Each endpoint lists the columns it can sort by (``sort`` is validated as one of them, so no
caller-supplied text ever reaches SQL) and its default order, which also breaks ties so that
paging stays stable.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Annotated, Any, Literal

from fastapi import Query
from sqlalchemy import ColumnElement
from sqlalchemy.orm import InstrumentedAttribute

SortOrder = Annotated[Literal["asc", "desc"] | None, Query()]
Column = ColumnElement[Any] | InstrumentedAttribute[Any]
SortColumns = dict[str, Column]


def order_by(
    sort: str | None,
    order: Literal["asc", "desc"] | None,
    columns: Mapping[str, Column],
    default: Sequence[Column],
) -> list[Column]:
    """ORDER BY terms: the chosen column (nulls last either way), then the default order."""
    if sort is None:
        return list(default)
    column = columns[sort]
    first = column.desc().nulls_last() if order == "desc" else column.asc().nulls_last()
    return [first, *default]
