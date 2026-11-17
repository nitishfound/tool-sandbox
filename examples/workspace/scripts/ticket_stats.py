import csv
from pathlib import Path

rows = list(csv.DictReader(Path("docs/tickets.csv").open()))
hours = [float(r["hours_to_first_response"]) for r in rows]
print(f"tickets={len(hours)} average_hours={sum(hours) / len(hours):.1f} max_hours={max(hours):.0f}")
