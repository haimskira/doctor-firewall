# UI design requirement — look like the current FMC

*Requested by the product owner, 2026-10-20.* The system must look **exactly like the new
Firewall Management Center UI** (current versions). Reference: the FMC Policy Editor screenshot in
[design/fmc-policy-editor-reference.png](design/fmc-policy-editor-reference.png). Every screen
follows these conventions; new screens must be designed against them.

## Shell

* **Top bar** — dark navy, full width: product name ("Firewall Management Center"-style title with
  our product name) and a breadcrumb under it (e.g. *Policies / Security policies / Policy
  Editor*); on the end side a global **Search** field, action button(s), a **notifications bell
  with a red count badge**, help, and the user menu.
* **Left sidebar** — white, collapsible (hamburger at the top), grouped under small grey section
  headings: **Monitor** (Insights & Reports, Events & Logs) and **Manage** (Policies, Objects,
  Firewall Devices, Secure Connections, Integrations), then Troubleshooting and Administration.
  Each item has an icon and a chevron; the active item has a light-blue background and a blue
  edge bar.
* **Content** — light grey background, white cards / tables.

## Policy Editor (rulebase)

* Back link at the top ("Return to Access Control Policy Management"), then the policy name with a
  lock icon (read-only) and an edit pencil.
* **Policy flow tabs** in evaluation order, separated by arrows, each with a status circle (green
  check = present, empty = none): *Packets → Prefilter Rules → Decryption → Security Intelligence →
  Identity → Access Control → More*. The active tab is underlined in blue. "Targeted: N devices" at
  the end.
* Toolbar: filter button, "Type to search" field, "Total N rules", view icons, outline button
  (e.g. *Add Category*) and primary blue button (e.g. *Add Rule*).
* **Rule table**: checkbox column; `#`; **Name** as a blue link; **Action** as a coloured icon plus
  text (green arrow *Allow*, red circle *Block / Block with reset*); small inspection icons (IPS
  shield, file, logging); a two-level header — **Source** over *Zones / Networks* and
  **Destination** over *Zones / Networks / Ports*; "Any" in grey; zone icons; long cells show two
  values and a blue "+N more" link; edit pencil and a kebab menu at the end of each row.
* **Section rows**: grey bands with a collapse chevron and checkbox — "**Mandatory** 4 rules (1 - 4)",
  "**Default** 6 rules (5 - 10)" — plus inherited "Parent Policy (No rules)" rows.
* Footer: **Default Action** selector (e.g. "Access Control: Block All Traffic"), rows-per-page
  selector (1000) and pagination ("1-10 of 10").

## Colours (light theme; a matching dark theme is kept)

| Token | Use | Value |
|---|---|---|
| `--top` | top bar | `#1b2531` |
| `--side` | sidebar | `#ffffff` |
| `--bg` | content background | `#f2f4f7` |
| `--primary` | links, primary buttons, active tab | `#1d69cc` |
| `--band` | section rows, table header | `#eef1f5` |
| `--allow` | Allow / Trust | `#2e9e5b` |
| `--block` | Block | `#d64545` |

Fonts: system UI fonts only (offline; no web-font downloads). Hebrew uses the same layout mirrored
(RTL): the sidebar moves to the right; IPs, object names and ACL values stay LTR.

## Assets

Open assets only, bundled (no CDN): **Inter** (OFL-1.1) as the UI font — Hebrew falls back to the
system Hebrew font — and **Phosphor** icons (MIT). No Cisco logo, name, CSS or fonts (D-021).

## Status

* **Shell:** dark top bar (brand + breadcrumb, dark search field, bell with red count pill, user
  menu); sidebar exactly as the FMC — *Monitor* (Insights & Reports, Events & Logs), *Manage*
  (Policies, Objects, Firewall Devices, Integrations), divider, *Administration* — items with
  several pages open a flyout, single-page items are direct links; collapsible to icons.
* **Summary Dashboard** (home): title with the snapshot switcher, subtitle, tabs (Overview /
  Risk / Recommendations / Status), widgets with collapse / minimise / close and *Add Widgets*,
  "Top …" bar tables with coloured bars, "Last analysed …" footers.
* **Policy Editor:** flow tabs, Targeted devices, two-level header, action icons, section bands,
  Default Action footer, recommendation tags.
* Recommendations, connectivity map, naming convention and the inventory screens use the same
  cards, tables, inputs and buttons.
* **Policy Editor** also explains objects on hover / focus (value, members, which groups contain
  it); NAT is not shown (not used in this estate); Decryption and Identity open even when they
  are not linked from the access policy.
* **Connectivity map:** tier-tinted pill nodes in light column bands, soft curved edges, focus on
  hover / tap fades everything not connected.
* **Assets:** list / detail — assets with kind icons and tier chips, components table inside.
* **Inspection profiles** (Policies flyout): tier → intrusion / file policy table; recommendation
  tag *Inspection* (purple) and an Allow ← Trust action diff in previews.
* Deliberately absent until the feature exists: Add Rule, Save — no button that does nothing.
