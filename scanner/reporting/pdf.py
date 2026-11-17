"""Report "NETWORK ASSESSMENT" in PDF, senza librerie esterne.

Il progetto dipende solo da Flask e Scapy e deve funzionare offline su un Pi:
un PDF fatto di testo, rettangoli colorati e linee si scrive a mano con la
sola libreria standard. Usa i tre caratteri che ogni lettore PDF ha gia'
(Helvetica, Helvetica-Bold, Courier), quindi niente font da incorporare; le
larghezze dei caratteri servono a mandare a capo il testo. Quello che non e'
nella codifica Windows-1252 (alfabeti non latini, emoji) diventa "?".

Parte da assessment.report_data(): lo stesso dato da cui nasce il testo.
"""
import time
import zlib
from datetime import datetime

PAGE_W, PAGE_H = 595.28, 841.89  # A4, in punti
MARGIN = 50.0
MARGIN_TOP = 50.0
MARGIN_BOTTOM = 58.0
CONTENT_W = PAGE_W - 2 * MARGIN

INK = (0.10, 0.11, 0.13)
MUTED = (0.42, 0.45, 0.50)
FAINT = (0.62, 0.65, 0.69)
RULE = (0.86, 0.87, 0.89)
STRIPE = (0.965, 0.968, 0.973)
DARK = (0.043, 0.051, 0.063)
ACCENT = (0.18, 0.90, 0.65)
WHITE = (1.0, 1.0, 1.0)
AMBER_BG = (1.0, 0.96, 0.84)
AMBER_INK = (0.50, 0.33, 0.02)

# severita' -> (colore di riempimento, colore del testo sul riempimento)
SEVERITY = {
    "critical": ((0.85, 0.15, 0.15), WHITE),
    "high": ((0.92, 0.43, 0.05), WHITE),
    "medium": ((0.93, 0.72, 0.06), DARK),
    "low": ((0.55, 0.58, 0.63), WHITE),
}
SEVERITY_ORDER = ("critical", "high", "medium", "low")

# Larghezze dei caratteri ASCII 32..126 in millesimi di em (metriche AFM
# standard di Helvetica e Helvetica-Bold). Courier ha sempre 600.
_HELV = [
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
    556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
    1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
    667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
    333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
    556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584,
]
_HELV_BOLD = [
    278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278,
    556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611,
    975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778,
    667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556,
    333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611,
    611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584,
]
# Pochi caratteri Windows-1252 non ASCII che compaiono davvero nei report.
_WIN_WIDTHS = {0x96: 556, 0x97: 1000, 0xB7: 278, 0xA0: 278, 0xB0: 400, 0x95: 350}
_FONTS = {"F1": "Helvetica", "F2": "Helvetica-Bold", "F3": "Courier"}


def _encode(text):
    """Testo -> byte Windows-1252, senza caratteri di controllo."""
    raw = str(text).encode("cp1252", errors="replace")
    return bytes(b if b >= 32 else 32 for b in raw)


def _width(text, font, size):
    total = 0
    for b in _encode(text):
        if font == "F3":
            total += 600
        elif 32 <= b <= 126:
            total += (_HELV_BOLD if font == "F2" else _HELV)[b - 32]
        else:
            total += _WIN_WIDTHS.get(b, 611 if font == "F2" else 556)
    return total * size / 1000.0


def _escape(text):
    s = _encode(text).decode("latin-1")
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _wrap(text, font, size, max_w):
    """Manda a capo `text` entro `max_w` punti; una parola piu' larga della
    colonna (un hostname o un URL lungo) si spezza a caratteri."""
    lines = []
    for paragraph in str(text).split("\n"):
        current = ""
        for word in paragraph.split(" "):
            candidate = word if not current else current + " " + word
            if _width(candidate, font, size) <= max_w:
                current = candidate
                continue
            if current:
                lines.append(current)
                current = ""
            while len(word) > 1 and _width(word, font, size) > max_w:
                cut = len(word)
                while cut > 1 and _width(word[:cut], font, size) > max_w:
                    cut -= 1
                lines.append(word[:cut])
                word = word[cut:]
            current = word
        lines.append(current)
    return lines


def _color(prefix, rgb):
    return f"{rgb[0]:.3f} {rgb[1]:.3f} {rgb[2]:.3f} {prefix}"


class _Doc:
    """Pagine A4 come liste di operatori PDF. `y` e' la posizione corrente
    misurata dall'alto della pagina; PDF vuole l'origine in basso, la
    conversione e' tutta qui dentro."""

    def __init__(self):
        self.pages = []
        self.y = MARGIN_TOP
        self.new_page()

    def new_page(self):
        self.pages.append([])
        self.y = MARGIN_TOP

    def _emit(self, op):
        self.pages[-1].append(op)

    def room(self, height):
        return self.y + height <= PAGE_H - MARGIN_BOTTOM

    def ensure(self, height):
        """Va a pagina nuova se `height` non ci sta. True se l'ha fatto."""
        if self.room(height):
            return False
        self.new_page()
        return True

    def text(self, x, baseline, s, font="F1", size=10, color=INK, align="left", page=None):
        if align == "right":
            x -= _width(s, font, size)
        elif align == "center":
            x -= _width(s, font, size) / 2
        op = f"BT /{font} {size} Tf {_color('rg', color)} {x:.2f} {PAGE_H - baseline:.2f} Td ({_escape(s)}) Tj ET"
        (self.pages[page] if page is not None else self.pages[-1]).append(op)

    def rect(self, x, top, w, h, fill=None, stroke=None, line=0.6, page=None):
        ops = []
        if fill:
            ops.append(f"{_color('rg', fill)} {x:.2f} {PAGE_H - top - h:.2f} {w:.2f} {h:.2f} re f")
        if stroke:
            ops.append(f"{_color('RG', stroke)} {line} w {x:.2f} {PAGE_H - top - h:.2f} {w:.2f} {h:.2f} re S")
        (self.pages[page] if page is not None else self.pages[-1]).extend(ops)

    def hline(self, x1, x2, top, color=RULE, line=0.6, page=None):
        op = f"{_color('RG', color)} {line} w {x1:.2f} {PAGE_H - top:.2f} m {x2:.2f} {PAGE_H - top:.2f} l S"
        (self.pages[page] if page is not None else self.pages[-1]).append(op)

    def paragraph(self, text, x=MARGIN, width=CONTENT_W, font="F1", size=10, color=INK, leading=1.4, gap=0):
        """Testo che va a capo e, se serve, cambia pagina riga per riga."""
        step = size * leading
        for line in _wrap(text, font, size, width):
            self.ensure(step)
            self.text(x, self.y + size, line, font, size, color)
            self.y += step
        self.y += gap


def _format_ts(epoch):
    return datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")


def _format_duration(seconds):
    minutes, secs = divmod(max(0, int(seconds)), 60)
    return f"{minutes}m {secs}s" if minutes else f"{secs}s"


def _header(doc, generated_at, subtitle):
    doc.rect(0, 0, PAGE_W, 92, fill=DARK)
    doc.rect(0, 92, PAGE_W, 2.5, fill=ACCENT)
    doc.text(MARGIN, 50, "RaspiScanner", "F2", 24, WHITE)
    doc.text(MARGIN, 70, subtitle, "F1", 11, ACCENT)
    doc.text(PAGE_W - MARGIN, 50, datetime.fromtimestamp(generated_at).strftime("%Y-%m-%d %H:%M"),
             "F1", 9.5, (0.78, 0.80, 0.83), align="right")
    doc.text(PAGE_W - MARGIN, 70, "raspiscanner.it", "F1", 9.5, (0.55, 0.58, 0.63), align="right")
    doc.y = 118


def _section_title(doc, title, size=9):
    doc.ensure(size * 3)
    doc.text(MARGIN, doc.y + size, title.upper(), "F2", size, MUTED)
    doc.y += size + 5
    doc.hline(MARGIN, PAGE_W - MARGIN, doc.y - 1.5)
    doc.y += 5


def _meta(doc, data):
    rows = []
    if data.get("started_at"):
        rows.append(("Scan started", _format_ts(data["started_at"])))
    if data.get("finished_at"):
        rows.append(("Scan finished", _format_ts(data["finished_at"])))
    if data.get("started_at") and data.get("finished_at"):
        rows.append(("Duration", _format_duration(data["finished_at"] - data["started_at"])))
    devices = sum(n["count"] for n in data["networks"])
    rows.append(("Networks", str(len(data["networks"]))))
    rows.append(("Devices", str(devices)))
    for key, value in rows:
        doc.text(MARGIN, doc.y + 10, key, "F1", 9.5, MUTED)
        doc.text(MARGIN + 92, doc.y + 10, value, "F1", 9.5, INK)
        doc.y += 15
    doc.y += 8


def _partial_note(doc):
    text = ("Partial snapshot: the scan was still running when this report was generated, so "
            "some networks may be incomplete and the counts will grow.")
    lines = _wrap(text, "F1", 9, CONTENT_W - 20)
    height = len(lines) * 12.5 + 14
    doc.ensure(height + 8)
    doc.rect(MARGIN, doc.y, CONTENT_W, height, fill=AMBER_BG)
    top = doc.y + 8
    for line in lines:
        doc.text(MARGIN + 10, top + 9, line, "F1", 9, AMBER_INK)
        top += 12.5
    doc.y += height + 12


def _changes(doc, changes):
    _section_title(doc, "Changes since previous scan")
    added, removed, changed = changes["added"], changes["removed"], changes["changed"]
    if not (added or removed or changed):
        doc.paragraph("No changes since the previous saved scan.", size=10, color=MUTED, gap=10)
        return
    for title, items, sign in (
        (f"{len(added)} new device(s)", [f"{d.get('ip')}  {d.get('mac') or '-'}  {d.get('vendor') or 'Unknown vendor'}" for d in added], "+"),
        (f"{len(removed)} device(s) no longer seen", [f"{d.get('ip')}  {d.get('mac') or '-'}  {d.get('vendor') or 'Unknown vendor'}" for d in removed], "-"),
        (f"{len(changed)} device(s) changed", [f"{c['new'].get('ip')}  {c['mac'] or '-'}: {', '.join(c['fields'])}" for c in changed], "~"),
    ):
        if not items:
            continue
        doc.paragraph(title, font="F2", size=9.5, color=INK, gap=2)
        for item in items:
            doc.paragraph(f"{sign} {item}", x=MARGIN + 10, width=CONTENT_W - 10, font="F3", size=8.5, color=INK, leading=1.45)
        doc.y += 6
    doc.y += 4


def _risk_boxes(doc, risk):
    gap = 8.0
    box_w = (CONTENT_W - 3 * gap) / 4
    box_h = 48.0
    doc.ensure(box_h + 6)
    for i, name in enumerate(SEVERITY_ORDER):
        x = MARGIN + i * (box_w + gap)
        fill, _ = SEVERITY[name]
        count = risk.get(name, 0)
        doc.rect(x, doc.y, box_w, box_h, fill=WHITE, stroke=RULE)
        doc.rect(x, doc.y, box_w, 4, fill=fill)
        doc.text(x + 12, doc.y + 33, str(count), "F2", 22, fill if count else FAINT)
        doc.text(x + box_w - 12, doc.y + 31, name.capitalize(), "F1", 9.5, MUTED, align="right")
    doc.y += box_h + 14


def _group_table(doc, group):
    columns = ((MARGIN + 8, 190, "F1", 9.5, INK), (MARGIN + 208, 88, "F3", 9, INK), (MARGIN + 304, CONTENT_W - 312, "F1", 9, MUTED))

    def title(continued=False):
        label = group["title"] + (" (continued)" if continued else "")
        doc.text(MARGIN, doc.y + 9, label, "F2", 8.5, MUTED)
        doc.y += 15

    doc.ensure(15 + 26)
    title()
    for index, (label, ip, services) in enumerate(group["rows"]):
        cells = [label, ip, services or ""]
        wrapped = [_wrap(c, f, s, w) for c, (_, w, f, s, _) in zip(cells, columns)]
        height = max(len(w) for w in wrapped) * 12.5 + 7
        if doc.ensure(height):
            title(continued=True)
        if index % 2 == 0:
            doc.rect(MARGIN, doc.y, CONTENT_W, height, fill=STRIPE)
        for (x, _, font, size, color), lines in zip(columns, wrapped):
            for n, line in enumerate(lines):
                doc.text(x, doc.y + 12 + n * 12.5, line, font, size, color)
        doc.y += height
    doc.y += 10


def _findings(doc, findings):
    if not findings:
        # una riga sola: cosi' il titolo non resta isolato in cima a una
        # pagina, lontano dalla rete a cui si riferisce
        doc.ensure(28)
        doc.text(MARGIN, doc.y + 9, "SECURITY FINDINGS", "F2", 8.5, MUTED)
        doc.text(MARGIN + 112, doc.y + 9.5, "None on this network.", "F1", 9.5, MUTED)
        doc.y += 28
        return
    doc.ensure(40)
    doc.text(MARGIN, doc.y + 9, "SECURITY FINDINGS", "F2", 8.5, MUTED)
    doc.y += 15
    text_x = MARGIN + 66
    text_w = CONTENT_W - 66
    for severity, ip, label, message in findings:
        fill, ink = SEVERITY.get(severity, SEVERITY["low"])
        msg_lines = _wrap(message, "F1", 9.5, text_w)
        detail_lines = _wrap(f"{ip}   {label}", "F1", 8.5, text_w)
        height = len(msg_lines) * 12.5 + len(detail_lines) * 11.5 + 9
        doc.ensure(height)
        doc.rect(MARGIN, doc.y + 1, 54, 14, fill=fill)
        doc.text(MARGIN + 27, doc.y + 11, severity.upper(), "F2", 7.5, ink, align="center")
        top = doc.y
        for line in msg_lines:
            doc.text(text_x, top + 11, line, "F1", 9.5, INK)
            top += 12.5
        for line in detail_lines:
            doc.text(text_x, top + 10, line, "F1", 8.5, MUTED)
            top += 11.5
        doc.y += height
    doc.y += 6


def _network(doc, net, first):
    summary = (f"{net['count']} device{'s' if net['count'] != 1 else ''}  ·  "
               f"{net['cameras']} camera{'s' if net['cameras'] != 1 else ''}  ·  {net['nvrs']} NVR/DVR  ·  "
               f"{net['infra']} network device{'s' if net['infra'] != 1 else ''}  ·  "
               f"{net['findings_total']} finding{'s' if net['findings_total'] != 1 else ''}")
    # titolo, riepilogo e riquadri del rischio restano insieme
    if not first:
        doc.y += 10
    doc.ensure(150)
    doc.text(MARGIN, doc.y + 15, f"Network {net['cidr']}", "F2", 15, INK)
    if net.get("iface"):
        doc.text(PAGE_W - MARGIN, doc.y + 15, f"Interface {net['iface']}", "F1", 10, MUTED, align="right")
    doc.y += 24
    doc.paragraph(summary, size=9.5, color=MUTED, gap=2)
    if net.get("no_mac"):
        plural = "s" if net["no_mac"] != 1 else ""
        doc.paragraph(f"{net['no_mac']} device{plural} on this network have no MAC address (found via ICMP over a "
                      "VPN/NOARP link, not ARP): expected, not a scan error.", size=8.5, color=FAINT, gap=2)
    doc.y += 8
    doc.text(MARGIN, doc.y + 9, "RISK SUMMARY", "F2", 8.5, MUTED)
    doc.y += 15
    _risk_boxes(doc, net["risk"])
    for group in net["groups"]:
        _group_table(doc, group)
    _findings(doc, net["findings"])


def _disclaimers(doc, texts):
    lines = []
    for text in texts:
        lines.extend(_wrap(text, "F1", 8.5, CONTENT_W - 24))
        lines.append("")
    lines.pop()
    height = len(lines) * 11.5 + 20
    doc.ensure(height)
    doc.rect(MARGIN, doc.y, CONTENT_W, height, fill=STRIPE)
    top = doc.y + 10
    for line in lines:
        doc.text(MARGIN + 12, top + 8, line, "F1", 8.5, MUTED)
        top += 11.5
    doc.y += height


def _footers(doc, label):
    total = len(doc.pages)
    for index in range(total):
        doc.hline(MARGIN, PAGE_W - MARGIN, PAGE_H - 40, page=index)
        doc.text(MARGIN, PAGE_H - 28, label, "F1", 8, FAINT, page=index)
        doc.text(PAGE_W - MARGIN, PAGE_H - 28, f"Page {index + 1} of {total}", "F1", 8, FAINT, align="right", page=index)


def _assemble(pages, title, generated_at):
    """Scrive il file: intestazione, oggetti, tabella xref, trailer."""
    objects = []  # corpo di ogni oggetto, numerato da 1

    def add(body):
        objects.append(body)
        return len(objects)

    catalog = add(b"")  # 1, riempito dopo
    pages_root = add(b"")  # 2
    fonts = {key: add(f"<< /Type /Font /Subtype /Type1 /BaseFont /{name} /Encoding /WinAnsiEncoding >>".encode())
             for key, name in _FONTS.items()}
    font_res = " ".join(f"/{key} {num} 0 R" for key, num in fonts.items())
    created = datetime.fromtimestamp(generated_at).strftime("D:%Y%m%d%H%M%S")
    info = add(f"<< /Title ({_escape(title)}) /Producer (RaspiScanner) /Creator (RaspiScanner) "
               f"/CreationDate ({created}) >>".encode())

    page_nums = []
    for ops in pages:
        content = zlib.compress("\n".join(op for op in ops if op).encode("latin-1"), 6)
        stream = add(b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(content) + content + b"\nendstream")
        page_nums.append(add(
            f"<< /Type /Page /Parent {pages_root} 0 R /MediaBox [0 0 {PAGE_W:.2f} {PAGE_H:.2f}] "
            f"/Resources << /Font << {font_res} >> >> /Contents {stream} 0 R >>".encode()))
    objects[catalog - 1] = f"<< /Type /Catalog /Pages {pages_root} 0 R >>".encode()
    kids = " ".join(f"{n} 0 R" for n in page_nums)
    objects[pages_root - 1] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_nums)} >>".encode()

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n".encode() + body + b"\nendobj\n"
    xref_at = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode() + b"0000000000 65535 f \n"
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode()
    out += (f"trailer\n<< /Size {len(objects) + 1} /Root {catalog} 0 R /Info {info} 0 R >>\n"
            f"startxref\n{xref_at}\n%%EOF\n").encode()
    return bytes(out)


def render(data, generated_at=None, partial=False, subtitle="Network assessment report"):
    """PDF (bytes) a partire da assessment.report_data(). `partial` aggiunge
    l'avviso di istantanea parziale, per un report generato a scan in corso."""
    generated_at = generated_at or time.time()
    doc = _Doc()
    _header(doc, generated_at, subtitle)
    _meta(doc, data)
    if partial:
        _partial_note(doc)
    if data.get("changes") is not None:
        _changes(doc, data["changes"])
    for index, net in enumerate(data["networks"]):
        _network(doc, net, first=index == 0)
    doc.y += 8
    _disclaimers(doc, data["disclaimers"])
    _footers(doc, "RaspiScanner network assessment report")
    return _assemble(doc.pages, f"RaspiScanner - {subtitle}", generated_at)
