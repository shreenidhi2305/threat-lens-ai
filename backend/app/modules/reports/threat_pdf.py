"""Security and threat monitoring report, rendered as a PDF with charts."""

from __future__ import annotations

import io
from datetime import datetime, timezone
from html import escape

from reportlab.graphics.shapes import Drawing, Line, Rect, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from app.modules.threat_monitoring.schemas import Detection, ThreatStats, TimelineBucket

INK = colors.HexColor('#17343b')
MUTED = colors.HexColor('#557078')
LINE = colors.HexColor('#d5dee0')
TRACK = colors.HexColor('#e7eeef')
PAPER = colors.HexColor('#f4f7f8')
HIGH = colors.HexColor('#c4533a')
MED = colors.HexColor('#c4922a')
LOW = colors.HexColor('#2f8f6b')
WHITE = colors.white

_WINDOW_LABELS = {
    '24h': 'Last 24 hours',
    '7d': 'Last 7 days',
    '30d': 'Last 30 days',
}

_MAX_TABLE_ROWS = 80


def _esc(value: object, fallback: str = '—') -> str:
    if value is None or value == '':
        return fallback
    return escape(str(value))


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        'title': ParagraphStyle(
            'MonTitle', parent=base['Title'], fontName='Helvetica-Bold', fontSize=18,
            leading=22, textColor=INK, spaceAfter=1 * mm,
        ),
        'subtitle': ParagraphStyle(
            'MonSubtitle', parent=base['Normal'], fontSize=8.5, leading=11,
            textColor=MUTED, spaceAfter=2 * mm,
        ),
        'heading': ParagraphStyle(
            'MonHeading', parent=base['Heading2'], fontName='Helvetica-Bold', fontSize=12,
            leading=15, textColor=INK, spaceBefore=4 * mm, spaceAfter=2 * mm,
        ),
        'caption': ParagraphStyle(
            'MonCaption', parent=base['Normal'], fontName='Helvetica-Bold', fontSize=8,
            leading=10, textColor=INK, spaceBefore=1 * mm, spaceAfter=1 * mm,
        ),
        'body': ParagraphStyle(
            'MonBody', parent=base['Normal'], fontSize=8.5, leading=11, textColor=INK,
        ),
        'cell': ParagraphStyle(
            'MonCell', parent=base['Normal'], fontSize=7.5, leading=9.5, textColor=INK,
        ),
        'cell_muted': ParagraphStyle(
            'MonCellMuted', parent=base['Normal'], fontSize=7.5, leading=9.5, textColor=MUTED,
        ),
        'head': ParagraphStyle(
            'MonHead', parent=base['Normal'], fontName='Helvetica-Bold', fontSize=7,
            leading=9, textColor=WHITE,
        ),
        'kpi_label': ParagraphStyle(
            'MonKpiLabel', parent=base['Normal'], fontSize=7, leading=9, textColor=MUTED,
        ),
        'kpi_value': ParagraphStyle(
            'MonKpiValue', parent=base['Normal'], fontName='Helvetica-Bold', fontSize=12,
            leading=14, textColor=INK,
        ),
    }


def _bars(items: list[tuple[str, int, colors.Color]], width: float) -> Drawing:
    """Horizontal bars. Values share one scale so lengths are comparable."""
    row_h = 16
    label_w = 72
    value_w = 28
    bar_max = max(width - label_w - value_w, 20)
    height = 6 + max(len(items), 1) * row_h
    drawing = Drawing(width, height)
    peak = max((count for _, count, _ in items), default=0) or 1
    if not items:
        drawing.add(String(0, 4, 'No data', fontName='Helvetica', fontSize=8, fillColor=MUTED))
        return drawing
    for index, (label, value, color) in enumerate(items):
        y = height - 14 - index * row_h
        drawing.add(String(0, y, label[:18], fontName='Helvetica', fontSize=8, fillColor=INK))
        drawing.add(Rect(label_w, y - 1, bar_max, 9, fillColor=TRACK, strokeColor=None))
        fill = bar_max * (value / peak) if value else 0
        if fill > 0:
            drawing.add(Rect(label_w, y - 1, fill, 9, fillColor=color, strokeColor=None))
        drawing.add(String(
            label_w + bar_max + 6, y, str(value),
            fontName='Helvetica', fontSize=8, fillColor=MUTED,
        ))
    return drawing


def _timeline_chart(buckets: list[TimelineBucket], width: float) -> Drawing:
    height = 158
    left = 24
    bottom = 42
    plot_w = width - left - 6
    plot_h = height - bottom - 10
    drawing = Drawing(width, height)
    count = len(buckets)
    if count == 0:
        drawing.add(String(0, 20, 'No activity in this window', fontName='Helvetica', fontSize=8, fillColor=MUTED))
        return drawing

    peak = max(bucket.total for bucket in buckets) or 1
    slot = plot_w / count
    bar_w = max(slot * 0.7, 1)
    drawing.add(Line(left, bottom, left + plot_w, bottom, strokeColor=LINE, strokeWidth=0.6))
    drawing.add(Line(left, bottom + plot_h / 2, left + plot_w, bottom + plot_h / 2, strokeColor=LINE, strokeWidth=0.3))
    drawing.add(String(0, bottom + plot_h - 4, str(peak), fontName='Helvetica', fontSize=6, fillColor=MUTED))
    drawing.add(String(0, bottom + plot_h / 2 - 2, str(max(peak // 2, 0)), fontName='Helvetica', fontSize=6, fillColor=MUTED))

    step = 1 if count <= 8 else (4 if count <= 24 else 5)
    for index, bucket in enumerate(buckets):
        x = left + index * slot + (slot - bar_w) / 2
        y = bottom
        if bucket.total == 0:
            drawing.add(Rect(x, y, bar_w, 1, fillColor=LINE, strokeColor=None))
        else:
            for amount, color in (
                (bucket.malicious, HIGH),
                (bucket.suspicious, MED),
                (bucket.benign, LOW),
            ):
                bar_h = plot_h * (amount / peak)
                if bar_h > 0:
                    drawing.add(Rect(x, y, bar_w, bar_h, fillColor=color, strokeColor=None))
                    y += bar_h
        if index % step == 0 or index == count - 1:
            drawing.add(String(x, 22, bucket.label, fontName='Helvetica', fontSize=6, fillColor=MUTED))

    legend_x = left
    for name, color in (('Malicious', HIGH), ('Suspicious', MED), ('Benign', LOW)):
        drawing.add(Rect(legend_x, 6, 8, 8, fillColor=color, strokeColor=None))
        drawing.add(String(legend_x + 12, 7, name, fontName='Helvetica', fontSize=7, fillColor=INK))
        legend_x += 78
    return drawing


def _kpi_table(stats: ThreatStats, window_total: int, styles: dict[str, ParagraphStyle]) -> Table:
    cells = [
        ('Total detections', str(stats.total_detections)),
        ('Malicious', str(stats.malicious)),
        ('Suspicious', str(stats.suspicious)),
        ('Benign', str(stats.benign)),
        ('Open alerts', str(stats.open_alerts)),
        ('Last 24 hours', str(stats.last_24h)),
        ('Detection rate', f'{stats.detection_rate:.1%}'),
        ('Selected window', str(window_total)),
    ]
    tiles = [
        [Paragraph(label, styles['kpi_label']), Paragraph(value, styles['kpi_value'])]
        for label, value in cells
    ]
    table = Table([tiles[:4], tiles[4:]], colWidths=[45 * mm] * 4)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), PAPER),
        ('BOX', (0, 0), (-1, -1), 0.4, LINE),
        ('INNERGRID', (0, 0), (-1, -1), 0.3, LINE),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 3),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    return table


def _chart_pair(
    left_title: str,
    left: Drawing,
    right_title: str,
    right: Drawing,
    styles: dict[str, ParagraphStyle],
) -> Table:
    table = Table(
        [
            [Paragraph(left_title, styles['caption']), Paragraph(right_title, styles['caption'])],
            [left, right],
        ],
        colWidths=[90 * mm, 90 * mm],
    )
    table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 3),
        ('TOPPADDING', (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
    ]))
    return table


def _family_items(stats: ThreatStats) -> list[tuple[str, int, colors.Color]]:
    items: list[tuple[str, int, colors.Color]] = []
    for entry in stats.by_family[:8]:
        name = str(entry.get('family') or 'Unknown')
        try:
            count = int(entry.get('count') or 0)
        except (TypeError, ValueError):
            count = 0
        items.append((name, count, INK))
    return items


def _detection_table(
    detections: list[Detection],
    styles: dict[str, ParagraphStyle],
) -> Table:
    header = [
        Paragraph(label, styles['head'])
        for label in ('When (UTC)', 'File', 'Verdict', 'Level', 'Score', 'Family')
    ]
    data: list[list[object]] = [header]
    for detection in detections:
        moment = detection.at
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        else:
            moment = moment.astimezone(timezone.utc)
        data.append([
            Paragraph(moment.strftime('%Y-%m-%d %H:%M'), styles['cell_muted']),
            Paragraph(_esc(detection.filename), styles['cell']),
            Paragraph(_esc(detection.verdict_label), styles['cell']),
            Paragraph(_esc(detection.level), styles['cell']),
            Paragraph(str(detection.score), styles['cell']),
            Paragraph(_esc(detection.family), styles['cell']),
        ])
    table = Table(data, colWidths=[32 * mm, 52 * mm, 26 * mm, 20 * mm, 16 * mm, 34 * mm], repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), INK),
        ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
        ('BACKGROUND', (0, 1), (-1, -1), WHITE),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [WHITE, PAPER]),
        ('BOX', (0, 0), (-1, -1), 0.4, LINE),
        ('INNERGRID', (0, 1), (-1, -1), 0.2, LINE),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    return table


def render_threat_monitoring_pdf(
    *,
    stats: ThreatStats,
    timeline: list[TimelineBucket],
    detections: list[Detection],
    window: str,
    filter_notes: list[str],
    prepared_by: str,
    role: str,
    matched_count: int,
) -> bytes:
    """Render the monitoring snapshot plus the filtered detection table."""
    buffer = io.BytesIO()
    styles = _styles()
    frame = Frame(15 * mm, 15 * mm, 180 * mm, 267 * mm, id='normal')

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont('Helvetica', 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(15 * mm, 9 * mm, 'ThreatLens AI | Security and threat monitoring report')
        canvas.drawRightString(195 * mm, 9 * mm, f'Page {doc.page}')
        canvas.restoreState()

    document = BaseDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=15 * mm,
        rightMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
        title='ThreatLens AI Threat Monitoring Report',
        pageCompression=0,
    )
    document.addPageTemplates([PageTemplate(id='report', frames=frame, onPage=footer)])

    generated = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    window_label = _WINDOW_LABELS.get(window, window)
    window_total = sum(bucket.total for bucket in timeline)
    shown = detections[:_MAX_TABLE_ROWS]
    hidden = max(matched_count - len(shown), 0)

    verdict_items = [
        ('Malicious', stats.malicious, HIGH),
        ('Suspicious', stats.suspicious, MED),
        ('Benign', stats.benign, LOW),
    ]
    level_items = [
        ('High', int(stats.by_level.get('high', 0) or 0), HIGH),
        ('Medium', int(stats.by_level.get('medium', 0) or 0), MED),
        ('Low', int(stats.by_level.get('low', 0) or 0), LOW),
    ]
    families = _family_items(stats)
    half = 86 * mm

    story: list[object] = [
        Paragraph('Threat monitoring report', styles['title']),
        Paragraph(
            f'{window_label} &nbsp;|&nbsp; Generated {generated} &nbsp;|&nbsp; '
            f'{_esc(prepared_by)} ({_esc(role)})',
            styles['subtitle'],
        ),
        Paragraph(
            (
                f'The detection log holds {stats.total_detections} files: '
                f'{stats.malicious} malicious and {stats.suspicious} suspicious '
                f'({stats.detection_rate:.1%} detection rate). '
                f'{window_label} accounts for {window_total} detections. '
                f'{stats.open_alerts} alerts are still open.'
            ),
            styles['body'],
        ),
        Paragraph('Monitoring snapshot', styles['heading']),
        Paragraph(
            'Counts below cover the full detection log. The activity chart follows the window selected on Threat Monitor.',
            styles['body'],
        ),
        Spacer(1, 2 * mm),
        _kpi_table(stats, window_total, styles),
        Spacer(1, 3 * mm),
        _chart_pair(
            'Verdict mix',
            _bars(verdict_items, half),
            'Risk levels',
            _bars(level_items, half),
            styles,
        ),
        Paragraph('Top families', styles['caption']),
    ]
    if families:
        story.append(_bars(families, 180 * mm))
    else:
        story.append(Paragraph('No families recorded yet.', styles['body']))

    story.extend([
        Paragraph(f'Activity · {window_label}', styles['heading']),
        _timeline_chart(timeline, 180 * mm),
        Paragraph('Filtered detections', styles['heading']),
        Paragraph('Filters: ' + _esc('; '.join(filter_notes)), styles['body']),
        Spacer(1, 2 * mm),
    ])
    if not shown:
        story.append(Paragraph('No detections match the current filters.', styles['body']))
    else:
        story.append(_detection_table(shown, styles))
        if hidden:
            story.append(Spacer(1, 2 * mm))
            story.append(Paragraph(
                f'Showing the {len(shown)} most recent matches. {hidden} additional matches were omitted.',
                styles['body'],
            ))
        else:
            story.append(Spacer(1, 2 * mm))
            story.append(Paragraph(f'{matched_count} detection(s) match the current filters.', styles['body']))

    document.build(story)
    return buffer.getvalue()
