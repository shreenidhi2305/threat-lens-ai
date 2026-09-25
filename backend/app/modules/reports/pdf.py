"""Server-side PDF rendering for completed static analysis results."""

from __future__ import annotations

import io
from datetime import datetime, timezone
from html import escape
from typing import Iterable

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

from app.modules.file_analysis.schemas import AnalysisResult


def _build_styles() -> dict[str, ParagraphStyle]:
    base_styles = getSampleStyleSheet()
    return {
        'title': ParagraphStyle('ReportTitle', parent=base_styles['Title'], fontName='Helvetica-Bold', fontSize=20, leading=24, textColor=colors.HexColor('#17343b'), spaceAfter=3 * mm),
        'subtitle': ParagraphStyle('ReportSubtitle', parent=base_styles['Normal'], fontSize=9, textColor=colors.HexColor('#557078'), spaceAfter=7 * mm),
        'heading': ParagraphStyle('ReportHeading', parent=base_styles['Heading2'], fontName='Helvetica-Bold', fontSize=13, leading=16, textColor=colors.HexColor('#17343b'), spaceBefore=5 * mm, spaceAfter=3 * mm),
        'subheading': ParagraphStyle('ReportSubheading', parent=base_styles['Heading3'], fontName='Helvetica-Bold', fontSize=10, leading=13, textColor=colors.HexColor('#31545c'), spaceBefore=2 * mm, spaceAfter=2 * mm),
        'label': ParagraphStyle('ReportLabel', parent=base_styles['Normal'], fontName='Helvetica-Bold', fontSize=8.5, leading=11, textColor=colors.HexColor('#31545c')),
        'body': ParagraphStyle('ReportBody', parent=base_styles['Normal'], fontSize=8.5, leading=11, textColor=colors.HexColor('#24363b'), wordWrap='CJK'),
        'small': ParagraphStyle('ReportSmall', parent=base_styles['Normal'], fontSize=7.5, leading=9, textColor=colors.HexColor('#557078')),
    }


def _new_document(buffer: io.BytesIO, footer_label: str, pdf_title: str) -> BaseDocTemplate:
    frame = Frame(15 * mm, 15 * mm, 180 * mm, 267 * mm, id='normal')

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont('Helvetica', 7.5)
        canvas.setFillColor(colors.HexColor('#6b7f84'))
        canvas.drawString(15 * mm, 9 * mm, footer_label)
        canvas.drawRightString(195 * mm, 9 * mm, f'Page {doc.page}')
        canvas.restoreState()

    doc = BaseDocTemplate(buffer, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=15 * mm, bottomMargin=15 * mm, title=pdf_title)
    doc.addPageTemplates([PageTemplate(id='report', frames=frame, onPage=footer)])
    return doc


def _text(value: object, fallback: str = 'Not available') -> str:
    if value is None or value == '':
        return fallback
    if isinstance(value, bool):
        return 'Yes' if value else 'No'
    return escape(str(value))


def _paragraph(value: object, style: ParagraphStyle, fallback: str = 'Not available') -> Paragraph:
    return Paragraph(_text(value, fallback), style)


def _rows(items: Iterable[tuple[str, object]], styles: dict[str, ParagraphStyle]) -> Table:
    data = [[_paragraph(label, styles['label']), _paragraph(value, styles['body'])] for label, value in items]
    if not data:
        data = [[_paragraph('Status', styles['label']), _paragraph('Not available', styles['body'])]]
    table = Table(data, colWidths=[47 * mm, 133 * mm], repeatRows=0)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#eef2f3')),
        ('BOX', (0, 0), (-1, -1), 0.4, colors.HexColor('#c9d2d5')),
        ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.HexColor('#d9e0e2')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 7),
        ('RIGHTPADDING', (0, 0), (-1, -1), 7),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    return table


def _list_block(title: str, values: list[object], styles: dict[str, ParagraphStyle]) -> list[object]:
    flow: list[object] = [Paragraph(escape(title), styles['subheading'])]
    if not values:
        flow.append(Paragraph('Not available', styles['body']))
    else:
        for value in values:
            flow.append(Paragraph(f'&bull; {_text(value)}', styles['body']))
    flow.append(Spacer(1, 3 * mm))
    return flow


def render_analysis_pdf(result: AnalysisResult) -> bytes:
    """Render an AnalysisResult without reading or storing the uploaded file."""
    buffer = io.BytesIO()
    styles = _build_styles()
    doc = _new_document(buffer, 'ThreatLens AI | Static malware analysis report', 'ThreatLens AI Analysis Report')

    metadata = result.metadata
    hashes = result.hashes
    ml = result.ml
    verdict = result.verdict
    signature = result.signature_match
    network = result.network_indicators
    rule_family = signature.type if signature.matched else None
    yara_families = list(dict.fromkeys(
        str(match.meta['family'])
        for match in result.yara_matches
        if match.meta.get('family')
    ))
    rule_families = list(dict.fromkeys(
        ([rule_family] if rule_family else []) + yara_families
    ))
    rule_evidence = (
        result.risk.level != 'low'
        or signature.matched
        or bool(result.yara_matches)
        or bool(result.suspicious_indicators)
    )
    ml_benign = bool(ml and ml.available and ml.applicable and ml.malicious is False)
    elevated_by_rules = bool(ml_benign and rule_evidence and verdict and verdict.label != 'benign')

    story: list[object] = [
        Paragraph('ThreatLens AI', styles['title']),
        Paragraph(f'Static analysis report | {_text(result.object_path)} | {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}', styles['subtitle']),
        Paragraph('Analyst Summary', styles['heading']),
        _rows([
            ('Overall verdict', verdict.label if verdict else result.risk.classification),
            ('Risk score', f'{verdict.score}/100 ({verdict.level})' if verdict else f'{result.risk.score}/100 ({result.risk.level})'),
            ('ML malware probability', f'{ml.malware_probability:.1%}' if ml and ml.malware_probability is not None else None),
            ('ML classification', 'Benign' if ml_benign else (ml.category if ml and ml.category else None)),
            ('Rule/YARA families', ', '.join(rule_families) or result.risk.classification),
            ('Recommended action', verdict.recommended_action if verdict else result.risk.recommended_action),
        ], styles),
        Paragraph(
            _text(
                (verdict.classification if verdict else result.risk.classification)
                + '. '
                + (verdict.recommended_action if verdict else result.risk.recommended_action)
                + (' ML classified the sample as benign; the final verdict was elevated due to rule/YARA evidence.' if elevated_by_rules else '')
            ),
            styles['body'],
        ),
        Paragraph('File Metadata and Hashes', styles['heading']),
        _rows([
            ('File', result.object_path), ('Type', metadata.file_type), ('MIME', metadata.mime_type),
            ('Size', f'{metadata.size_bytes} bytes'), ('Extension', metadata.extension), ('Magic bytes', metadata.magic_hex),
            ('MD5', hashes.md5), ('SHA-1', hashes.sha1), ('SHA-256', hashes.sha256),
        ], styles),
        Paragraph('Detection and Classification Evidence', styles['heading']),
        _rows([
            ('ML status', 'Available' if ml and ml.available else (ml.reason if ml else 'Not available')),
            ('ML applicable', ml.applicable if ml else None),
            ('ML category confidence', f'{ml.category_confidence:.1%}' if ml and ml.category_confidence is not None else None),
            ('ML model version', ml.model_versions.get('detector') if ml else None),
            ('Signature match', signature.name if signature.matched else 'No known-hash match'),
            ('Signature type', signature.type if signature.matched else None),
            ('YARA/rule families', ', '.join(rule_families) or None),
            ('Engine agreement', verdict.agreement if verdict else None),
        ], styles),
    ]

    if ml and ml.available and ml.applicable and ml.malicious and ml.top_categories:
        story.append(Paragraph('ML category candidates', styles['subheading']))
        story.append(_rows([(category.category, f'{category.probability:.1%}') for category in ml.top_categories], styles))
    story.extend(_list_block('Static classification signals', result.suspicious_indicators, styles))

    story.extend([
        Paragraph('PE and Static Analysis', styles['heading']),
        _rows([
            ('Shannon entropy', metadata.shannon_entropy), ('Likely packed', metadata.likely_packed),
            ('Printable ratio', metadata.printable_ratio), ('Likely text', metadata.likely_text),
            ('Extension/content match', metadata.extension_matches_content),
            ('Suspicious signal count', len(result.suspicious_strings)),
        ], styles),
    ])
    story.append(Paragraph('Network Indicators and IOCs', styles['heading']))
    story.extend(_list_block('URLs', network.urls, styles))
    story.extend(_list_block('IP addresses', network.ips, styles))
    story.extend(_list_block('Domains', network.domains, styles))

    story.append(Paragraph(f'YARA Matches ({len(result.yara_matches)})', styles['heading']))
    if result.yara_matches:
        for match in result.yara_matches:
            tags = ', '.join(match.tags) or 'No tags'
            meta = ', '.join(f'{key}: {value}' for key, value in match.meta.items()) or 'No metadata'
            story.append(Paragraph(escape(match.rule), styles['subheading']))
            story.append(_rows([
                ('Tags', tags),
                ('Family', match.meta.get('family')),
                ('MITRE ID', match.meta.get('mitre')),
                ('Severity', match.meta.get('severity')),
                ('Description', match.meta.get('description')),
                ('Metadata', meta),
                ('Matched indicators', ', '.join(match.matched_strings) or 'None recorded'),
            ], styles))
    else:
        story.append(Paragraph('No YARA matches recorded.', styles['body']))

    if result.notes:
        story.append(Paragraph('Analysis Notes', styles['heading']))
        story.extend(_list_block('Notes', result.notes, styles))

    doc.build(story)
    return buffer.getvalue()


_WINDOW_LABELS = {'24h': 'Last 24 hours', '7d': 'Last 7 days', '30d': 'Last 30 days'}


def render_summary_pdf(
    stats: dict,
    timeline: list[dict],
    window: str,
    generated_by: str | None = None,
) -> bytes:
    """Render an aggregate threat-monitoring / operational summary report."""
    buffer = io.BytesIO()
    styles = _build_styles()
    doc = _new_document(buffer, 'ThreatLens AI | Threat monitoring summary report', 'ThreatLens AI Threat Summary Report')

    period = _WINDOW_LABELS.get(window, window)
    story: list[object] = [
        Paragraph('ThreatLens AI', styles['title']),
        Paragraph(
            f'Threat monitoring summary | {period} | '
            f'{datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}'
            + (f' | Generated by {_text(generated_by)}' if generated_by else ''),
            styles['subtitle'],
        ),
        Paragraph('Detection Overview', styles['heading']),
        _rows([
            ('Total detections', stats.get('total_detections')),
            ('Malicious', stats.get('malicious')),
            ('Suspicious', stats.get('suspicious')),
            ('Benign', stats.get('benign')),
            ('Detections in last 24h', stats.get('last_24h')),
            ('Detection rate', f"{stats.get('detection_rate', 0):.1%}" if stats.get('detection_rate') is not None else None),
            ('Open alerts', stats.get('open_alerts')),
            ('ML-only catches', stats.get('ml_only_catches')),
        ], styles),
        Paragraph('Breakdown by Risk Level', styles['heading']),
        _rows(list((stats.get('by_level') or {}).items()) or [('No data', 'Not available')], styles),
        Paragraph('Breakdown by Engine Agreement', styles['heading']),
        _rows(list((stats.get('by_agreement') or {}).items()) or [('No data', 'Not available')], styles),
        Paragraph('Top Malware Families', styles['heading']),
    ]

    top_families = stats.get('top_families') or []
    if top_families:
        story.append(_rows([(f['family'], f['count']) for f in top_families], styles))
    else:
        story.append(Paragraph('No malicious detections recorded in this period.', styles['body']))

    story.append(Paragraph(f'Activity Timeline ({period})', styles['heading']))
    if timeline:
        story.append(_rows(
            [(b['label'], f"{b['total']} total — {b['malicious']} malicious, {b['suspicious']} suspicious") for b in timeline],
            styles,
        ))
    else:
        story.append(Paragraph('No timeline data available.', styles['body']))

    doc.build(story)
    return buffer.getvalue()
