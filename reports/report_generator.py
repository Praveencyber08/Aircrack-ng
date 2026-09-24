"""Paginated, escaped PDF reports built from immutable assessment snapshots."""

from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


def build_report(path, assessment, username):
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="Kicker", fontSize=10, textColor=colors.HexColor("#087f75"), spaceAfter=18
        )
    )
    styles["Title"].fontSize = 29
    styles["Title"].leading = 36
    styles["Title"].alignment = 0
    styles["BodyText"].leading = 15
    styles["BodyText"].spaceAfter = 10
    styles["Heading2"].textColor = colors.HexColor("#087f75")
    styles["Heading2"].spaceBefore = 16
    facts = assessment.evidence

    def p(value, style="BodyText"):
        # Built-in PDF font supports Latin-1. Replace unsupported glyphs explicitly.
        safe = str(value).encode("latin-1", "replace").decode("latin-1")
        return Paragraph(escape(safe), styles[style])

    story = [
        Spacer(1, 1.5 * cm),
        p("SPECTRA / WIRELESS ASSURANCE", "Kicker"),
        p("Wi-Fi Security Assessment and Vulnerability Analysis Using Aircrack-ng", "Title"),
        Spacer(1, cm),
        p("Security assessment report", "Heading2"),
        p(facts["essid"], "Title"),
        p(f"BSSID: {facts['bssid']}"),
        p(
            "DEMO DATA - NOT LIVE NETWORK DATA"
            if facts["demo"]
            else "AUTHORIZED LABORATORY OBSERVATION",
            "Kicker",
        ),
        p(f"Assessment #{assessment.id} | {assessment.created_at.isoformat()} UTC"),
        p(f"Prepared by: {username}"),
        Spacer(1, cm),
        p(
            "Confidential - authorized laboratory use only. Classification is based only on collected evidence. No password testing, exploit validation or credential extraction was performed."
        ),
        PageBreak(),
        p("Executive summary", "Heading1"),
    ]
    severities = ["Critical", "High", "Medium", "Low", "Informational"]
    highest = min(
        (f.severity for f in assessment.findings), key=severities.index, default="Informational"
    )
    story += [
        p(
            f"The observed configuration produced {len(assessment.findings)} findings. The highest evidence-based classification is {highest}. These results describe observed configuration risks, not proof of compromise."
        ),
        p("Assessment scope and authorization", "Heading2"),
        p(
            f"Selected network: {facts['essid']} ({facts['bssid']}). Permission reference: {assessment.scope_reference}."
        ),
        p(
            "The analyst explicitly confirmed ownership or permission before this assessment. Authorization is recorded with the user, network and UTC timestamp. Demo authorization refers only to synthetic data."
        ),
        p("Network information and security configuration", "Heading2"),
    ]
    rows = [[p("Attribute"), p("Observed value")]]
    for key in (
        "essid",
        "bssid",
        "channel",
        "encryption",
        "cipher",
        "authentication",
        "signal",
        "last_seen",
    ):
        rows.append(
            [
                p(key.replace("_", " ").title()),
                p(facts.get(key) if facts.get(key) is not None else "Unknown"),
            ]
        )
    table = Table(rows, colWidths=[5 * cm, 11 * cm], repeatRows=1, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e5f4f1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#dce3e9")),
            ]
        )
    )
    story += [
        table,
        p("Evidence limitations", "Heading2"),
        p(
            "Evidence comes from scoped discovery observations. Signal strength is contextual, not a security rating. Capture metadata is reported separately in the application and is not used to infer password strength or handshake completeness. Firmware, router administration settings and exploitability require separate authorized verification."
        ),
        PageBreak(),
        p("Findings and recommendations", "Heading1"),
    ]
    for finding in assessment.findings:
        story.append(
            KeepTogether(
                [
                    p(f"{finding.severity.upper()} | {finding.title}", "Heading2"),
                    p(finding.description),
                ]
            )
        )
        for label, value in (
            ("Evidence", finding.evidence),
            ("Potential impact", finding.impact),
            ("Recommendation", finding.recommendation),
        ):
            story.append(p(f"{label}: {value}"))
    story += [
        p("Conclusion", "Heading2"),
        p(
            "Prioritize remediation of obsolete configurations, then validate the changed settings with another authorized assessment. WPA2 or WPA3 observations alone do not establish vulnerability or complete security."
        ),
        p("Assessment metadata", "Heading2"),
        p(
            f"Assessment ID: {assessment.id}. Network ID: {assessment.network_id}. User ID: {assessment.user_id}. UTC: {assessment.created_at.isoformat()}. Rule snapshot: {assessment.rules}."
        ),
        p("References", "Heading2"),
        p("Aircrack-ng documentation: https://www.aircrack-ng.org/doku.php?id=airodump-ng"),
        p("Scapy documentation: https://scapy.readthedocs.io/"),
    ]

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#dce3e9"))
        canvas.line(2 * cm, 1.7 * cm, 19 * cm, 1.7 * cm)
        canvas.setFont("Helvetica", 8)
        canvas.drawString(
            2 * cm,
            1.2 * cm,
            "SPECTRA | "
            + ("DEMO DATA - NOT LIVE NETWORK DATA" if facts["demo"] else "AUTHORIZED LAB"),
        )
        canvas.drawRightString(19 * cm, 1.2 * cm, f"Page {doc.page}")
        canvas.restoreState()

    SimpleDocTemplate(
        str(path),
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=1.8 * cm,
        bottomMargin=2.2 * cm,
        title="Wi-Fi Security Assessment",
        author=username,
    ).build(story, onFirstPage=footer, onLaterPages=footer)
