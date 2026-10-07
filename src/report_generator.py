"""
PDF Report Generator for PhishGuard AI.
Produces professional, multi-section cybersecurity audit reports using ReportLab,
incorporating scan metadata, model predictions, feature metrics, explainable indicators,
threat intelligence, and formal risk disclaimers.
"""

from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

from src.config import GENERATED_REPORTS_DIR
from src.utils import setup_logger

logger = setup_logger("ReportGenerator")


class SecurityReportGenerator:
    """
    Generates formal PDF audit reports for scanned URLs.
    """

    def __init__(self, output_dir: Path = GENERATED_REPORTS_DIR):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_pdf(
        self,
        scan_data: Dict[str, Any],
        output_filename: Optional[str] = None
    ) -> Path:
        """
        Builds the PDF document and writes it to disk.

        Returns:
            Path to the generated PDF report.
        """
        scan_id = scan_data.get("id") or scan_data.get("scan_id") or "UNSAVED"
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        if not output_filename:
            output_filename = f"PhishGuard_Report_Scan_{scan_id}_{timestamp_str}.pdf"

        file_path = self.output_dir / output_filename

        doc = SimpleDocTemplate(
            str(file_path),
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()

        # Custom typography styles
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#0F172A"),  # Slate 900
            fontName="Helvetica-Bold",
            spaceAfter=4
        )
        tagline_style = ParagraphStyle(
            "DocTagline",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#64748B"),  # Slate 500
            fontName="Helvetica",
            spaceAfter=12
        )
        h2_style = ParagraphStyle(
            "SectionH2",
            parent=styles["Heading2"],
            fontSize=12,
            leading=16,
            textColor=colors.HexColor("#1E293B"),
            fontName="Helvetica-Bold",
            spaceBefore=10,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            "BodyDark",
            parent=styles["Normal"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#334155"),
            fontName="Helvetica"
        )
        disclaimer_style = ParagraphStyle(
            "Disclaimer",
            parent=styles["Normal"],
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#64748B"),
            fontName="Helvetica-Oblique"
        )

        story = []

        # 1. Header Banner
        story.append(Paragraph("🛡️ PHISHGUARD AI", title_style))
        story.append(Paragraph("Explainable AI-Based Phishing URL Detection and Risk Analysis System", tagline_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2563EB"), spaceAfter=12))

        # 2. Section: Scan Information
        story.append(Paragraph("1. SCAN INFORMATION", h2_style))
        scan_info_data = [
            [
                Paragraph("<b>Scan Reference:</b>", body_style),
                Paragraph(f"#{scan_id}", body_style),
                Paragraph("<b>Audit Date/Time:</b>", body_style),
                Paragraph(str(scan_data.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))), body_style)
            ],
            [
                Paragraph("<b>Submitted URL:</b>", body_style),
                Paragraph(str(scan_data.get("url", "")), body_style),
                Paragraph("<b>Normalized URL:</b>", body_style),
                Paragraph(str(scan_data.get("normalized_url", "")), body_style)
            ]
        ]
        info_table = Table(scan_info_data, colWidths=[100, 170, 100, 170])
        info_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(info_table)
        story.append(Spacer(1, 10))

        # 3. Section: Final Assessment & Risk Score
        story.append(Paragraph("2. FINAL RISK ASSESSMENT", h2_style))
        classification = str(scan_data.get("classification", "UNKNOWN")).upper()
        risk_score = float(scan_data.get("risk_score", 0.0))

        if classification == "SAFE":
            badge_bg = colors.HexColor("#DCFCE7")  # Green 100
            badge_fg = colors.HexColor("#166534")  # Green 800
            badge_text = f"🟢 SAFE (Risk Score: {risk_score}/100)"
        elif classification == "SUSPICIOUS":
            badge_bg = colors.HexColor("#FEF3C7")  # Amber 100
            badge_fg = colors.HexColor("#92400E")  # Amber 800
            badge_text = f"🟠 SUSPICIOUS (Risk Score: {risk_score}/100)"
        else:
            badge_bg = colors.HexColor("#FEE2E2")  # Red 100
            badge_fg = colors.HexColor("#991B1B")  # Red 800
            badge_text = f"🔴 PHISHING (Risk Score: {risk_score}/100)"

        assessment_style = ParagraphStyle(
            "BadgeStyle",
            parent=styles["Normal"],
            fontSize=13,
            leading=16,
            textColor=badge_fg,
            fontName="Helvetica-Bold",
            alignment=1
        )

        assessment_data = [
            [Paragraph(f"<b>FINAL CLASSIFICATION:</b> {badge_text}", assessment_style)],
            [Paragraph(str(scan_data.get("reason_summary", "Automated heuristic and multi-model consensus assessment.")), body_style)]
        ]
        assessment_table = Table(assessment_data, colWidths=[540])
        assessment_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), badge_bg),
            ("BACKGROUND", (0, 1), (0, 1), colors.HexColor("#FFFFFF")),
            ("BOX", (0, 0), (-1, -1), 1, badge_fg),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ]))
        story.append(assessment_table)
        story.append(Spacer(1, 10))

        # 4. Section: ML Model Predictions & Ensemble
        story.append(Paragraph("3. MACHINE LEARNING MODEL CONSENSUS", h2_style))
        lr_pred = scan_data.get("lr_prediction", "N/A")
        dt_pred = scan_data.get("dt_prediction", "N/A")
        rf_pred = scan_data.get("rf_prediction", "N/A")
        ens_prob = scan_data.get("ensemble_prob", 0.0)

        ml_rows = [
            [
                Paragraph("<b>Classifier</b>", body_style),
                Paragraph("<b>Algorithm Type</b>", body_style),
                Paragraph("<b>Prediction</b>", body_style),
                Paragraph("<b>Weight in Ensemble</b>", body_style)
            ],
            [
                Paragraph("Random Forest", body_style),
                Paragraph("Ensemble Decision Trees (100 estimators)", body_style),
                Paragraph(f"<b>{rf_pred}</b>", body_style),
                Paragraph("50%", body_style)
            ],
            [
                Paragraph("Decision Tree", body_style),
                Paragraph("Single CART Split (Depth=10)", body_style),
                Paragraph(f"<b>{dt_pred}</b>", body_style),
                Paragraph("25%", body_style)
            ],
            [
                Paragraph("Logistic Regression", body_style),
                Paragraph("L2-Regularized Linear Classifier (StandardScaled)", body_style),
                Paragraph(f"<b>{lr_pred}</b>", body_style),
                Paragraph("25%", body_style)
            ],
            [
                Paragraph("<b>Final Weighted Ensemble</b>", body_style),
                Paragraph(f"Phishing Probability: {float(ens_prob)*100:.1f}%", body_style),
                Paragraph(f"<b>{classification}</b>", body_style),
                Paragraph("100%", body_style)
            ]
        ]
        ml_table = Table(ml_rows, colWidths=[120, 200, 110, 110])
        ml_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
            ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#F1F5F9")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(ml_table)
        story.append(Spacer(1, 10))

        # 5. Section: Extracted Structural & Lexical Features
        story.append(Paragraph("4. KEY EXTRACTED URL FEATURES", h2_style))
        features = scan_data.get("features", {})
        if not features and "features_json" in scan_data:
            import json
            features = json.loads(scan_data["features_json"] or "{}")

        feat_rows = [
            [
                Paragraph("<b>Feature Name</b>", body_style),
                Paragraph("<b>Extracted Value</b>", body_style),
                Paragraph("<b>Feature Name</b>", body_style),
                Paragraph("<b>Extracted Value</b>", body_style)
            ],
            [
                Paragraph("URL Total Length", body_style),
                Paragraph(str(features.get("url_length", "N/A")), body_style),
                Paragraph("HTTPS Present", body_style),
                Paragraph("Yes (1)" if features.get("is_https") == 1 else "No (0)", body_style)
            ],
            [
                Paragraph("Domain Length", body_style),
                Paragraph(str(features.get("domain_length", "N/A")), body_style),
                Paragraph("Raw IP Address Host", body_style),
                Paragraph("Yes (1)" if features.get("is_ip_address") == 1 else "No (0)", body_style)
            ],
            [
                Paragraph("Subdomain Count", body_style),
                Paragraph(str(features.get("qty_subdomains", "N/A")), body_style),
                Paragraph("URL Shortener Detected", body_style),
                Paragraph("Yes (1)" if features.get("is_shortened") == 1 else "No (0)", body_style)
            ],
            [
                Paragraph("Hyphen Count", body_style),
                Paragraph(str(features.get("qty_hyphen", "N/A")), body_style),
                Paragraph("Suspicious Keywords Count", body_style),
                Paragraph(str(features.get("qty_suspicious_keywords", 0)), body_style)
            ],
            [
                Paragraph("Shannon Entropy", body_style),
                Paragraph(f"{float(features.get('url_entropy', 0.0)):.2f} bits", body_style),
                Paragraph("Suspicious TLD Flag", body_style),
                Paragraph("Yes (1)" if features.get("is_suspicious_tld") == 1 else "No (0)", body_style)
            ]
        ]
        feat_table = Table(feat_rows, colWidths=[140, 130, 140, 130])
        feat_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(feat_table)
        story.append(Spacer(1, 10))

        # 6. Section: Explainable Security Reasoning
        explanation = scan_data.get("explanation", {})
        suspicious_flags = explanation.get("suspicious_reasons", [])
        positive_flags = explanation.get("positive_indicators", [])

        if suspicious_flags or positive_flags:
            story.append(Paragraph("5. EXPLAINABLE AI INDICATORS", h2_style))
            exp_rows = [
                [
                    Paragraph("<b>Indicator Type</b>", body_style),
                    Paragraph("<b>Observation Title</b>", body_style),
                    Paragraph("<b>Technical Analysis Detail</b>", body_style)
                ]
            ]
            for s in suspicious_flags[:4]:
                exp_rows.append([
                    Paragraph("<font color='#EF4444'><b>[SUSPICIOUS]</b></font>", body_style),
                    Paragraph(f"<b>{s.get('title', '')}</b>", body_style),
                    Paragraph(s.get("detail", ""), body_style)
                ])
            for p in positive_flags[:3]:
                exp_rows.append([
                    Paragraph("<font color='#10B981'><b>[POSITIVE]</b></font>", body_style),
                    Paragraph(f"<b>{p.get('title', '')}</b>", body_style),
                    Paragraph(p.get("detail", ""), body_style)
                ])

            exp_table = Table(exp_rows, colWidths=[90, 150, 300])
            exp_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(exp_table)
            story.append(Spacer(1, 10))

        # 7. Threat Intelligence (if present)
        threat_intel = scan_data.get("threat_intel")
        if threat_intel and threat_intel.get("status") == "success":
            story.append(Paragraph("6. SUPPLEMENTARY THREAT INTELLIGENCE", h2_style))
            dns_info = threat_intel.get("dns", {})
            ssl_info = threat_intel.get("ssl", {})
            whois_info = threat_intel.get("whois", {})

            intel_rows = [
                [
                    Paragraph("<b>Signal</b>", body_style),
                    Paragraph("<b>Result Detail</b>", body_style)
                ],
                [
                    Paragraph("DNS Resolved IPs", body_style),
                    Paragraph(", ".join(dns_info.get("ip_addresses", [])) or "None resolved", body_style)
                ],
                [
                    Paragraph("SSL/TLS Certificate", body_style),
                    Paragraph(f"Issuer: {ssl_info.get('issuer', 'N/A')} (Expires: {ssl_info.get('valid_until', 'N/A')})", body_style)
                ],
                [
                    Paragraph("WHOIS Registrar / Age", body_style),
                    Paragraph(f"Registrar: {whois_info.get('registrar', 'N/A')} | Age: {whois_info.get('domain_age_days', 'N/A')} days", body_style)
                ]
            ]
            intel_table = Table(intel_rows, colWidths=[150, 390])
            intel_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(intel_table)
            story.append(Spacer(1, 10))

        # 8. Disclaimer (Mandatory)
        story.append(Spacer(1, 8))
        story.append(HRFlowable(width="100%", thickness=0.75, color=colors.HexColor("#94A3B8"), spaceAfter=6))
        story.append(Paragraph(
            "<b>DISCLAIMER:</b> This tool provides an automated risk assessment and should not be treated "
            "as absolute proof that a website is malicious or safe. URL-only heuristic and machine-learning "
            "analysis operates on structural and lexical indicators without guaranteeing real-time server-side safety.",
            disclaimer_style
        ))

        # Build Document
        doc.build(story)
        logger.info(f"Generated PDF security report at: {file_path}")
        return file_path
