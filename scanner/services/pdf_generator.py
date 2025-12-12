"""
PDF Report Generator Service

Generates PDF reports from scan results using ReportLab.
"""

from io import BytesIO
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT


class PDFReportGenerator:
    """Generates PDF reports from scan results."""
    
    # Color definitions - Dunetrails Theme
    PRIMARY_COLOR = colors.HexColor('#31469D')    # Deep Blue
    ACCENT_COLOR = colors.HexColor('#D97B46')     # Muted Orange
    SUCCESS_COLOR = colors.HexColor('#10b981')
    WARNING_COLOR = colors.HexColor('#D97B46')    # Muted Orange
    ERROR_COLOR = colors.HexColor('#ef4444')
    MUTED_COLOR = colors.HexColor('#6b7394')
    
    GRADE_COLORS = {
        'A+': colors.HexColor('#10b981'),
        'A': colors.HexColor('#34d399'),
        'B': colors.HexColor('#31469D'),
        'C': colors.HexColor('#D97B46'),
        'D': colors.HexColor('#f59e0b'),
        'E': colors.HexColor('#f97316'),
        'F': colors.HexColor('#ef4444'),
    }
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Set up custom paragraph styles."""
        self.styles.add(ParagraphStyle(
            name='ZSTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=self.PRIMARY_COLOR,
            spaceAfter=6,
        ))
        
        self.styles.add(ParagraphStyle(
            name='ZSSubTitle',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=self.MUTED_COLOR,
            spaceAfter=12,
        ))
        
        self.styles.add(ParagraphStyle(
            name='ZSDomainName',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.black,
            spaceAfter=4,
        ))
        
        self.styles.add(ParagraphStyle(
            name='ZSSectionHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=self.PRIMARY_COLOR,
            spaceBefore=16,
            spaceAfter=8,
        ))
        
        self.styles.add(ParagraphStyle(
            name='ZSMessageSuccess',
            parent=self.styles['Normal'],
            fontSize=9,
            textColor=self.SUCCESS_COLOR,
            leftIndent=10,
            spaceAfter=2,
        ))
        
        self.styles.add(ParagraphStyle(
            name='ZSMessageWarning',
            parent=self.styles['Normal'],
            fontSize=9,
            textColor=self.WARNING_COLOR,
            leftIndent=10,
            spaceAfter=2,
        ))
        
        self.styles.add(ParagraphStyle(
            name='ZSMessageError',
            parent=self.styles['Normal'],
            fontSize=9,
            textColor=self.ERROR_COLOR,
            leftIndent=10,
            spaceAfter=2,
        ))
        
        self.styles.add(ParagraphStyle(
            name='ZSMessageInfo',
            parent=self.styles['Normal'],
            fontSize=9,
            textColor=self.MUTED_COLOR,
            leftIndent=10,
            spaceAfter=2,
        ))
        
        self.styles.add(ParagraphStyle(
            name='ZSRemediation',
            parent=self.styles['Normal'],
            fontSize=9,
            textColor=colors.black,
            leftIndent=15,
            spaceAfter=4,
        ))
    
    def generate(self, scan_result: dict) -> bytes:
        """
        Generate a PDF report from scan results.
        
        Args:
            scan_result: Dictionary containing scan results
            
        Returns:
            PDF file as bytes
        """
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=20*mm,
            leftMargin=20*mm,
            topMargin=20*mm,
            bottomMargin=20*mm,
        )
        
        elements = []
        
        # Header
        elements.append(Paragraph("ZeroSpoof Email Security Report", self.styles['ZSTitle']))
        elements.append(Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')} | Score Profile v{scan_result.get('score_version', '1.0')}",
            self.styles['ZSSubTitle']
        ))
        
        elements.append(Spacer(1, 10))
        
        # Domain info
        elements.append(Paragraph(f"Domain: {scan_result.get('domain', 'Unknown')}", self.styles['ZSDomainName']))
        
        provider = scan_result.get('provider', 'unknown')
        provider_display = {
            'microsoft365': 'Microsoft 365',
            'google_workspace': 'Google Workspace',
        }.get(provider, provider.replace('_', ' ').title())
        
        elements.append(Paragraph(f"Provider: {provider_display}", self.styles['ZSSubTitle']))
        
        elements.append(Spacer(1, 10))
        
        # Score summary table
        score = scan_result.get('score', 0)
        grade = scan_result.get('grade', 'F')
        grade_color = self.GRADE_COLORS.get(grade, self.ERROR_COLOR)
        
        score_data = [
            ['Overall Score', 'Grade'],
            [f"{score}/100", grade],
        ]
        
        score_table = Table(score_data, colWidths=[80*mm, 40*mm], rowHeights=[None, 20*mm])
        score_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f0f0f5')),
            ('TEXTCOLOR', (0, 0), (-1, 0), self.PRIMARY_COLOR),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('FONTSIZE', (0, 1), (0, 1), 20),
            ('FONTSIZE', (1, 1), (1, 1), 24),
            ('TEXTCOLOR', (0, 1), (0, 1), self.PRIMARY_COLOR),
            ('TEXTCOLOR', (1, 1), (1, 1), grade_color),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('TOPPADDING', (0, 1), (-1, 1), 8),
            ('BOTTOMPADDING', (0, 1), (-1, 1), 8),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#e0e0e0')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e0e0e0')),
        ]))
        elements.append(score_table)
        
        elements.append(Spacer(1, 20))
        
        # Control sections
        controls = [
            ('MX Records', 'mx', 10),
            ('SPF (Sender Policy Framework)', 'spf', 25),
            ('DKIM (DomainKeys Identified Mail)', 'dkim', 25),
            ('DMARC (Domain-based Message Authentication)', 'dmarc', 40),
        ]
        
        checks = scan_result.get('checks', {})
        
        for control_name, control_key, max_points in controls:
            check = checks.get(control_key, {})
            points = check.get('points', 0)
            
            # Section header with score
            score_pct = (points / max_points * 100) if max_points > 0 else 0
            if score_pct >= 80:
                score_color = self.SUCCESS_COLOR
            elif score_pct >= 50:
                score_color = self.WARNING_COLOR
            else:
                score_color = self.ERROR_COLOR
            
            header_text = f"{control_name} - <font color='{score_color.hexval()}'>{points}/{max_points}</font>"
            elements.append(Paragraph(header_text, self.styles['ZSSectionHeader']))
            
            # Messages
            messages = check.get('messages', [])
            for msg in messages:
                level = msg.get('level', 'info')
                text = msg.get('text', '')
                
                style_name = {
                    'success': 'ZSMessageSuccess',
                    'warning': 'ZSMessageWarning',
                    'error': 'ZSMessageError',
                }.get(level, 'ZSMessageInfo')
                
                icon = {
                    'success': '[OK]',
                    'warning': '[!]',
                    'error': '[X]',
                }.get(level, '[i]')
                
                elements.append(Paragraph(f"{icon} {text}", self.styles[style_name]))
        
        # Remediation section
        remediation = scan_result.get('remediation', [])
        if remediation:
            elements.append(Spacer(1, 20))
            elements.append(Paragraph(
                "<font color='#f59e0b'>Recommended Actions</font>",
                self.styles['ZSSectionHeader']
            ))
            
            # Remove duplicates while preserving order
            seen = set()
            unique_remediation = []
            for item in remediation:
                if item not in seen:
                    seen.add(item)
                    unique_remediation.append(item)
            
            for i, item in enumerate(unique_remediation, 1):
                elements.append(Paragraph(f"{i}. {item}", self.styles['ZSRemediation']))
        
        # Build PDF
        doc.build(elements)
        
        pdf_bytes = buffer.getvalue()
        buffer.close()
        
        return pdf_bytes


def generate_pdf_report(scan_result: dict) -> bytes:
    """
    Convenience function to generate PDF report.
    
    Args:
        scan_result: Dictionary containing scan results
        
    Returns:
        PDF file as bytes
    """
    generator = PDFReportGenerator()
    return generator.generate(scan_result)
