import os
import sys
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas to dynamically compute and render total page count."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_number(num_pages)
            super().showPage()
        super().save()

    def draw_page_number(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 9)
        self.setFillColor(colors.HexColor("#64748B"))
        
        # Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(54, 750, "API Security Assessment & Automated VAPT Framework — Q&A and Project Guide")
            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.5)
            self.line(54, 742, 558, 742)

        # Footer
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(54, 45, 558, 45)
        self.drawString(54, 32, "Confidential — Portfolio & Penetration Testing Interview Preparation Guide")
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(558, 32, page_str)
        self.restoreState()

def create_guide_pdf(filename="API_Security_VAPT_Project_Complete_Guide_and_QA.pdf"):
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()

    # Custom Color Palette
    PRIMARY = colors.HexColor("#0F172A")    # Deep Navy
    ACCENT = colors.HexColor("#4F46E5")     # Indigo
    SUCCESS = colors.HexColor("#059669")    # Emerald Green
    DANGER = colors.HexColor("#DC2626")     # Crimson Red
    TEXT_DARK = colors.HexColor("#1E293B")  # Slate 800
    TEXT_MUTED = colors.HexColor("#64748B") # Slate 500
    BG_LIGHT = colors.HexColor("#F8FAFC")   # Light Slate
    BORDER_COLOR = colors.HexColor("#E2E8F0")

    # Typography Styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=PRIMARY,
        spaceAfter=6
    )

    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=12,
        leading=16,
        textColor=ACCENT,
        spaceAfter=15
    )

    h1_style = ParagraphStyle(
        'Header1',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=15,
        leading=19,
        textColor=PRIMARY,
        spaceBefore=14,
        spaceAfter=8,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'Header2',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=ACCENT,
        spaceBefore=10,
        spaceAfter=4,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'DocBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=TEXT_DARK,
        spaceAfter=6
    )

    body_bold = ParagraphStyle(
        'DocBodyBold',
        parent=body_style,
        fontName='Helvetica-Bold'
    )

    q_box_style = ParagraphStyle(
        'QuestionStyle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10.5,
        leading=14.5,
        textColor=colors.HexColor("#1E1B4B")
    )

    code_style = ParagraphStyle(
        'CodeStyle',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8.5,
        leading=11.5,
        textColor=colors.HexColor("#0F172A")
    )

    story = []

    def make_q_box(q_text):
        p = Paragraph(f"<b>USER QUESTION:</b> \"{q_text}\"", q_box_style)
        t = Table([[p]], colWidths=[504])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#EEF2FF")),
            ('LEFTPADDING', (0,0), (-1,-1), 12),
            ('RIGHTPADDING', (0,0), (-1,-1), 12),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#C7D2FE")),
            ('LINELEFT', (0,0), (-1,-1), 4, ACCENT),
        ]))
        return t

    def make_code_box(code_text):
        p = Paragraph(code_text.replace("\n", "<br/>").replace(" ", "&nbsp;"), code_style)
        t = Table([[p]], colWidths=[504])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#F1F5F9")),
            ('LEFTPADDING', (0,0), (-1,-1), 10),
            ('RIGHTPADDING', (0,0), (-1,-1), 10),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
        ]))
        return t

    # =========================================================================
    # COVER / HEADER
    # =========================================================================
    story.append(Spacer(1, 15))
    story.append(Paragraph("API Security Assessment & Automated VAPT Framework", title_style))
    story.append(Paragraph("Comprehensive Technical Guide, Questions & Answers, Practical Labs, and Interview Manual", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=2, color=ACCENT, spaceBefore=4, spaceAfter=14))

    meta_table_data = [
        [Paragraph("<b>Target Framework:</b> OWASP API Security Top 10", body_style), Paragraph("<b>Language / Stack:</b> Python 3.14, Flask, SQLite, Burp Suite", body_style)],
        [Paragraph("<b>Assessment Status:</b> 16 Baseline Vulnerabilities Found", body_style), Paragraph("<b>Retest Remediation:</b> 100.0% Verified (0 False Positives)", body_style)]
    ]
    meta_table = Table(meta_table_data, colWidths=[250, 254])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), BG_LIGHT),
        ('BOX', (0,0), (-1,-1), 1, BORDER_COLOR),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('RIGHTPADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 14))

    # =========================================================================
    # SECTION 1: WHAT WAS BUILT
    # =========================================================================
    story.append(Paragraph("1. Project Architecture & What Was Built", h1_style))
    story.append(make_q_box("What did you build in this project, and what are all the components?"))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "The project is an enterprise-grade <b>API Vulnerability Assessment and Penetration Testing (VAPT) Framework</b>. "
        "It consists of four distinct engineering systems working in harmony:", body_style
    ))

    arch_items = [
        [Paragraph("<b>1. ShopVault REST API Testbed</b> (<code>api_testbed/</code>)", body_style),
         Paragraph("A realistic e-commerce and document-vault Flask API with SQLite database, multi-user accounts (Alice, Bob, Admin), and a dual security toggle: <b>Vulnerable Mode</b> (contains 16 real-world OWASP flaws) vs. <b>Secure Mode</b> (hardened production code).", body_style)],
        [Paragraph("<b>2. Automated Python VAPT Scanner</b> (<code>vapt_framework/</code>)", body_style),
         Paragraph("An automated scanning engine with 8 security modules executing algorithmic attacks against target endpoints. Features a strict <b>Scope Guard</b> enforcing testing boundaries.", body_style)],
        [Paragraph("<b>3. Multi-Format Reporting Engine</b> (<code>reports/</code>)", body_style),
         Paragraph("Automatically aggregates findings and generates an interactive dark-mode <b>HTML Dashboard</b>, raw <b>JSON</b>, and <b>Markdown</b> summaries with CVSS v3.1 scores.", body_style)],
        [Paragraph("<b>4. Retesting & Verification Suite</b> (<code>retest_engine.py</code>)", body_style),
         Paragraph("A regression engine that diffs baseline scans against hardened scans to mathematically certify patch effectiveness, calculate % remediation rates, and eliminate false positives.", body_style)]
    ]
    arch_table = Table(arch_items, colWidths=[160, 344])
    arch_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#F8FAFC")),
        ('GRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(arch_table)
    story.append(Spacer(1, 14))

    # =========================================================================
    # SECTION 2: STEP-BY-STEP EXECUTION
    # =========================================================================
    story.append(Paragraph("2. Step-by-Step Execution Guide & Windows Commands", h1_style))
    story.append(make_q_box("Tell me step by step what am I run and see the output result?"))
    story.append(Spacer(1, 6))
    story.append(Paragraph("<b>Option A: One-Click End-to-End Automated Demo</b>", h2_style))
    story.append(Paragraph("Run the all-in-one test suite which automatically starts the API, scans it, restarts in secure mode, and verifies fixes:", body_style))
    story.append(make_code_box("cd \"c:\\Users\\ASUS\\Desktop\\API Security Assessment & Automated VAPT Framework\"\npython run_demo.py"))
    story.append(Paragraph("<b>Terminal Output:</b> Phase 1 finds 16 vulnerabilities; Phase 2 verifies 0 remaining; Phase 3 certifies 100% remediation rate.", body_style))
    story.append(Spacer(1, 4))

    story.append(Paragraph("<b>Option B: Two-Terminal Manual Pentest Workflow</b>", h2_style))
    story.append(Paragraph("Simulating an authentic penetration test requires two Command Prompt windows:", body_style))
    
    cmd_data = [
        [Paragraph("<b>Terminal 1 (The Server)</b>", body_bold), Paragraph("<code>python -m api_testbed.app --port 5000 --reseed</code><br/><i>Keeps the website/API running on port 5000.</i>", body_style)],
        [Paragraph("<b>Terminal 2 (The Pentester)</b>", body_bold), Paragraph("<code>python vapt_cli.py --target http://127.0.0.1:5000</code><br/><i>Runs all 8 modules and finds 16 vulnerabilities.</i>", body_style)],
        [Paragraph("<b>Terminal 2 (Burp Suite Mode)</b>", body_bold), Paragraph("<code>python vapt_cli.py --proxy http://127.0.0.1:8080</code><br/><i>Routes all traffic through Burp Suite proxy.</i>", body_style)],
        [Paragraph("<b>Terminal 1 (Fix Mode)</b>", body_bold), Paragraph("Press <code>Ctrl+C</code>, then run: <code>python -m api_testbed.app --port 5000 --secure</code>", body_style)],
        [Paragraph("<b>Terminal 2 (Retest & Verify)</b>", body_bold), Paragraph("<code>python vapt_cli.py --target http://127.0.0.1:5000 --prefix vapt_retest --baseline reports\\vapt_scan.json</code>", body_style)]
    ]
    t_cmd = Table(cmd_data, colWidths=[150, 354])
    t_cmd.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('BACKGROUND', (0,0), (0,-1), BG_LIGHT),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(t_cmd)
    story.append(Spacer(1, 14))

    # =========================================================================
    # SECTION 3: ERRORS & SOLUTIONS
    # =========================================================================
    story.append(PageBreak())
    story.append(Paragraph("3. Troubleshooting Common Terminal Errors", h1_style))
    story.append(make_q_box("I saw errors like 'Start-Process is not recognized', 'WinError 10061', and 'unrecognized arguments'. Why did they happen?"))
    story.append(Spacer(1, 6))

    err_data = [
        [Paragraph("<b>Error 1: 'Start-Process' is not recognized</b>", body_bold),
         Paragraph("<b>Cause:</b> <code>Start-Process</code> is a PowerShell command, but you were in standard Windows Command Prompt (<code>cmd.exe</code>).<br/><b>Solution:</b> In Command Prompt, use <code>start</code> instead: <code>start reports\\vapt_baseline.html</code>", body_style)],
        [Paragraph("<b>Error 2: [WinError 10061] No connection could be made</b>", body_bold),
         Paragraph("<b>Cause:</b> The API server on port 5000 was stopped or not running when the scanner ran.<br/><b>Solution:</b> Keep Terminal 1 running the API first before launching the scanner in Terminal 2.", body_style)],
        [Paragraph("<b>Error 3: can't open file 'vapt_cli.py': No such file</b>", body_bold),
         Paragraph("<b>Cause:</b> The terminal was located in <code>C:\\Users\\ASUS></code> instead of the project directory.<br/><b>Solution:</b> Run <code>cd \"c:\\Users\\ASUS\\Desktop\\API Security Assessment & Automated VAPT Framework\"</code> first.", body_style)],
        [Paragraph("<b>Error 4: vapt_cli.py: error: unrecognized arguments</b>", body_bold),
         Paragraph("<b>Cause:</b> The command was accidentally pasted twice on one line (e.g. <code>...vapt_scan.jsonpython vapt_cli.py...</code>).<br/><b>Solution:</b> Copy and paste the single, clean command.", body_style)],
        [Paragraph("<b>Error 5: Unable to connect to proxy (port 8080)</b>", body_bold),
         Paragraph("<b>Cause:</b> <code>--proxy http://127.0.0.1:8080</code> was specified, but Burp Suite was not opened.<br/><b>Solution:</b> Omit <code>--proxy</code> for direct scanning, or open Burp Suite first.", body_style)]
    ]
    t_err = Table(err_data, colWidths=[160, 344])
    t_err.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#FEF2F2")),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(t_err)
    story.append(Spacer(1, 14))

    # =========================================================================
    # SECTION 4: CONCEPTUAL EXPLANATION
    # =========================================================================
    story.append(Paragraph("4. Simple Conceptual Explanation (The Bank & The Hacker)", h1_style))
    story.append(make_q_box("Can you explain simple and short what the project is and why two terminals are used?"))
    story.append(Spacer(1, 6))

    story.append(Paragraph(
        "Think of this project using a simple real-world analogy: <b>A Bank and a Security Guard</b>.", body_style
    ))
    story.append(Paragraph(
        "<b>1. The Bank (Terminal 1 — <code>api_testbed</code>):</b><br/>"
        "This terminal turns ON the web application on your computer (<code>http://127.0.0.1:5000</code>). "
        "It stores user accounts, secret corporate files, and balances. In 'Weak Mode', the bank doors have faulty locks.", body_style
    ))
    story.append(Paragraph(
        "<b>2. The Security Guard / Penetration Tester (Terminal 2 — <code>vapt_framework</code>):</b><br/>"
        "This terminal launches an automated Python robot that tries 8 different hacking techniques to test if anyone can break into the bank. "
        "It proves weaknesses by taking pictures (Proof-of-Concepts) and writing an audit report.", body_style
    ))
    story.append(Paragraph(
        "<b>Why 2 Terminals?</b> In real life, you cannot test a bank's security if the bank is closed! "
        "Terminal 1 keeps the bank open and alive. Terminal 2 acts as the security auditor testing it.", body_style
    ))
    story.append(Spacer(1, 14))

    # =========================================================================
    # SECTION 5: PRACTICAL BROWSER EXPERIMENT
    # =========================================================================
    story.append(PageBreak())
    story.append(Paragraph("5. Practical Hands-On Browser Exploitation Labs", h1_style))
    story.append(make_q_box("Show me in practical how can I understand betterly?"))
    story.append(Spacer(1, 6))

    story.append(Paragraph(
        "To understand vulnerabilities with your own eyes, you executed real attacks directly in your web browser:", body_style
    ))

    labs = [
        [Paragraph("<b>Lab 1: SQL Injection (Steal All Passwords)</b>", body_bold),
         Paragraph("<b>URL:</b> <code>http://127.0.0.1:5000/api/v1/products/search?q=' UNION SELECT id, username, password_hash, role, email, is_admin FROM users --</code><br/>"
                   "<b>Result:</b> The product search failed to validate input, dumping all user accounts and password hashes directly to the screen.", body_style)],
        [Paragraph("<b>Lab 2: Remote OS Command Injection</b>", body_bold),
         Paragraph("<b>URL:</b> <code>http://127.0.0.1:5000/api/v1/tools/ping?host=127.0.0.1 & whoami</code><br/>"
                   "<b>Result:</b> The network diagnostic tool passed raw input to the Windows command shell, executing <code>whoami</code> and revealing the computer's username.", body_style)],
        [Paragraph("<b>Lab 3: Secret Key Disclosure</b>", body_bold),
         Paragraph("<b>URL:</b> <code>http://127.0.0.1:5000/api/v1/tools/debug/config</code><br/>"
                   "<b>Result:</b> An unauthenticated debug endpoint exposed server secret keys (<code>secret123</code>) and environment paths.", body_style)],
        [Paragraph("<b>The Security Fix (Hardened Mode)</b>", body_bold),
         Paragraph("When restarted with <code>--secure</code>, all three URLs were refreshed:<br/>"
                   "• Lab 1 returned 0 products (safely parameterized queries with <code>?</code>).<br/>"
                   "• Lab 2 returned 'Invalid host parameter' (regex allowlist block).<br/>"
                   "• Lab 3 returned HTTP 404 Not Found (debug routes completely disabled).", body_style)]
    ]
    t_labs = Table(labs, colWidths=[160, 344])
    t_labs.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('BACKGROUND', (0,0), (0,-2), BG_LIGHT),
        ('BACKGROUND', (0,-1), (-1,-1), colors.HexColor("#F0FDF4")),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(t_labs)
    story.append(Spacer(1, 14))

    # =========================================================================
    # SECTION 6: UNDERSTANDING REPORTS & REMEDIATION
    # =========================================================================
    story.append(Paragraph("6. Understanding Reports, Remediation & Calculations", h1_style))
    story.append(make_q_box("Which website was tested? What does remediation mean? How does Python automatically calculate the reports?"))
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>Q: Which website did we test?</b>", body_bold))
    story.append(Paragraph(
        "You did <b>NOT</b> test an outside internet website like Google or Amazon (which is illegal without permission). "
        "You tested <b>ShopVault API</b> running locally inside your own machine at <code>http://127.0.0.1:5000</code>. "
        "In computer networking, <code>127.0.0.1</code> is the standard <b>loopback address (localhost)</b> meaning 'this computer'. "
        "Furthermore, your scanner has a built-in <b>Ethical Scope Guard</b> that strictly refuses to scan external URLs.", body_style
    ))
    story.append(Spacer(1, 4))

    story.append(Paragraph("<b>Q: What does 'Remediation' mean?</b>", body_bold))
    story.append(Paragraph(
        "<b>Remediation means 'The Security Fix'.</b> Finding a security hole is only half the job; writing the code patch "
        "to permanently repair the vulnerability is remediation.", body_style
    ))
    story.append(Spacer(1, 4))

    story.append(Paragraph("<b>Q: What is the Last Report (<code>retest_verification_report.html</code>)?</b>", body_bold))
    story.append(Paragraph(
        "In enterprise penetration testing, security teams must prove whether developers actually fixed reported flaws. "
        "The Retest Report compares your baseline scan (16 vulnerabilities) against the secure scan (0 vulnerabilities), "
        "mathematically certifying a <b>100.0% Remediation Rate with 0 False Positives</b>.", body_style
    ))
    story.append(Spacer(1, 4))

    story.append(Paragraph("<b>Q: How does Python automatically calculate the numbers and build the HTML?</b>", body_bold))
    story.append(Paragraph(
        "1. <b>Detection:</b> When an exploit succeeds, Python appends a <code>Vulnerability</code> object to a list.<br/>"
        "2. <b>Statistics Calculation:</b> Python calculates <code>Total = len(findings)</code> (16), counts by severity (Critical: 6, High: 7, Medium: 1, Low: 1, Info: 1), and computes:<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;<b>Remediation Rate %</b> = (Resolved Findings / Baseline Findings) × 100 = (16 / 16) × 100 = <b>100.0%</b>.<br/>"
        "3. <b>HTML Generation:</b> Python uses the <b>Jinja2</b> template engine to inject these values and interactive JavaScript accordions into <code>html_template.py</code>, writing the finished report to <code>reports/vapt_baseline.html</code>.", body_style
    ))
    story.append(Spacer(1, 14))

    # =========================================================================
    # SECTION 7: INTERVIEW DEMONSTRATION SCRIPT
    # =========================================================================
    story.append(PageBreak())
    story.append(Paragraph("7. Interview Walkthrough & Presentation Script", h1_style))
    story.append(make_q_box("If someone says: 'Show me your project and explain it', what should I say and show?"))
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>The 30-Second Elevator Pitch</b>", h2_style))
    story.append(Paragraph(
        "<i>\"This project is an Automated API Security Assessment & VAPT Framework built in Python. "
        "I built a dual-mode REST API testbed called ShopVault covering the OWASP API Security Top 10, "
        "and an automated multi-module scanner that tests endpoints, generates Proof-of-Concepts, "
        "and programmatically retests patches to achieve 100% verified remediation with zero false positives.\"</i>", body_style
    ))
    story.append(Spacer(1, 4))

    story.append(Paragraph("<b>The Live 3-Step Screen Demonstration</b>", h2_style))

    demo_steps = [
        [Paragraph("<b>Step 1: Run Live Demo</b>", body_bold),
         Paragraph("Run <code>python run_demo.py</code> in terminal.<br/>"
                   "<b>What to say:</b> <i>\"Here the framework launches the API, runs all 8 modules in Phase 1 finding 16 vulnerabilities, restarts in secure mode in Phase 2, and runs the retesting engine in Phase 3.\"</i>", body_style)],
        [Paragraph("<b>Step 2: Show Baseline Report</b>", body_bold),
         Paragraph("Run <code>start reports\\vapt_baseline.html</code>.<br/>"
                   "<b>What to say:</b> Point to <b>VAPT-BOLA-001</b> and explain: <i>\"Here, User Bob accessed Alice's confidential M&A strategy documents by changing ID from 2 to 1 due to missing object authorization.\"</i> Then show SQL injection dumping password hashes.", body_style)],
        [Paragraph("<b>Step 3: Show Retest Report</b>", body_bold),
         Paragraph("Run <code>start reports\\retest_verification_report.html</code>.<br/>"
                   "<b>What to say:</b> <i>\"This is the fix verification audit. It automatically compares the baseline vs. retest scan, confirming that all 16 vulnerabilities were resolved (100% remediation) with zero false positives.\"</i>", body_style)]
    ]
    t_demo = Table(demo_steps, colWidths=[150, 354])
    t_demo.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('BACKGROUND', (0,0), (0,-1), BG_LIGHT),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(t_demo)
    story.append(Spacer(1, 10))

    story.append(Paragraph("<b>Top Interview Questions & Winning Answers</b>", h2_style))
    story.append(Paragraph(
        "<b>Q: How did you test BOLA without high false positives?</b><br/>"
        "<i>\"Simple fuzzing produces high false positives. My framework implements <b>dual-identity cross-tenant testing</b>. "
        "It authenticates as both a victim (Alice) and an attacker (Bob). It uses Bob's token to request Alice's resource. "
        "Only if the response returns HTTP 200 AND contains Alice's private ID and data is a BOLA flaw flagged.\"</i>", body_style
    ))
    story.append(Paragraph(
        "<b>Q: Can this framework work with Burp Suite?</b><br/>"
        "<i>\"Yes. The CLI includes a <code>--proxy http://127.0.0.1:8080</code> flag that routes all scanner requests through Burp Suite, "
        "plus pre-configured raw <code>.http</code> request files for manual validation in Burp Repeater.\"</i>", body_style
    ))
    story.append(Spacer(1, 14))

    # =========================================================================
    # SECTION 8: RESUME BULLETS
    # =========================================================================
    story.append(Paragraph("8. Resume & Portfolio Entry", h1_style))
    story.append(Paragraph(
        "<b>Project: API Security Assessment & Automated VAPT Framework</b><br/>"
        "<b>Technologies:</b> Python, Flask, REST APIs, Burp Suite, OWASP API Security Top 10, SQLite, PyJWT<br/>"
        "• Engineered an automated API security testing framework in Python with 8 specialized modules covering the OWASP API Security Top 10.<br/>"
        "• Developed ShopVault REST API, a dual-mode (Vulnerable vs. Hardened) Flask/SQLite testbed to simulate attack scenarios and remediations.<br/>"
        "• Automated dual-token cross-tenant testing to detect Broken Object Level Authorization (BOLA) across private user documents and orders.<br/>"
        "• Implemented an automated Retesting & Verification Engine that programmatically compares baseline and post-remediation scans, achieving a 100% verified remediation rate and eliminating false positives.<br/>"
        "• Integrated upstream Burp Suite proxy routing and built an interactive HTML reporting dashboard with CVSS v3.1 scoring, wire-level HTTP PoCs, and actionable remediation guidance.", body_style
    ))

    # Build Document using NumberedCanvas
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"[+] PDF generated successfully: {filename}")
    return os.path.abspath(filename)

if __name__ == "__main__":
    create_guide_pdf()
