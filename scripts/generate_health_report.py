#!/usr/bin/env python3
"""
Enterprise Infrastructure Health-Check Excel Report Generator
Generates an 18-worksheet comprehensive health-check workbook with formatting,
filters, conditional styling, and KPI metrics.
"""

import sys
import os
import datetime
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

# Theme Colors
HEADER_FILL = PatternFill(start_color="1F4E78", end_color="1F4E78", fill_type="solid")
HEADER_FONT = Font(name="Segoe UI", size=11, bold=True, color="FFFFFF")
SUBHEADER_FILL = PatternFill(start_color="D9E1F2", end_color="D9E1F2", fill_type="solid")
SUBHEADER_FONT = Font(name="Segoe UI", size=10, bold=True, color="1F4E78")

KPI_TITLE_FONT = Font(name="Segoe UI", size=9, bold=True, color="595959")
KPI_VAL_CRIT = Font(name="Segoe UI", size=16, bold=True, color="C00000")
KPI_VAL_WARN = Font(name="Segoe UI", size=16, bold=True, color="ED7D31")
KPI_VAL_OK = Font(name="Segoe UI", size=16, bold=True, color="385723")
KPI_VAL_INFO = Font(name="Segoe UI", size=16, bold=True, color="1F4E78")

BORDER_THIN = Border(
    left=Side(style='thin', color='D9D9D9'),
    right=Side(style='thin', color='D9D9D9'),
    top=Side(style='thin', color='D9D9D9'),
    bottom=Side(style='thin', color='D9D9D9')
)

SEVERITY_FILLS = {
    "CRITICAL": PatternFill(start_color="F8CBAD", end_color="F8CBAD", fill_type="solid"),
    "HIGH": PatternFill(start_color="FCE4D6", end_color="FCE4D6", fill_type="solid"),
    "MEDIUM": PatternFill(start_color="FFF2CC", end_color="FFF2CC", fill_type="solid"),
    "LOW": PatternFill(start_color="E2EFDA", end_color="E2EFDA", fill_type="solid"),
    "INFO": PatternFill(start_color="D9E1F2", end_color="D9E1F2", fill_type="solid"),
    "HEALTHY": PatternFill(start_color="E2EFDA", end_color="E2EFDA", fill_type="solid"),
    "WARNING": PatternFill(start_color="FFF2CC", end_color="FFF2CC", fill_type="solid"),
    "DEGRADED": PatternFill(start_color="FCE4D6", end_color="FCE4D6", fill_type="solid"),
}

SEVERITY_FONTS = {
    "CRITICAL": Font(name="Segoe UI", size=10, bold=True, color="C00000"),
    "HIGH": Font(name="Segoe UI", size=10, bold=True, color="C65911"),
    "MEDIUM": Font(name="Segoe UI", size=10, bold=True, color="833C0C"),
    "LOW": Font(name="Segoe UI", size=10, bold=False, color="385723"),
    "INFO": Font(name="Segoe UI", size=10, bold=False, color="1F4E78"),
    "HEALTHY": Font(name="Segoe UI", size=10, bold=True, color="385723"),
    "WARNING": Font(name="Segoe UI", size=10, bold=True, color="B25E00"),
    "DEGRADED": Font(name="Segoe UI", size=10, bold=True, color="C65911"),
}

WORKSHEET_DEFINITIONS = [
    ("Executive Summary", ["Metric / Category", "Value", "Status", "Notes"]),
    ("Infrastructure Inventory", ["Hostname", "FQDN", "IP Address", "OS Version", "OS Build", "Role / Workload", "CPUs", "RAM (GB)", "Disk (GB)", "Free Disk (GB)", "Virtual/Physical", "Status"]),
    ("Windows Health", ["Hostname", "Uptime", "Pending Reboot", "Failed Services", "Critical Event Count", "Time Sync Source", "Firewall Status", "Antivirus/EDR", "Disk Space Alert", "Health Status"]),
    ("Active Directory Health", ["Domain Controller", "Site", "FSMO Roles", "SYSVOL Status", "Netlogon", "Replication Partner", "Repl Failures", "DCDiag Summary", "Tombstone State", "Status"]),
    ("DNS Health", ["Server / Zone", "Type", "AD-Integrated", "Forwarders", "Scavenging Enabled", "Stale Records Count", "Resolution Test", "Status", "Remarks"]),
    ("DHCP Health", ["Scope ID", "Scope Name", "State", "Subnet Mask", "Total IPs", "In Use", "Free", "Utilization %", "Failover Partner", "Failover State", "Status"]),
    ("VMware vCenter Health", ["vCenter FQDN", "Version/Build", "Service State", "Active Alarms", "SSO Domain", "DB Storage Free %", "NTP Status", "Overall Health"]),
    ("ESXi Host Health", ["Host Name", "Cluster", "ESXi Version", "CPU Sockets/Cores", "CPU Ready %", "Memory (GB)", "Memory Ballooning", "Hyperthreading", "Connection State", "Host Alarms", "Status"]),
    ("VM Health", ["VM Name", "Host", "Datastore", "Power State", "vCPU", "vRAM (GB)", "VM Tools State", "Hardware Version", "Snapshot Count", "Oldest Snapshot (Hours)", "Status"]),
    ("Storage Health", ["Datastore / LUN", "Storage Type", "Capacity (GB)", "Free Space (GB)", "Free %", "Thin Provisioned", "Avg Latency (ms)", "Multipath Policy", "Path Count", "Health Status"]),
    ("Backup Health", ["Protected Entity", "Backup Job Name", "Schedule", "Last Run Time", "Result", "Backup Age (Hours)", "RPO Target (Hours)", "RPO Met", "Repository Free %", "Status"]),
    ("Security & Hardening", ["Component / Host", "Control Name", "Benchmark Requirement", "Current Setting", "Compliance State", "Risk Severity", "Remediation Recommendation"]),
    ("Performance", ["Resource / Host", "Metric Name", "Current Value", "Warning Threshold", "Critical Threshold", "Peak Time", "Contention Detected", "Status"]),
    ("Issues & Findings", ["Issue ID", "Date/Time", "Category", "Component", "Host", "Environment", "Severity", "Status", "Finding", "Evidence", "Root Cause", "Impact", "Recommendation", "Risk", "Rollback Plan", "Requires Approval", "Approval Status", "Remediation Status", "Validation Status"]),
    ("Recommended Remediation", ["Issue ID", "Category", "Target System", "Recommended Action", "Detailed Steps", "Prerequisites", "Risk Level", "Expected Downtime", "Rollback Procedure", "Approval Required"]),
    ("Remediation Approval", ["Change ID", "Issue ID", "Target System", "Proposed Action", "Risk", "Approval Status", "Approved By", "Approval Timestamp", "Execution Window", "Scope Constraints"]),
    ("Remediation History", ["Change ID", "Issue ID", "Execution Date", "Operator", "Target System", "Action Taken", "Before State", "After State", "Result", "Duration (Sec)", "Notes"]),
    ("Validation Results", ["Validation ID", "Change ID", "Issue ID", "Validation Check", "Expected Result", "Actual Result", "Validation Status", "Verified At", "Verified By", "Final Sign-off"])
]

def format_sheet(ws, title, headers, data=None):
    ws.title = title
    ws.views.sheetView[0].showGridLines = True
    
    # Title Row
    ws.merge_cells("A1:D1")
    title_cell = ws["A1"]
    title_cell.value = f"ENTERPRISE INFRASTRUCTURE OPERATIONS - {title.upper()}"
    title_cell.font = Font(name="Segoe UI", size=13, bold=True, color="1F4E78")
    
    meta_cell = ws["A2"]
    meta_cell.value = f"Report Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Assessment Engine: Enterprise Infrastructure Operations CoE"
    meta_cell.font = Font(name="Segoe UI", size=9, italic=True, color="595959")
    
    # Header Row
    start_row = 4
    for col_idx, header in enumerate(headers, start=1):
        cell = ws.cell(row=start_row, column=col_idx, value=header)
        cell.fill = HEADER_FILL
        cell.font = HEADER_FONT
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        cell.border = BORDER_THIN

    ws.row_dimensions[start_row].height = 26
    
    # Data Rows
    current_row = start_row + 1
    if data:
        for row_data in data:
            for col_idx, val in enumerate(row_data, start=1):
                cell = ws.cell(row=current_row, column=col_idx, value=val)
                cell.font = Font(name="Segoe UI", size=10)
                cell.border = BORDER_THIN
                cell.alignment = Alignment(vertical="center")
                
                # Check for severity/status styling
                s_val = str(val).upper().strip()
                if s_val in SEVERITY_FILLS:
                    cell.fill = SEVERITY_FILLS[s_val]
                    cell.font = SEVERITY_FONTS[s_val]
                    cell.alignment = Alignment(horizontal="center", vertical="center")
            current_row += 1
            
    # Auto-adjust column widths
    for col in ws.columns:
        max_len = 0
        col_letter = get_column_letter(col[0].column)
        for cell in col:
            # Skip merged banner in row 1 & 2 for width calculation
            if cell.row in [1, 2]:
                continue
            if cell.value:
                val_str = str(cell.value)
                max_len = max(max_len, len(val_str.split("\n")[0]))
        ws.column_dimensions[col_letter].width = max(max_len + 4, 14)
        
    # Enable AutoFilter and Freeze Panes
    last_col = get_column_letter(len(headers))
    ws.auto_filter.ref = f"A{start_row}:{last_col}{max(current_row-1, start_row)}"
    ws.freeze_panes = f"A{start_row + 1}"

def create_report(output_path="reports/Enterprise_Infrastructure_Health_Check.xlsx", assessment_data=None):
    wb = Workbook()
    # Remove default sheet
    wb.remove(wb.active)
    
    if assessment_data is None:
        assessment_data = {}
        
    for sheet_title, headers in WORKSHEET_DEFINITIONS:
        ws = wb.create_sheet(title=sheet_title)
        sheet_data = assessment_data.get(sheet_title, [])
        format_sheet(ws, sheet_title, headers, sheet_data)
        
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    wb.save(output_path)
    print(f"[OK] Report template generated successfully at: {output_path}")
    return output_path

if __name__ == "__main__":
    out = "reports/Enterprise_Infrastructure_Health_Check.xlsx"
    if len(sys.argv) > 1:
        out = sys.argv[1]
    create_report(out)
