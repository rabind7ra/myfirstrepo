"""
Main entry point for Login Security Analyzer.

This script integrates loading, analysis, searching, statistics,
dashboard display, and report export in a menu-driven workflow.
"""

from typing import Any, Dict, List, Optional

from core.account_lock_manager import load_locked_accounts
from core.blacklist_manager import load_blacklisted_ips
from core.chart_generator import generate_security_charts
from core.pdf_exporter import export_security_pdf_report
from interface.dashboard import display_dashboard_from_analysis
from interface.display import display_statistics, print_alerts, print_status_message, print_subheader, print_table
from interface.menu import (
    get_menu_selection,
    prompt_advanced_search_filters,
    prompt_ip_search,
    prompt_username_search,
)
from core.analyzer import analyze_login_records
from core.data_loader import load_login_activity
from core.logger import log_error, log_info, log_warning
from core.report_generator import generate_security_reports
from core.search_engine import search_records_by_ip, search_records_by_username, search_security_data
from core.statistics import generate_security_statistics


DATASET_PATH = "data/login_activity.csv"
APP_LOG_PATH = "data/application_log.txt"


def _can_use_records(records: Optional[List[Dict[str, Any]]]) -> bool:
    """
    Check whether dataset records are available for processing.
    """
    return isinstance(records, list) and len(records) > 0


def _show_search_results(title: str, rows: List[Dict[str, Any]]) -> None:
    """
    Display search results in a table when available.
    """
    if not rows:
        print(f"\nNo matches found for {title.lower()}.")
        return

    # Show common useful columns if they exist.
    preferred_columns = ["username", "ip_address", "timestamp", "status", "result", "location", "country"]
    columns = [column for column in preferred_columns if column in rows[0]]
    if not columns:
        columns = list(rows[0].keys())

    print_table(rows, columns, title=title)


def _filter_alerts_by_type(alerts: List[Dict[str, Any]], alert_type: str) -> List[Dict[str, Any]]:
    """
    Return alerts that match a specific alert_type.
    """
    target = alert_type.upper().strip()
    return [alert for alert in alerts if str(alert.get("alert_type", "")).upper().strip() == target]


def _safe_int(value: Any, default: int = 0) -> int:
    """
    Convert value to integer safely for table display.
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def run_application() -> None:
    """
    Run the menu-based Login Security Analyzer application.
    """
    records: List[Dict[str, Any]] = []
    analysis_result: Dict[str, Any] = {}

    log_info("Program started.", APP_LOG_PATH)

    while True:
        try:
            selection = get_menu_selection()
            option = selection["option"]

            if option == "1":
                records = load_login_activity(DATASET_PATH, log_file_path=APP_LOG_PATH)
                if records:
                    print()
                    print_status_message(
                        f"Dataset loaded successfully: {len(records)} record(s).",
                        status="success",
                    )
                else:
                    print()
                    print_status_message(
                        "Dataset load completed, but no valid records were found.",
                        status="warning",
                    )
                    log_warning("Dataset loaded with zero valid records.", APP_LOG_PATH)

            elif option == "2":
                if not _can_use_records(records):
                    print("\nPlease load the dataset first (Option 1).")
                    continue

                analysis_result = analyze_login_records(records, log_file_path=APP_LOG_PATH)
                print()
                print_status_message("Security analysis completed.", status="success")
                display_dashboard_from_analysis(analysis_result)

            elif option == "3":
                alerts = analysis_result.get("alerts", [])
                if not alerts:
                    print("\nNo alerts available. Run security analysis first (Option 2).")
                    continue
                print_alerts(alerts, title="Security Alerts")

            elif option == "4":
                if not _can_use_records(records):
                    print("\nPlease load the dataset first (Option 1).")
                    continue

                username_query = prompt_username_search()
                if username_query == "":
                    print("\nSearch text cannot be empty.")
                    continue

                matches = search_records_by_username(records, username_query)
                _show_search_results("Username Search Results", matches)

            elif option == "5":
                if not _can_use_records(records):
                    print("\nPlease load the dataset first (Option 1).")
                    continue

                ip_query = prompt_ip_search()
                if ip_query == "":
                    print("\nSearch text cannot be empty.")
                    continue

                matches = search_records_by_ip(records, ip_query)
                _show_search_results("IP Address Search Results", matches)

            elif option == "6":
                if not _can_use_records(records):
                    print("\nPlease load the dataset first (Option 1).")
                    continue

                alerts = analysis_result.get("alerts", [])
                blacklist_status = analysis_result.get("blacklist_status", {})
                account_lock_status = analysis_result.get("account_lock_status", {})
                statistics_data = generate_security_statistics(
                    records,
                    alerts,
                    blacklist_status,
                    account_lock_status,
                )
                display_statistics(statistics_data)

            elif option == "7":
                if not _can_use_records(records):
                    print("\nPlease load the dataset first (Option 1).")
                    continue

                alerts = analysis_result.get("alerts", [])
                blacklist_status = analysis_result.get("blacklist_status", {})
                account_lock_status = analysis_result.get("account_lock_status", {})
                report_status = generate_security_reports(
                    records=records,
                    alerts=alerts,
                    summary_report_path="data/summary_report.txt",
                    suspicious_csv_path="data/suspicious_logins.csv",
                    blacklist_status=blacklist_status,
                    account_lock_status=account_lock_status,
                    log_file_path=APP_LOG_PATH,
                    chart_directory="exports/charts",
                    pdf_report_path="exports/security_report.pdf",
                )

                print()
                print_status_message("Report export finished.", status="info")
                print(
                    f"  - Summary report: {report_status['summary_report']['saved']}\n"
                    f"  - Suspicious CSV : {report_status['suspicious_alerts_csv']['saved']}\n"
                    f"  - PDF report     : {report_status['pdf_report']['saved']}\n"
                    f"  - Chart folder   : {report_status['charts']['directory']}"
                )

            elif option == "8":
                log_info("Program exited by user.", APP_LOG_PATH)
                print()
                print_status_message("Exiting Login Security Analyzer. Stay safe.", status="success")
                break

            elif option == "9":
                blacklisted_ips = sorted(load_blacklisted_ips())
                blacklisted_ip_rows = [{"ip_address": ip} for ip in blacklisted_ips]
                print_table(blacklisted_ip_rows, ["ip_address"], title="Blacklisted IP Addresses")

            elif option == "10":
                locked_accounts = load_locked_accounts()
                locked_rows = [
                    {
                        "username": username,
                        "locked_until": locked_until.strftime("%Y-%m-%d %H:%M:%S"),
                    }
                    for username, locked_until in sorted(locked_accounts.items())
                ]
                print_table(locked_rows, ["username", "locked_until"], title="Locked Accounts")

            elif option == "11":
                alerts = analysis_result.get("alerts", [])
                if not alerts:
                    print("\nNo alerts available. Run security analysis first (Option 2).")
                    continue

                threat_rows = [
                    {
                        "alert_type": str(alert.get("alert_type", "UNKNOWN_ALERT")),
                        "risk_level": str(alert.get("risk_level", "UNKNOWN")).upper(),
                        "threat_score": _safe_int(alert.get("threat_score", 0), 0),
                    }
                    for alert in alerts
                ]
                print_table(threat_rows, ["alert_type", "risk_level", "threat_score"], title="Threat Score View")

            elif option == "12":
                alerts = analysis_result.get("alerts", [])
                midnight_alerts = _filter_alerts_by_type(alerts, "MIDNIGHT_LOGIN_ACTIVITY")
                print_alerts(midnight_alerts, title="Midnight Login Alerts")

            elif option == "13":
                alerts = analysis_result.get("alerts", [])
                admin_alerts = _filter_alerts_by_type(alerts, "ADMIN_ACCOUNT_ATTACK")
                print_alerts(admin_alerts, title="Admin Account Attack Alerts")

            elif option == "14":
                if not _can_use_records(records):
                    print("\nPlease load the dataset first (Option 1).")
                    continue

                alerts = analysis_result.get("alerts", [])
                blacklist_status = analysis_result.get("blacklist_status", {})
                account_lock_status = analysis_result.get("account_lock_status", {})
                statistics_data = generate_security_statistics(
                    records,
                    alerts,
                    blacklist_status,
                    account_lock_status,
                )
                health_summary = statistics_data.get("security_health_summary", {})
                print_subheader("Security Health Summary")
                print(f"  Security Health Score : {health_summary.get('security_health_score', 0)}")
                print(f"  Health Status         : {health_summary.get('health_status', 'Unknown')}")

            elif option == "15":
                if not _can_use_records(records):
                    print("\nPlease load the dataset first (Option 1).")
                    continue

                filter_input = prompt_advanced_search_filters()
                alerts = analysis_result.get("alerts", [])
                search_result = search_security_data(
                    records=records,
                    alerts=alerts,
                    username_query=filter_input.get("username", ""),
                    ip_query=filter_input.get("ip_address", ""),
                    date_query=filter_input.get("date", ""),
                    risk_level_query=filter_input.get("risk_level", ""),
                    location_query=filter_input.get("location", ""),
                )

                print_subheader("Advanced Search Summary")
                for key, value in search_result.get("counts", {}).items():
                    print(f"  {key}: {value}")

                advanced_records = search_result.get("results", {}).get("records_advanced", [])
                advanced_alerts = search_result.get("results", {}).get("alerts_advanced", [])

                _show_search_results("Advanced Record Matches", advanced_records)
                print_alerts(advanced_alerts, title="Advanced Alert Matches")

            elif option == "16":
                if not _can_use_records(records):
                    print("\nPlease load the dataset first (Option 1).")
                    continue

                alerts = analysis_result.get("alerts", [])
                chart_status = generate_security_charts(records, alerts, chart_directory="exports/charts")
                if chart_status.get("saved", True):
                    print_status_message("Security charts exported.", status="success")
                    print(f"  - Chart directory: {chart_status.get('directory', 'exports/charts')}")
                    print(f"  - Login chart (PNG): {chart_status.get('login_activity', {}).get('png_chart')}")
                    print(f"  - Risk chart (PNG): {chart_status.get('risk_distribution', {}).get('png_chart')}")
                else:
                    print_status_message("Failed to export security charts.", status="critical")
                    print(f"  - Error: {chart_status.get('error', 'Unknown error')}")

            elif option == "17":
                if not _can_use_records(records):
                    print("\nPlease load the dataset first (Option 1).")
                    continue

                alerts = analysis_result.get("alerts", [])
                blacklist_status = analysis_result.get("blacklist_status", {})
                account_lock_status = analysis_result.get("account_lock_status", {})
                statistics_data = generate_security_statistics(
                    records,
                    alerts,
                    blacklist_status,
                    account_lock_status,
                )
                chart_status = generate_security_charts(records, alerts, chart_directory="exports/charts")
                pdf_status = export_security_pdf_report(
                    records=records,
                    alerts=alerts,
                    statistics_data=statistics_data,
                    chart_status=chart_status,
                    output_path="exports/security_report.pdf",
                )

                if pdf_status.get("saved"):
                    print_status_message("PDF report exported successfully.", status="success")
                    print(f"  - PDF path: {pdf_status.get('path')}")
                else:
                    print_status_message("Failed to export PDF report.", status="critical")
                    print(f"  - Error: {pdf_status.get('error', 'Unknown error')}")

        except KeyboardInterrupt:
            print("\n\nKeyboard interrupt received. Exiting safely.")
            log_warning("Program interrupted by keyboard input.", APP_LOG_PATH)
            break
        except Exception as exc:
            # Catch-all to keep the app beginner-friendly and resilient.
            log_error(f"Unexpected application error: {exc}", APP_LOG_PATH)
            print("\nAn unexpected error occurred. Please try again.")


if __name__ == "__main__":
    run_application()
