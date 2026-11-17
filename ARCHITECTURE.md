# Login Security Analyzer Architecture

## Project Goal
A cybersecurity-focused Python application that analyzes login activity records and detects suspicious login behavior.

## Folder Responsibilities

### core/
Contains all backend logic:
- data loading
- suspicious activity detection
- statistics
- searching
- report generation

### interface/
Contains all user interaction:
- menu system
- dashboard
- formatted displays

### data/
Stores datasets and generated reports.

### exports/
Stores exported reports and charts.

### tests/
Contains testing files and test cases.

### docs/
Contains assignment documentation and flowcharts.

### config/
Contains application settings and thresholds.

## Main Flow

main.py
→ menu.py
→ data_loader.py
→ analyzer.py
→ detector.py
→ statistics.py
→ report_generator.py
→ display.py