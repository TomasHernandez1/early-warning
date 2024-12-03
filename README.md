# early-warning
Script for Early Warning analysis of recently published and modified CVEs and uploading information to an Azure MongoDB.

This script is designed to connect to an Azure MongoDB and upload CVE-related information obtained from various sources. It facilitates proactive monitoring and analysis of vulnerabilities by leveraging the NIST database, GitHub, and the CISA Known Exploited Vulnerabilities (KEV) catalog.

# Features
## 1. CVE Data Retrieval
Source: NIST database.
Time Range Selection: Allows users to define a specific time range to search for CVEs.
Process: 
- Retrieves newly published CVEs and uploads them to the database.
- Fetches recently modified CVEs, checks if they are already in the database, and:
- Updates existing records with new information.
- Inserts new records if they are not already present.

## 2. GitHub Exploit Analysis
Searches GitHub for potential exploits associated with the CVEs stored in the database.
Adds references to these exploits in the database for easy access.

## 3. CISA KEV and Ransomware Campaigns
Queries the CISA database for Known Exploited Vulnerabilities (KEVs).
Identifies any associated ransomware campaigns.
Updates the database with KEV and ransomware details.

## 4. CWE Description Update
Updates the Common Weakness Enumeration (CWE) fields in the database with detailed descriptions to enhance the understanding of each vulnerability.

## 5. Vendor and Product Information Completion
Identifies CVE records with missing vendor or product information.
Attempts to populate these fields to ensure data completeness.

# Use Case
This script is ideal for security teams and researchers who need to maintain an up-to-date repository of vulnerabilities, potential exploits, and associated risks. It provides a consolidated view of the CVE landscape, enriched with actionable insights from GitHub and CISA.

# Usage
python3 early_warning.py
