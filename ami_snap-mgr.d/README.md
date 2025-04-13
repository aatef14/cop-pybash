# AMI and Snapshot Manager

A Python script for managing Amazon Machine Images (AMIs) and their associated snapshots in AWS. This tool helps automate the process of disabling AMIs and archiving their snapshots, with built-in date filtering and reporting capabilities.

## Features

- 🔍 Filter AMIs by date range
- 📊 Generate Excel reports of AMIs and their associated snapshots
- 🚫 Disable selected AMIs
- 📦 Archive associated snapshots
- 🔄 Automatic dependency management
- ⚡ Interactive command-line interface

## Requirements

- Python 3.x
- AWS CLI configured with appropriate credentials
- AWS account with necessary permissions for EC2 operations

The script will automatically install the following Python packages if they're not present:
- boto3
- pandas
- openpyxl

## Setup

1. Ensure you have Python 3.x installed
2. Configure AWS CLI with your credentials:
   ```bash
   aws configure
   ```
3. Make the script executable (Linux/Mac):
   ```bash
   chmod +x ami_snap_mgr.py
   ```

## Usage

Run the script:
```bash
./ami_snap_mgr.py
```

The script will:
1. Prompt for date range filters (optional)
2. Display found AMIs and their associated snapshots
3. Generate an Excel report with details
4. Ask for confirmation before disabling AMIs
5. Disable the selected AMIs
6. Ask for confirmation before archiving snapshots
7. Archive the associated snapshots

## Date Filtering

- Start date: Optional (YYYY-MM-DD format). If not provided, no lower date limit is applied
- End date: Optional (YYYY-MM-DD format). If not provided, current date is used

## Output

- Generates an Excel report named `ami_snapshot_report_YYYYMMDD_HHMMSS.xlsx`
- Contains details of AMIs and their associated snapshots
- Provides real-time feedback on operations

## Important Notes

- The script requires appropriate AWS permissions to:
  - List AMIs
  - Disable AMIs
  - Modify snapshots
- There is a 30-second wait period between disabling AMIs and archiving snapshots
- Failed snapshot archiving operations are logged and can be retried
- Always review the Excel report before confirming operations

## Error Handling

- The script includes comprehensive error handling
- Failed operations are clearly reported
- Provides option to retry failed snapshot archiving operations

## Security

- Uses AWS credentials from your configured AWS CLI
- Operates only on AMIs owned by your AWS account
- Requires explicit confirmation before making changes

## Support

For issues or questions, please open an issue in the repository. 