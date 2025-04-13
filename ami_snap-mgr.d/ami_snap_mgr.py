#!/usr/bin/env python3
"""
AMI and Snapshot Manager Script
Automatically installs required dependencies if not present
"""

import sys
import subprocess
import pkg_resources

def install_dependencies():
    """Install required packages if not already installed"""
    required_packages = {
        'boto3': 'boto3',
        'pandas': 'pandas',
        'openpyxl': 'openpyxl'  # Required for Excel support in pandas
    }
    
    print("Checking dependencies...")
    for package, pip_name in required_packages.items():
        try:
            pkg_resources.require(package)
            print(f"✅ {package} is already installed")
        except pkg_resources.DistributionNotFound:
            print(f"📦 Installing {package}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", pip_name])
            print(f"✅ {package} has been installed")

# Install dependencies before importing them
install_dependencies()

# Now import the required packages
import boto3
from datetime import datetime
import pandas as pd
import time

def get_ami_snapshots(start_date=None, end_date=None):
    """Get AMIs and their associated snapshots within the specified date range"""
    ec2 = boto3.client('ec2')
    ami_snapshot_map = {}

    try: 
        # Get AMIs owned by the account
        filters = [{'Name': 'owner-id', 'Values': [boto3.client('sts').get_caller_identity()['Account']]}]
        amis = ec2.describe_images(Filters=filters)['Images']
        
        # Set default end date to current date if not provided
        if not end_date:
            end_date = datetime.now().replace(hour=23, minute=59, second=59)
        else:
            # Set time to end of day for the end date
            end_date = end_date.replace(hour=23, minute=59, second=59)
        
        # Set default start date to beginning of time if not provided
        if not start_date:
            start_date = datetime.strptime('1970-01-01 00:00:00', '%Y-%m-%d %H:%M:%S')
        else:
            # Set time to start of day for the start date
            start_date = start_date.replace(hour=0, minute=0, second=0)
        
        print(f"\nFiltering AMIs created between:")
        print(f"Start: {start_date.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"End  : {end_date.strftime('%Y-%m-%d %H:%M:%S')}")
        
        for ami in amis:
            creation_date = datetime.strptime(ami['CreationDate'].split('.')[0], '%Y-%m-%dT%H:%M:%S')
            if start_date <= creation_date <= end_date:
                ami_id = ami['ImageId']
                snapshot_ids = [block_device['Ebs']['SnapshotId'] 
                              for block_device in ami.get('BlockDeviceMappings', [])
                              if 'Ebs' in block_device and 'SnapshotId' in block_device['Ebs']]
                
                ami_snapshot_map[ami_id] = {
                    'name': ami.get('Name', 'N/A'),
                    'creation_date': ami.get('CreationDate', 'N/A'),
                    'snapshots': snapshot_ids
                }
        
        return ami_snapshot_map
    
    except Exception as e:
        print(f"Error getting AMI information: {str(e)}")
        return {}

def get_date_input(prompt, default_date=None):
    """Get date input from user with validation"""
    while True:
        date_str = input(prompt).strip()
        if not date_str and default_date:
            return default_date
        
        try:
            if not date_str:
                return None
            return datetime.strptime(date_str, '%Y-%m-%d')
        except ValueError:
            print("❌ Invalid date format. Please use YYYY-MM-DD format (e.g., 2024-12-31)")

def create_excel_report(ami_snapshot_map, output_file='ami_snapshot_report.xlsx'):
    """Create an Excel report with AMI and snapshot details"""
    try:
        data = []
        for ami_id, details in ami_snapshot_map.items():
            for snapshot_id in details['snapshots']:
                data.append({
                    'AMI ID': ami_id,
                    'AMI Name': details['name'],
                    'Creation Date': details['creation_date'],
                    'Snapshot ID': snapshot_id
                })
        
        df = pd.DataFrame(data)
        df.to_excel(output_file, index=False)
        print(f"\n✅ Excel report created: {output_file}")
        return True
    
    except Exception as e:
        print(f"❌ Error creating Excel report: {str(e)}")
        return False

def disable_ami(ami_id):
    """Disable an AMI using AWS CLI"""
    try:
        print(f"\nDisabling AMI: {ami_id}")
        cmd = f"aws ec2 disable-image --image-id {ami_id}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"✅ Successfully disabled AMI: {ami_id}")
            return True
        else:
            print(f"❌ Failed to disable AMI: {ami_id}")
            print(f"Error: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Error disabling AMI: {ami_id}\nReason: {e}")
        return False

def archive_snapshot(snapshot_id):
    """Archive a snapshot using AWS CLI command"""
    try:
        print(f"\nArchiving snapshot: {snapshot_id}")
        cmd = f"aws ec2 modify-snapshot-tier --snapshot-id {snapshot_id} --storage-tier archive"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"✅ Successfully archived snapshot: {snapshot_id}")
            return True
        else:
            print(f"❌ Failed to archive snapshot: {snapshot_id}")
            print(f"Error: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Error archiving snapshot: {snapshot_id}\nReason: {e}")
        return False

def process_amis_and_snapshots(ami_snapshot_map):
    """Disable AMIs and archive their snapshots"""
    print("\nProcessing AMIs and Snapshots...")
    
    # First process AMIs
    print("\nStep 1: Disabling AMIs")
    disabled_amis = []
    for ami_id, details in ami_snapshot_map.items():
        if disable_ami(ami_id):
            disabled_amis.append(ami_id)
            print(f"✅ Successfully disabled AMI: {ami_id}")
        else:
            print(f"❌ Failed to disable AMI: {ami_id}")
    
    if not disabled_amis:
        print("\nNo AMIs were successfully disabled. Stopping process.")
        return
    
    # Ask for confirmation before archiving snapshots
    print("\nStep 2: Archive Snapshots")
    proceed = input("\nDo you want to proceed with archiving the snapshots? (yes/no): ").lower()
    if proceed != 'yes':
        print("Snapshot archiving cancelled. AMIs have been disabled but snapshots remain in standard tier.")
        return
    
    print("\nWaiting 30 seconds for AMI disable operations to propagate...")
    time.sleep(30)
    
    # Process snapshots for successfully disabled AMIs
    failed_snapshots = []
    for ami_id in disabled_amis:
        details = ami_snapshot_map[ami_id]
        print(f"\nProcessing snapshots for AMI: {ami_id}")
        for snapshot_id in details['snapshots']:
            if not archive_snapshot(snapshot_id):
                failed_snapshots.append((ami_id, snapshot_id))
    
    if failed_snapshots:
        print("\n⚠️ The following snapshots could not be archived:")
        for ami_id, snap_id in failed_snapshots:
            print(f"  - AMI {ami_id}: Snapshot {snap_id}")
        print("\nPlease wait a few minutes and run the script again to retry archiving these snapshots.")

def main():
    """Main function to orchestrate the AMI and snapshot management"""
    print("AMI and Snapshot Manager")
    print("=======================")
    print("\nDate Filter Options (Press Enter to use defaults)")
    print("Default start date: No limit")
    print(f"Default end date: {datetime.now().strftime('%Y-%m-%d')} (Current Date)")
    
    # Get date range from user
    start_date = get_date_input("\nEnter start date (YYYY-MM-DD) or press Enter for no limit: ")
    end_date = get_date_input(f"Enter end date (YYYY-MM-DD) or press Enter for current date: ", 
                             datetime.now())
    
    # Get AMIs and their snapshots
    ami_snapshot_map = get_ami_snapshots(start_date, end_date)
    if not ami_snapshot_map:
        print("No AMIs found in the specified date range.")
        return
    
    # Display AMIs and snapshots
    print(f"\nFound {len(ami_snapshot_map)} AMIs in the specified date range:")
    for ami_id, details in ami_snapshot_map.items():
        print(f"\nAMI: {ami_id}")
        print(f"Name: {details['name']}")
        print(f"Creation Date: {details['creation_date']}")
        print("Snapshots:")
        for snapshot_id in details['snapshots']:
            print(f"  - {snapshot_id}")
    
    # Create Excel report
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_name = f'ami_snapshot_report_{timestamp}.xlsx'
    create_excel_report(ami_snapshot_map, report_name)
    
    # Confirm before proceeding with AMI disabling
    proceed = input("\nDo you want to proceed with disabling the AMIs? (yes/no): ").lower()
    if proceed != 'yes':
        print("Operation cancelled.")
        return
    
    # Process AMIs and snapshots
    process_amis_and_snapshots(ami_snapshot_map)
    print("\nOperation completed.")

if __name__ == "__main__":
    main() 