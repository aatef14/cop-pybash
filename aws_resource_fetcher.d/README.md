# AWS Resource Inventory Tool

A Python script that generates comprehensive reports of AWS resources across multiple services in Excel format.

## Features

- **Multi-service inventory**: Collects data from 20+ AWS services
- **Automatic dependency handling**: Installs required packages if missing
- **Detailed reporting**: Provides rich metadata for each resource type
- **User-friendly output**: 
  - Clear progress messages during execution
  - Timestamped Excel files
  - Customizable output filenames
- **Container-ready**: Can be run in Docker environments

## Supported AWS Services

- EC2 Instances
- S3 Buckets
- RDS Databases
- EKS Clusters
- VPC Resources (VPCs, Subnets, Route Tables)
- Load Balancers (ALB)
- WAF Web ACLs
- CloudFront Distributions
- Route 53 Hosted Zones
- Cognito User Pools
- API Gateways
- ECR Repositories
- FSx File Systems
- Direct Connect
- And more...

## Prerequisites

- Python 3.9+
- AWS credentials configured (~/.aws/credentials or environment variables)
- Required IAM permissions for the services being inventoried

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd aws-resource-report

# The script will automatically install dependencies when first run
```

## Usage

```bash
python aws-resource-details.py
```

When executed, the script will:
1. Check/install dependencies automatically
2. Inventory all supported AWS services
3. Prompt for an output filename
4. Generate an Excel file with multiple sheets (one per service)

## Output Example

```
Starting AWS Resource Inventory Collection...

🔍 Fetching S3 Buckets...
✅ Found 5 S3 buckets

🔍 Fetching EC2 Instances...
✅ Found 12 EC2 instances
...
✅ AWS Inventory saved to my-report-20230413_142356.xlsx
```

## Docker Support

```bash
# Build the image
docker build -t aws-resource-report .

# Run the container
docker run -it -v ~/.aws:/root/.aws aws-resource-report
```

## Configuration

Modify `regions` list in the script to inventory resources across multiple regions.

## License

NO-COPYRIGHT FREECENSE