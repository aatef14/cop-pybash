import sys
import subprocess
import pkg_resources

def install_dependencies():
    """Install required packages if not already installed"""
    required_packages = {
        'boto3': 'boto3',
        'pandas': 'pandas',
        'openpyxl': 'openpyxl',
        'pytz': 'pytz'
    }
    
    print("Checking dependencies...")
    for package, pip_name in required_packages.items():
        try:
            pkg_resources.require(package)
            print(f" {package} is already installed")
        except pkg_resources.DistributionNotFound:
            print(f" Installing {package}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", pip_name])
            print(f" {package} has been installed")

# Install dependencies before importing them
install_dependencies()

import boto3
import pandas as pd
from datetime import datetime
import openpyxl
from botocore.exceptions import NoRegionError
import pytz  # pip install pytz

def get_s3_buckets():
    print("Fetching S3 Buckets...")
    s3 = boto3.client('s3')
    response = s3.list_buckets()
    buckets = response['Buckets']
    print("S3 Buckets fetched.")
    return buckets

def get_bucket_inventory_details(bucket_name):
    s3 = boto3.client('s3')
    
    try:
        response = s3.get_bucket_location(Bucket=bucket_name)
        region = response['LocationConstraint'] if 'LocationConstraint' in response else 'us-east-1'
    except Exception as e:
        print(f"Error getting region for bucket {bucket_name}: {str(e)}")
        region = 'Unknown'

    try:
        response = s3.head_bucket(Bucket=bucket_name)
        creation_date = response['ResponseMetadata']['HTTPHeaders']['date']
    except Exception as e:
        print(f"Error getting creation date for bucket {bucket_name}: {str(e)}")
        creation_date = 'Unknown'
    
    return {
        'Name': bucket_name,
        'AWS Region': region,
        'Creation Date': creation_date
    }

def get_ec2_instance_details(region_name):
    print(f"Fetching EC2 Instances in {region_name}...")
    try:
        # Specify the AWS region where your EC2 instances are located
        #region_name = 'ap-south-1'
        ec2_client = boto3.client('ec2', region_name=region_name)
        instances = ec2_client.describe_instances()
        # Set IST timezone
        ist_tz = pytz.timezone('Asia/Kolkata')

        inventory = []
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                instance_name = ''
                instance_type = instance['InstanceType']
                platform = instance.get('Platform', 'Linux')
                if 'Tags' in instance:
                    for tag in instance['Tags']:
                        if tag['Key'] == 'Name':
                            instance_name = tag['Value']
                key_name = instance.get('KeyName', 'No KeyPair')
                iam_role = instance.get('IamInstanceProfile', {}).get('Arn', 'No IAM Role')
                instance_type_info = ec2_client.describe_instance_types(InstanceTypes=[instance_type])
                vcpu = instance_type_info['InstanceTypes'][0]['VCpuInfo']['DefaultVCpus']
                memory = instance_type_info['InstanceTypes'][0]['MemoryInfo']['SizeInMiB'] / 1024
                private_ip = instance.get('PrivateIpAddress', 'N/A')
                public_ip = instance.get('PublicIpAddress', 'N/A')
                ipv6_addresses = [ipv6_address_info.get('Ipv6Address', 'N/A') for network_interface in instance.get('NetworkInterfaces', []) for ipv6_address_info in network_interface.get('Ipv6Addresses', [])]
                ipv6_ips = ', '.join(ipv6_addresses) if ipv6_addresses else 'N/A'
                instance_state = instance['State']['Name']
                volume_ids, volume_types, volume_sizes = [], [], []
                total_volume_size = 0
                for block_device in instance['BlockDeviceMappings']:
                    volume_id = block_device['Ebs']['VolumeId']
                    volume_info = ec2_client.describe_volumes(VolumeIds=[volume_id])
                    volume_type = volume_info['Volumes'][0]['VolumeType']
                    volume_size = volume_info['Volumes'][0]['Size']
                    volume_ids.append(volume_id)
                    volume_types.append(volume_type)
                    volume_sizes.append(volume_size)
                    total_volume_size += volume_size
                volume_ids_str = ', '.join(volume_ids)
                volume_types_str = ', '.join(volume_types)
                volume_sizes_str = ', '.join(map(str, volume_sizes))
                availability_zone = instance['Placement']['AvailabilityZone']
                region = region_name
                # Retrieve network interface details with IST attach time
                for interface in instance.get('NetworkInterfaces', []):
                    network_interface_id = interface['NetworkInterfaceId']
                    attach_time_utc = interface.get('Attachment', {}).get('AttachTime', None)
                    attach_time_ist = (
                        attach_time_utc.astimezone(ist_tz).strftime('%Y-%m-%d %H:%M:%S') 
                        if attach_time_utc else 'N/A'
                    )
                inventory.append({
                    'Instance Name': instance_name, 'Instance ID': instance_id, 'Instance State': instance_state, 
                    'Private IP': private_ip, 'Public IP': public_ip, 'IPv6 IP': ipv6_ips, 'Availability_Zone': availability_zone, 
                    'Platform': platform, 'Instance Type': instance_type, 'vCPU': vcpu, 'Memory (GiB)': memory, 
                    'Volume ID(s)': volume_ids_str, 'Volume Type(s)': volume_types_str, 'Volume Size (GB)': volume_sizes_str, 
                    'Total Volume Size (GB)': total_volume_size, 'Key Pair': key_name, 'IAM Role': iam_role, 'Region': region, 'Network Interface ID': network_interface_id,
                    'Attach Time (IST)': attach_time_ist
                })
        print(f"EC2 Instances in {region_name} fetched.")
        return inventory
    except NoRegionError:
        print('Please specify an AWS region in the script.')
        return []
    
def get_autoscaling_group_inventory():
    print("Fetching Auto Scaling Groups...")
    autoscaling = boto3.client('autoscaling')
    response = autoscaling.describe_auto_scaling_groups()
    inventory = []
    for group in response['AutoScalingGroups']:
        group_name = group['AutoScalingGroupName']
        launch_configuration = group.get('LaunchConfigurationName', 'N/A')
        min_size = group['MinSize']
        max_size = group['MaxSize']
        desired_capacity = group['DesiredCapacity']
        instance_ids = [instance['InstanceId'] for instance in group['Instances']]
        availability_zones = ', '.join(group['AvailabilityZones'])
        creation_time = group['CreatedTime'].strftime('%Y-%m-%d %H:%M:%S')
        inventory.append({
            'AutoScaling Group Name': group_name, 'Launch Configuration': launch_configuration, 
            'Min Size': min_size, 'Max Size': max_size, 'Desired Capacity': desired_capacity, 
            'Instance IDs': ', '.join(instance_ids), 'Availability Zones': availability_zones, 
            'Creation Time': creation_time
        })
    print("Auto Scaling Groups fetched.")
    return inventory

    
def get_alb_inventory():
    print("Fetching ALBs...")
    elbv2 = boto3.client('elbv2')
    response = elbv2.describe_load_balancers()
    inventory = []
    for lb in response['LoadBalancers']:
        availability_zones = ', '.join([zone['ZoneName'] for zone in lb['AvailabilityZones']])
        inventory.append({
            'Name': lb['LoadBalancerName'], 'DNS Name': lb['DNSName'], 'State': lb['State']['Code'], 
            'VPC ID': lb['VpcId'], 'Availability Zones': availability_zones, 'Type': lb['Type'], 
            'Date Created': lb['CreatedTime'].strftime('%Y-%m-%d %H:%M:%S')
        })
    print("ALBs fetched.")
    return inventory

def get_waf_inventory():
    print("Fetching WAF Web ACLs...")
    # Specify the regions for regional WAF
    regions = ['ap-south-1', 'us-east-1', 'eu-west-1']  # Add or remove regions as needed
    inventory = []

    # Fetch Regional WAFs
    for region_name in regions:
        waf_client = boto3.client('wafv2', region_name=region_name)
        try:
            response = waf_client.list_web_acls(Scope='REGIONAL')
            for acl in response['WebACLs']:
                inventory.append({
                    'Name': acl['Name'],
                    'ARN': acl['ARN'],
                    'Scope': 'Regional',
                    'Region': region_name
                })
        except Exception as e:
            print(f"Error fetching regional WAF ACLs for region {region_name}: {e}")

    # Fetch Global (CloudFront) WAFs from us-east-1
    waf_client = boto3.client('wafv2', region_name='us-east-1')  # CloudFront WAFs are global but managed in us-east-1
    try:
        response = waf_client.list_web_acls(Scope='CLOUDFRONT')
        for acl in response['WebACLs']:
            inventory.append({
                'Name': acl['Name'],
                'ARN': acl['ARN'],
                'Scope': 'Global (CloudFront)',
                'Region': 'Global'
            })
    except Exception as e:
        print(f"Error fetching CloudFront WAF ACLs: {e}")
    print("WAF Web ACLs fetched.")
    return inventory

def get_eks_clusters():
    print("Fetching EKS Clusters...")
    eks = boto3.client('eks')
    response = eks.list_clusters()
    inventory = []
    for cluster_name in response['clusters']:
        cluster_info = eks.describe_cluster(name=cluster_name)['cluster']
        status = cluster_info['status']
        version = cluster_info['version']
        created = cluster_info['createdAt'].strftime('%Y-%m-%d %H:%M:%S')
        support_period = cluster_info.get('resourcesVpcConfig', {}).get('endpointPublicAccess', 'Unknown')
        provider = determine_provider(cluster_info)
        inventory.append({
            'Cluster name': cluster_name, 'Status': status, 'Kubernetes version': version, 
            'Support period': support_period, 'Provider': provider, 'Created': created
        })
    print("EKS Clusters fetched.")
    return inventory

def determine_provider(cluster_info):
    if 'platform' in cluster_info:
        return cluster_info['platform']
    elif 'platformVersion' in cluster_info:
        return f"EKS {cluster_info['platformVersion']}"
    else:
        return 'Unknown'

def get_cloudfront_inventory():
    print("Fetching CloudFront Distributions...")
    cloudfront = boto3.client('cloudfront')
    distributions = cloudfront.list_distributions()['DistributionList'].get('Items', [])
    inventory = []
    for dist in distributions:
        dist_id = dist.get('Id', 'Unknown')
        description = dist.get('Comment', '')
        dist_type = determine_distribution_type(dist)
        domain_name = dist.get('DomainName', '')
        alternate_domains = dist.get('Aliases', {}).get('Items', [])
        price_class = determine_price_class(dist)
        origins = determine_origins(dist)
        status = dist.get('Status', '')
        last_modified = dist.get('LastModifiedTime', '').strftime('%Y-%m-%d %H:%M:%S')
        inventory.append({
            'ID': dist_id, 'Description': description, 'Type': dist_type, 'Domain name': domain_name, 
            'Alternate domain names': ', '.join(alternate_domains), 'Price class': price_class, 'Origins': origins, 
            'Status': status, 'Last modified': last_modified
        })
    print("CloudFront Distributions fetched.")
    return inventory

def determine_distribution_type(dist):
    if 'S3OriginConfig' in dist:
        return 'S3'
    elif 'CustomOriginConfig' in dist:
        return 'Custom'
    else:
        return 'Unknown'

def determine_price_class(dist):
    price_class = dist.get('PriceClass', 'Unknown')
    if price_class == 'PriceClass_100':
        return 'Use Only U.S., Canada, and Europe'
    elif price_class == 'PriceClass_200':
        return 'Use Only U.S., Canada, Europe, and Israel'
    elif price_class == 'PriceClass_All':
        return 'Use All Edge Locations (Best Performance)'
    else:
        return price_class

def determine_origins(dist):
    origins = []
    if 'Origins' in dist and 'Items' in dist['Origins']:
        for origin in dist['Origins']['Items']:
            if 'S3OriginConfig' in origin:
                origins.append(origin['S3OriginConfig'].get('OriginAccessIdentity', 'Unknown'))
            elif 'CustomOriginConfig' in origin:
                origins.append(origin['CustomOriginConfig'].get('DomainName', 'Unknown'))
            else:
                origins.append('Unknown')
    return ', '.join(origins)

def get_route53_inventory():
    print("Fetching Route 53 Hosted Zones...")
    route53 = boto3.client('route53')
    response = route53.list_hosted_zones()
    hosted_zones = response['HostedZones']
    inventory = []
    for zone in hosted_zones:
        zone_id = zone['Id']
        zone_name = zone['Name']
        zone_type = 'Public' if zone['Config']['PrivateZone'] is False else 'Private'
        created_by = zone.get('CreatorRequest', 'Unknown')
        record_count = get_record_count(route53, zone_id)
        description = zone.get('Config', {}).get('Comment', '')
        hosted_zone_id = zone_id.split('/')[-1]
        inventory.append({
            'Selection': 'Route 53 Hosted Zone', 'Hosted zone name': zone_name, 'Type': zone_type, 
            'Created by': created_by, 'Record count': record_count, 'Description': description, 'Hosted Zone ID': hosted_zone_id
        })
    print("Route 53 Hosted Zones fetched.")
    return inventory

def get_record_count(route53, zone_id):
    response = route53.get_hosted_zone(Id=zone_id)
    return response['HostedZone']['ResourceRecordSetCount']

def get_cognito_inventory():
    print("Fetching Cognito User Pools...")
    cognito = boto3.client('cognito-idp')
    user_pools = cognito.list_user_pools(MaxResults=60)['UserPools']
    inventory = []
    for pool in user_pools:
        pool_id = pool['Id']
        pool_name = pool['Name']
        pool_status = pool.get('Status', 'Unknown')
        created = pool['CreationDate'].strftime('%Y-%m-%d %H:%M:%S')
        last_modified = pool['LastModifiedDate'].strftime('%Y-%m-%d %H:%M:%S')
        pool_details = cognito.describe_user_pool(UserPoolId=pool_id)['UserPool']
        pool_type = pool_details.get('UserPoolType', 'Unknown')
        pool_mfa = pool_details.get('MfaConfiguration', 'OFF')
        pool_domain = pool_details.get('CustomDomain', '')
        inventory.append({
            'User pool name': pool_name, 'Status': pool_status, 'Created': created, 
            'Last modified': last_modified, 'User pool ID': pool_id, 'Type': pool_type, 'MFA': pool_mfa, 
            'Domain': pool_domain
        })
    print("Cognito User Pools fetched.")
    return inventory

def get_http_api_gateway_inventory():
    print("Fetching HTTP API Gateways...")
    apigatewayv2 = boto3.client('apigatewayv2')
    response = apigatewayv2.get_apis()
    apis = response['Items']
    inventory = []
    for api in apis:
        api_id = api['ApiId']
        name = api['Name']
        description = api.get('Description', '')
        protocol_type = api['ProtocolType']
        created_date = api['CreatedDate'].strftime('%Y-%m-%d %H:%M:%S')
        version = api.get('Version', 'Unknown')
        tags = ', '.join([f"{key}: {value}" for key, value in api.get('Tags', {}).items()])
        inventory.append({
            'Name': name, 'Description': description, 'Protocol type': protocol_type, 'Created date': created_date, 
            'API ID': api_id, 'Version': version, 'Tags': tags
        })
    print("HTTP API Gateways fetched.")
    return inventory

def get_ecr_inventory():
    print("Fetching ECR Repositories...")
    ecr = boto3.client('ecr')
    response = ecr.describe_repositories()
    repos = response['repositories']
    inventory = []
    for repo in repos:
        repo_name = repo['repositoryName']
        uri = repo['repositoryUri']
        created = repo['createdAt'].strftime('%Y-%m-%d %H:%M:%S')
        image_scan = repo['imageScanningConfiguration']['scanOnPush']
        tags = repo['tags'] if 'tags' in repo else []
        tags_str = ', '.join([f"{tag['Key']}: {tag['Value']}" for tag in tags])
        inventory.append({
            'Repository name': repo_name, 'Repository URI': uri, 'Created': created, 
            'Image scan on push': image_scan, 'Tags': tags_str
        })
    print("ECR Repositories fetched.")
    return inventory

def get_fsx_inventory():
    print("Fetching FSx File Systems...")
    try:
        fsx = boto3.client('fsx')
        response = fsx.describe_file_systems()
        file_systems = response['FileSystems']
        
        if not file_systems:
            print("No Amazon FSx file systems found.")
            return []
        
        inventory = []
        for fs in file_systems:
            file_system_id = fs['FileSystemId']
            file_system_type = fs['FileSystemType']
            status = fs['Lifecycle']
            deployment_type = fs.get('DeploymentType', 'N/A')
            storage_type = fs['StorageType']
            storage_capacity = fs['StorageCapacity']
            throughput_capacity = fs.get('ThroughputCapacity', 'N/A')
            creation_time = fs['CreationTime'].astimezone().strftime('%Y-%m-%d %H:%M:%S')
            
            # Fetching volume information
            volumes = []
            for volume in fs.get('VolumeIds', []):
                volume_info = fsx.describe_file_system_associations(FileSystemId=file_system_id, VolumeId=volume)
                volumes.append({
                    'Volume ID': volume,
                    'Volume Type': volume_info['FileSystemAssociations'][0]['Lifecycle'],
                    'Volume Size (GiB)': volume_info['FileSystemAssociations'][0]['Capacity'],
                })
            
            inventory.append({
                'Items selection': 'Amazon FSx',
                'File system ID': file_system_id,
                'File system type': file_system_type,
                'Status': status,
                'Deployment type': deployment_type,
                'Storage type': storage_type,
                'Storage capacity': storage_capacity,
                'Throughput capacity': throughput_capacity,
                'Creation time': creation_time,
                'Volumes': volumes
            })
        
        print("FSx File Systems fetched.")
        return inventory
    
    except Exception as e:
        print(f"Error fetching FSx inventory: {str(e)}")
        return []
    
def get_rds_inventory():
    print("Fetching RDS Instances...")
    rds = boto3.client('rds')
    response = rds.describe_db_instances()
    inventory = []
    for instance in response['DBInstances']:
        db_identifier = instance['DBInstanceIdentifier']
        db_name = instance.get('DBName', 'N/A')  # Handle the case where 'DBName' may not exist
        db_engine = instance['Engine']
        db_instance_class = instance['DBInstanceClass']
        engine_version = instance['EngineVersion']
        master_username = instance['MasterUsername']
        multi_az = instance['MultiAZ']
        storage = instance['AllocatedStorage']
        backup_retention_period = instance['BackupRetentionPeriod']
        publicly_accessible = instance['PubliclyAccessible']
        vpc_security_groups = ', '.join([group['VpcSecurityGroupId'] for group in instance['VpcSecurityGroups']])
        endpoint = instance['Endpoint']['Address']
        availability_zone = endpoint.split('.')[2]
        db_subnet_group = instance['DBSubnetGroup']['DBSubnetGroupName']
        arn = instance['DBInstanceArn']
        public_access = instance['PubliclyAccessible']
        db_cluster_identifier = instance.get('DBClusterIdentifier', 'N/A')

        inventory.append({
            'DB Instance Identifier': db_identifier,
            'DB Name': db_name,
            'Engine': db_engine,
            'DB Instance Class': db_instance_class,
            'Engine Version': engine_version,
            'Master Username': master_username,
            'Multi-AZ': multi_az,
            'Storage (GB)': storage,
            'Backup Retention Period (Days)': backup_retention_period,
            'Publicly Accessible': publicly_accessible,
            'VPC Security Groups': vpc_security_groups,
            'Endpoint': endpoint,
            'Availability Zone': availability_zone,
            'DB Subnet Group': db_subnet_group,
            'DB Instance ARN': arn,
            'Public Access': public_access,
            'DB Cluster Identifier': db_cluster_identifier
        })

    print("RDS Instances fetched.")
    return inventory
def get_direct_connect_inventory():
    print("Fetching Direct Connect Connections...")
    try:
        directconnect = boto3.client('directconnect')
        response = directconnect.describe_connections()
        connections = response['connections']
        if not connections:
            print("No Amazon Direct Connect connections found.")
            return []
        inventory = []
        for connection in connections:
            connection_id = connection['connectionId']
            connection_name = connection['connectionName']
            connection_state = connection['connectionState']
            location = connection['location']
            bandwidth = connection['bandwidth']
            vlan = connection.get('vlan', 'N/A')
            partner_name = connection.get('partnerName', 'N/A')
            aws_device = connection.get('awsDevice', 'N/A')

            # Fetch virtual interfaces for each connection
            virtual_interfaces = get_virtual_interfaces(directconnect, connection_id)

            inventory.append({
                'Connection ID': connection_id, 'Connection Name': connection_name, 'State': connection_state, 
                'Location': location, 'Bandwidth': bandwidth, 'VLAN': vlan, 'Partner Name': partner_name, 
                'AWS Device': aws_device, 'Virtual Interfaces': virtual_interfaces
            })
        print("Direct Connect Connections fetched.")
        return inventory
    except Exception as e:
        print(f"Error fetching Direct Connect inventory: {str(e)}")
        return []

def get_virtual_interfaces(directconnect, connection_id):
    try:
        response = directconnect.describe_virtual_interfaces(connectionId=connection_id)
        virtual_interfaces = response['virtualInterfaces']
        vif_details = []
        for vif in virtual_interfaces:
            vif_details.append({
                'VIF ID': vif['virtualInterfaceId'], 'VIF Type': vif['virtualInterfaceType'], 
                'VIF Owner': vif['ownerAccount'], 'AWS Account ID': vif['amazonSideAsn'], 
                'Connection State': vif['virtualInterfaceState']
            })
        return vif_details
    except Exception as e:
        print(f"Error fetching Direct Connect inventory: {str(e)}")
        return []
    
def get_vpc_inventory():
    print("Fetching VPCs...")
    ec2 = boto3.client('ec2')
    vpcs = ec2.describe_vpcs()['Vpcs']
    inventory = []
    for vpc in vpcs:
        ipv4_cidr = vpc.get('CidrBlock', 'N/A')
        ipv6_cidr = ', '.join([ipv6['Ipv6CidrBlock'] for ipv6 in vpc.get('Ipv6CidrBlockAssociationSet', [])]) if 'Ipv6CidrBlockAssociationSet' in vpc else 'N/A'
        
        inventory.append({
            'VPC ID': vpc['VpcId'],
            'IPv4 CIDR Block': ipv4_cidr,
            'IPv6 CIDR Block': ipv6_cidr,
            'State': vpc['State'],
            'Is Default': vpc['IsDefault']
        })
    print("VPCs fetched.")
    return inventory

def get_subnet_inventory():
    print("Fetching Subnets...")
    ec2 = boto3.client('ec2')
    subnets = ec2.describe_subnets()['Subnets']
    inventory = []
    for subnet in subnets:
        ipv4_cidr = subnet.get('CidrBlock', 'N/A')
        ipv6_cidr = ', '.join([ipv6['Ipv6CidrBlock'] for ipv6 in subnet.get('Ipv6CidrBlockAssociationSet', [])]) if 'Ipv6CidrBlockAssociationSet' in subnet else 'N/A'

        inventory.append({
            'Subnet ID': subnet['SubnetId'],
            'VPC ID': subnet['VpcId'],
            'IPv4 CIDR Block': ipv4_cidr,
            'IPv6 CIDR Block': ipv6_cidr,
            'Availability Zone': subnet['AvailabilityZone'],
            'State': subnet['State']
        })
    print("Subnets fetched.")
    return inventory

def get_route_table_inventory():
    print("Fetching Route Tables...")
    ec2 = boto3.client('ec2')
    route_tables = ec2.describe_route_tables()['RouteTables']
    inventory = []
    for route_table in route_tables:
        routes = ', '.join([
            f"{route.get('DestinationCidrBlock', 'N/A')} (IPv4) -> {route.get('GatewayId', 'Local')}"
            if 'DestinationCidrBlock' in route else
            f"{route.get('DestinationIpv6CidrBlock', 'N/A')} (IPv6) -> {route.get('GatewayId', 'Local')}"
            for route in route_table['Routes']
        ])
        inventory.append({
            'Route Table ID': route_table['RouteTableId'],
            'VPC ID': route_table['VpcId'],
            'Routes': routes
        })
    print("Route Tables fetched.")
    return inventory

def get_nat_gateway_inventory():
    print("Fetching NAT Gateways...")
    ec2 = boto3.client('ec2')
    nat_gateways = ec2.describe_nat_gateways()['NatGateways']
    inventory = []
    for nat_gateway in nat_gateways:
        inventory.append({
            'NAT Gateway ID': nat_gateway['NatGatewayId'],
            'VPC ID': nat_gateway['VpcId'],
            'Subnet ID': nat_gateway['SubnetId'],
            'State': nat_gateway['State'],
            'Private IP': nat_gateway.get('NatGatewayAddresses', [{}])[0].get('PrivateIp', 'N/A'),
            'Public IP': nat_gateway.get('NatGatewayAddresses', [{}])[0].get('PublicIp', 'N/A'),
            'Allocation ID': nat_gateway.get('NatGatewayAddresses', [{}])[0].get('AllocationId', 'N/A'),
            'Creation Time': nat_gateway['CreateTime'].strftime('%Y-%m-%d %H:%M:%S')
        })
    print("NAT Gateways fetched.")
    return inventory

def get_vpc_peering_inventory():
    print("Fetching VPC Peering Connections...")
    ec2 = boto3.client('ec2')
    peerings = ec2.describe_vpc_peering_connections()['VpcPeeringConnections']
    inventory = []
    for peering in peerings:
        inventory.append({
            'Peering ID': peering['VpcPeeringConnectionId'],
            'Requester VPC': peering['RequesterVpcInfo']['VpcId'],
            'Accepter VPC': peering['AccepterVpcInfo']['VpcId'],
            'Status': peering['Status']['Code']
        })
    print("VPC Peering Connections fetched.")
    return inventory

def get_site_to_site_vpn_inventory():
    print("Fetching Site-to-Site VPN Connections...")
    ec2 = boto3.client('ec2')
    vpns = ec2.describe_vpn_connections()['VpnConnections']
    inventory = []
    for vpn in vpns:
        inventory.append({
            'VPN Connection ID': vpn['VpnConnectionId'],
            'Customer Gateway ID': vpn['CustomerGatewayId'],
            'VPN Gateway ID': vpn['VpnGatewayId'],
            'State': vpn['State'],
            'Type': vpn['Type']
        })
    print("Site-to-Site VPN Connections fetched.")
    return inventory

def get_transit_gateway_inventory():
    print("Fetching Transit Gateways...")
    ec2 = boto3.client('ec2')
    tgs = ec2.describe_transit_gateways()['TransitGateways']
    inventory = []
    for tg in tgs:
        inventory.append({
            'Transit Gateway ID': tg['TransitGatewayId'],
            'State': tg['State'],
            'Description': tg.get('Description', 'N/A'),
            'Amazon Side ASN': tg['Options'].get('AmazonSideAsn', 'N/A')
        })
    print("Transit Gateways fetched.")
    return inventory

def get_directory_service_inventory():
    print("Fetching Directory Service...")
    ds_client = boto3.client('ds')
    directories = ds_client.describe_directories()['DirectoryDescriptions']
    inventory = []
    for directory in directories:
        inventory.append({
            'Directory ID': directory['DirectoryId'],
            'Name': directory['Name'],
            'Type': directory['Type'],
            'State': directory['Stage'],
            'VPC ID': directory.get('VpcSettings', {}).get('VpcId', 'N/A'),
            'Subnet IDs': ', '.join(directory.get('VpcSettings', {}).get('SubnetIds', [])),
            'DNS IPs': ', '.join(directory.get('DnsIpAddrs', [])),
            'Description': directory.get('Description', 'N/A'),
            'Created Date': directory['LaunchTime'].strftime('%Y-%m-%d %H:%M:%S')
        })
    print("Directory Service fetched.")
    return inventory

def get_workspaces_inventory():
    print("Fetching WorkSpaces...")
    ws_client = boto3.client('workspaces')
    workspaces = ws_client.describe_workspaces()['Workspaces']
    inventory = []
    for workspace in workspaces:
        # Check if 'ModificationStates' exists and is not empty
        modification_states = workspace.get('ModificationStates', [])
        creation_date = modification_states[0]['StateChangeReason']['Message'] if modification_states else 'N/A'
        
        inventory.append({
            'Workspace ID': workspace['WorkspaceId'],
            'Directory ID': workspace['DirectoryId'],
            'User Name': workspace['UserName'],
            'State': workspace['State'],
            'Bundle ID': workspace['BundleId'],
            'Workspace Properties': {
                'Compute Type': workspace['WorkspaceProperties']['ComputeTypeName'],
                'Root Volume Size (GB)': workspace['WorkspaceProperties']['RootVolumeSizeGib'],
                'User Volume Size (GB)': workspace['WorkspaceProperties']['UserVolumeSizeGib']
            },
            'Creation Date': creation_date
        })
    print("WorkSpaces fetched.")
    return inventory

def save_to_excel(dataframes, filename):
    with pd.ExcelWriter(filename, engine='openpyxl') as writer:
        for name, df in dataframes.items():
            df.to_excel(writer, sheet_name=name, index=False)

def main():
    regions = ['ap-south-1']  # Add more regions as needed
    combined_inventory = {}

    print("\nStarting AWS Resource Inventory Collection...")
    
    # S3 Inventory
    print("\n🔍 Fetching S3 Buckets...")
    s3_buckets = get_s3_buckets()
    s3_inventory = [get_bucket_inventory_details(bucket['Name']) for bucket in s3_buckets]
    if s3_inventory:
        combined_inventory['S3 Buckets'] = pd.DataFrame(s3_inventory)
        print(f"✅ Found {len(s3_inventory)} S3 buckets")
    else:
        print("ℹ️ No S3 buckets found")

    # EC2 Inventory
    print("\n🔍 Fetching EC2 Instances...")
    ec2_inventory = []
    for region in regions:
        ec2_inventory.extend(get_ec2_instance_details(region))
    if ec2_inventory:
        combined_inventory['EC2 Instances'] = pd.DataFrame(ec2_inventory)
        print(f"✅ Found {len(ec2_inventory)} EC2 instances")
    else:
        print("ℹ️ No EC2 instances found")

    # Autoscaling Inventory
    print("\n🔍 Fetching Auto Scaling Groups...")
    autoscaling_inventory = get_autoscaling_group_inventory()
    if autoscaling_inventory:
        combined_inventory['Auto Scaling Groups'] = pd.DataFrame(autoscaling_inventory)
        print(f"✅ Found {len(autoscaling_inventory)} Auto Scaling groups")
    else:
        print("ℹ️ No Auto Scaling groups found")

    # ALB Inventory
    print("\n🔍 Fetching Application Load Balancers...")
    alb_inventory = get_alb_inventory()
    if alb_inventory:
        combined_inventory['ALBs'] = pd.DataFrame(alb_inventory)
        print(f"✅ Found {len(alb_inventory)} ALBs")
    else:
        print("ℹ️ No ALBs found")

    # WAF Inventory
    print("\n🔍 Fetching WAF Web ACLs...")
    waf_inventory = get_waf_inventory()
    if waf_inventory:
        combined_inventory['WAF Web ACLs'] = pd.DataFrame(waf_inventory)
        print(f"✅ Found {len(waf_inventory)} WAF Web ACLs")
    else:
        print("ℹ️ No WAF Web ACLs found")

    # EKS Inventory
    print("\n🔍 Fetching EKS Clusters...")
    eks_inventory = get_eks_clusters()
    if eks_inventory:
        combined_inventory['EKS Clusters'] = pd.DataFrame(eks_inventory)
        print(f"✅ Found {len(eks_inventory)} EKS clusters")
    else:
        print("ℹ️ No EKS clusters found")

    # CloudFront Inventory
    print("\n🔍 Fetching CloudFront Distributions...")
    cloudfront_inventory = get_cloudfront_inventory()
    if cloudfront_inventory:
        combined_inventory['CloudFront Distributions'] = pd.DataFrame(cloudfront_inventory)
        print(f"✅ Found {len(cloudfront_inventory)} CloudFront distributions")
    else:
        print("ℹ️ No CloudFront distributions found")

    # Route53 Inventory
    print("\n🔍 Fetching Route 53 Hosted Zones...")
    route53_inventory = get_route53_inventory()
    if route53_inventory:
        combined_inventory['Route 53 Hosted Zones'] = pd.DataFrame(route53_inventory)
        print(f"✅ Found {len(route53_inventory)} Route 53 hosted zones")
    else:
        print("ℹ️ No Route 53 hosted zones found")

    # Cognito Inventory
    print("\n🔍 Fetching Cognito User Pools...")
    cognito_inventory = get_cognito_inventory()
    if cognito_inventory:
        combined_inventory['Cognito User Pools'] = pd.DataFrame(cognito_inventory)
        print(f"✅ Found {len(cognito_inventory)} Cognito user pools")
    else:
        print("ℹ️ No Cognito user pools found")

    # API Gateway Inventory
    print("\n🔍 Fetching HTTP API Gateways...")
    api_gateway_inventory = get_http_api_gateway_inventory()
    if api_gateway_inventory:
        combined_inventory['HTTP API Gateways'] = pd.DataFrame(api_gateway_inventory)
        print(f"✅ Found {len(api_gateway_inventory)} HTTP API gateways")
    else:
        print("ℹ️ No HTTP API gateways found")

    # ECR Inventory
    print("\n🔍 Fetching ECR Repositories...")
    ecr_inventory = get_ecr_inventory()
    if ecr_inventory:
        combined_inventory['ECR Repositories'] = pd.DataFrame(ecr_inventory)
        print(f"✅ Found {len(ecr_inventory)} ECR repositories")
    else:
        print("ℹ️ No ECR repositories found")

    # FSx Inventory
    print("\n🔍 Fetching FSx File Systems...")
    fsx_inventory = get_fsx_inventory()
    if fsx_inventory:
        combined_inventory['FSx File Systems'] = pd.DataFrame(fsx_inventory)
        print(f"✅ Found {len(fsx_inventory)} FSx file systems")
    else:
        print("ℹ️ No FSx file systems found")

    # RDS Inventory
    print("\n🔍 Fetching RDS Instances...")
    rds_inventory = get_rds_inventory()
    if rds_inventory:
        combined_inventory['RDS Instances'] = pd.DataFrame(rds_inventory)
        print(f"✅ Found {len(rds_inventory)} RDS instances")
    else:
        print("ℹ️ No RDS instances found")

    # Direct Connect Inventory
    print("\n🔍 Fetching Direct Connect Connections...")
    direct_connect_inventory = get_direct_connect_inventory()
    if direct_connect_inventory:
        combined_inventory['Direct Connect Connections'] = pd.DataFrame(direct_connect_inventory)
        print(f"✅ Found {len(direct_connect_inventory)} Direct Connect connections")
    else:
        print("ℹ️ No Direct Connect connections found")

    # VPC Inventory
    print("\n🔍 Fetching VPCs...")
    vpc_inventory = get_vpc_inventory()
    if vpc_inventory:
        combined_inventory['VPCs'] = pd.DataFrame(vpc_inventory)
        print(f"✅ Found {len(vpc_inventory)} VPCs")
    else:
        print("ℹ️ No VPCs found")

    # Subnet Inventory
    print("\n🔍 Fetching Subnets...")
    subnet_inventory = get_subnet_inventory()
    if subnet_inventory:
        combined_inventory['Subnets'] = pd.DataFrame(subnet_inventory)
        print(f"✅ Found {len(subnet_inventory)} subnets")
    else:
        print("ℹ️ No subnets found")

    # Route Table Inventory
    print("\n🔍 Fetching Route Tables...")
    route_table_inventory = get_route_table_inventory()
    if route_table_inventory:
        combined_inventory['Route Tables'] = pd.DataFrame(route_table_inventory)
        print(f"✅ Found {len(route_table_inventory)} route tables")
    else:
        print("ℹ️ No route tables found")

    # NAT Gateway Inventory
    print("\n🔍 Fetching NAT Gateways...")
    nat_gateway_inventory = get_nat_gateway_inventory()
    if nat_gateway_inventory:
        combined_inventory['NAT Gateways'] = pd.DataFrame(nat_gateway_inventory)
        print(f"✅ Found {len(nat_gateway_inventory)} NAT gateways")
    else:
        print("ℹ️ No NAT gateways found")

    # VPC Peering Inventory
    print("\n🔍 Fetching VPC Peering Connections...")
    vpc_peering_inventory = get_vpc_peering_inventory()
    if vpc_peering_inventory:
        combined_inventory['VPC Peering Connections'] = pd.DataFrame(vpc_peering_inventory)
        print(f"✅ Found {len(vpc_peering_inventory)} VPC peering connections")
    else:
        print("ℹ️ No VPC peering connections found")

    # VPN Inventory
    print("\n🔍 Fetching Site-to-Site VPN Connections...")
    vpn_inventory = get_site_to_site_vpn_inventory()
    if vpn_inventory:
        combined_inventory['Site-to-Site VPN Connections'] = pd.DataFrame(vpn_inventory)
        print(f"✅ Found {len(vpn_inventory)} VPN connections")
    else:
        print("ℹ️ No VPN connections found")

    # Transit Gateway Inventory
    print("\n🔍 Fetching Transit Gateways...")
    transit_gateway_inventory = get_transit_gateway_inventory()
    if transit_gateway_inventory:
        combined_inventory['Transit Gateways'] = pd.DataFrame(transit_gateway_inventory)
        print(f"✅ Found {len(transit_gateway_inventory)} transit gateways")
    else:
        print("ℹ️ No transit gateways found")

    # Directory Service Inventory
    print("\n🔍 Fetching Directory Service...")
    directory_inventory = get_directory_service_inventory()
    if directory_inventory:
        combined_inventory['Directory Service'] = pd.DataFrame(directory_inventory)
        print(f"✅ Found {len(directory_inventory)} directory services")
    else:
        print("ℹ️ No directory services found")
    
    # Fetch WorkSpaces inventory
    print("\n🔍 Fetching WorkSpaces...")
    workspaces_inventory = get_workspaces_inventory()
    if workspaces_inventory:
        combined_inventory['WorkSpaces'] = pd.DataFrame(workspaces_inventory)
        print(f"✅ Found {len(workspaces_inventory)} WorkSpaces")
    else:
        print("ℹ️ No WorkSpaces found")

    # Save all inventories to Excel file
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = input("\nEnter a file name: ")
    actual = f'{filename}-{timestamp}.xlsx'
    save_to_excel(combined_inventory, actual)
    print(f"\n✅ AWS Inventory saved to {actual}")

if __name__ == '__main__':
    main()
