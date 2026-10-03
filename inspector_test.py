import boto3

REGION = "ap-south-1"

# Connect to Amazon Inspector
inspector = boto3.client("inspector2", region_name=REGION)

print("=== CLOUDSHIELD AWS CONNECTION TEST ===")

# Get EC2 Inspector findings
response = inspector.list_findings(maxResults=5)

findings = response.get("findings", [])

print(f"\nEC2 findings received: {len(findings)}")

for finding in findings:
    print("--------------------------------")
    print("Title:", finding.get("title"))
    print("Severity:", finding.get("severity"))
    print("Type:", finding.get("type"))

    resources = finding.get("resources", [])
    if resources:
        print("Resource:", resources[0].get("id"))

print("\n=== ECR SCAN TEST ===")

# Connect to Amazon ECR
ecr = boto3.client("ecr", region_name=REGION)

ecr_response = ecr.describe_image_scan_findings(
    repositoryName="cloudshield-app",
    imageId={"imageTag": "latest"}
)

scan = ecr_response.get("imageScanFindings", {})

print("ECR vulnerability counts:")
print(scan.get("findingSeverityCounts", {}))

print("\nCloudShield AWS connection successful!")