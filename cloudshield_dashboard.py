import boto3
import pandas as pd
import streamlit as st
import plotly.express as px

# ============================================================
# CONFIGURATION
# ============================================================

REGION = "ap-south-1"
ECR_REPOSITORY = "cloudshield-app"
ECR_IMAGE_TAG = "latest"

st.set_page_config(
    page_title="CloudShield",
    page_icon="🛡️",
    layout="wide"
)

# ============================================================
# AWS CLIENTS
# ============================================================

inspector = boto3.client(
    "inspector2",
    region_name=REGION
)

ecr = boto3.client(
    "ecr",
    region_name=REGION
)

# ============================================================
# HEADER
# ============================================================

st.title("🛡️ CloudShield")

st.subheader(
    "AWS Vulnerability Detection, Risk Prioritization & Remediation"
)

st.caption(
    "Amazon Inspector powered security monitoring for Amazon EC2 and Amazon ECR"
)

# ============================================================
# REFRESH BUTTON
# ============================================================

refresh_col, status_col = st.columns([1, 5])

with refresh_col:

    if st.button("🔄 Refresh Findings"):

        st.cache_data.clear()
        st.rerun()

with status_col:

    st.caption(
        "Region: ap-south-1 | EC2: Amazon Inspector | "
        "ECR: Enhanced Scanning"
    )

# ============================================================
# EC2 FINDINGS
# ============================================================

@st.cache_data(ttl=300)
def get_ec2_findings():

    findings = []

    paginator = inspector.get_paginator(
        "list_findings"
    )

    for page in paginator.paginate():

        findings.extend(
            page.get("findings", [])
        )

    rows = []

    for finding in findings:

        resources = finding.get(
            "resources",
            []
        )

        resource_id = ""
        resource_type = ""

        if resources:

            resource_id = resources[0].get(
                "id",
                ""
            )

            resource_type = resources[0].get(
                "type",
                ""
            )

        package_details = finding.get(
            "packageVulnerabilityDetails",
            {}
        )

        vulnerable_packages = package_details.get(
            "vulnerablePackages",
            []
        )

        package_name = ""
        fixed_version = ""

        if vulnerable_packages:

            package_name = vulnerable_packages[0].get(
                "name",
                ""
            )

            fixed_version = vulnerable_packages[0].get(
                "fixedInVersion",
                ""
            )

        rows.append(
            {
                "Source": "EC2",
                "Resource": resource_id,
                "Type": resource_type,
                "CVE": package_details.get(
                    "vulnerabilityId",
                    finding.get("title", "")
                ),
                "Title": finding.get(
                    "title",
                    ""
                ),
                "Severity": finding.get(
                    "severity",
                    "UNTRIAGED"
                ),
                "Package": package_name,
                "Fix": fixed_version,
                "Score": finding.get(
                    "inspectorScore",
                    0
                )
            }
        )

    return rows


# ============================================================
# ECR FINDINGS
# ============================================================

@st.cache_data(ttl=300)
def get_ecr_findings():

    response = ecr.describe_image_scan_findings(
        repositoryName=ECR_REPOSITORY,
        imageId={
            "imageTag": ECR_IMAGE_TAG
        }
    )

    scan = response.get(
        "imageScanFindings",
        {}
    )

    enhanced_findings = scan.get(
        "enhancedFindings",
        []
    )

    rows = []

    for finding in enhanced_findings:

        package_details = finding.get(
            "packageVulnerabilityDetails",
            {}
        )

        vulnerable_packages = package_details.get(
            "vulnerablePackages",
            []
        )

        package_name = ""
        fixed_version = ""

        if vulnerable_packages:

            package_name = vulnerable_packages[0].get(
                "name",
                ""
            )

            fixed_version = vulnerable_packages[0].get(
                "fixedInVersion",
                ""
            )

        rows.append(
            {
                "Source": "ECR",
                "Resource": ECR_REPOSITORY,
                "Type": "AWS_ECR_CONTAINER_IMAGE",
                "CVE": package_details.get(
                    "vulnerabilityId",
                    ""
                ),
                "Title": finding.get(
                    "title",
                    ""
                ),
                "Severity": finding.get(
                    "severity",
                    "UNTRIAGED"
                ),
                "Package": package_name,
                "Fix": fixed_version,
                "Score": finding.get(
                    "inspectorScore",
                    0
                )
            }
        )

    return rows


# ============================================================
# RISK PRIORITY
# ============================================================

def calculate_risk(row):

    severity = row["Severity"]

    try:
        score = float(row["Score"])
    except:
        score = 0

    if severity == "CRITICAL":

        base = 4

    elif severity == "HIGH":

        base = 3

    elif severity == "MEDIUM":

        base = 2

    elif severity == "LOW":

        base = 1

    else:

        base = 0

    risk_value = (base * 10) + score

    if severity == "UNTRIAGED":

        return "P3 - Low"

    if risk_value >= 45:

        return "P0 - Immediate"

    elif risk_value >= 35:

        return "P1 - High"

    elif risk_value >= 20:

        return "P2 - Medium"

    else:

        return "P3 - Low"


# ============================================================
# LOAD DATA
# ============================================================

@st.cache_data(ttl=300)
def load_data():

    ec2_data = get_ec2_findings()

    ecr_data = get_ecr_findings()

    all_data = ec2_data + ecr_data

    df = pd.DataFrame(
        all_data
    )

    if not df.empty:

        df["Risk Priority"] = df.apply(
            calculate_risk,
            axis=1
        )

    return df


# ============================================================
# FINDINGS FILTER FUNCTION
# ============================================================

def show_findings(
    data,
    key_prefix
):

    if data.empty:

        st.info(
            "No findings available."
        )

        return data

    col1, col2 = st.columns(2)

    with col1:

        severity_filter = st.multiselect(
            "Severity",
            [
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "LOW",
                "UNTRIAGED"
            ],
            default=[
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "LOW",
                "UNTRIAGED"
            ],
            key=f"{key_prefix}_severity"
        )

    with col2:

        priority_filter = st.multiselect(
            "Risk Priority",
            [
                "P0 - Immediate",
                "P1 - High",
                "P2 - Medium",
                "P3 - Low"
            ],
            default=[
                "P0 - Immediate",
                "P1 - High",
                "P2 - Medium",
                "P3 - Low"
            ],
            key=f"{key_prefix}_priority"
        )

    search_text = st.text_input(
        "🔎 Search CVE or package",
        key=f"{key_prefix}_search"
    )

    filtered = data[
        data["Severity"].isin(
            severity_filter
        )
        &
        data["Risk Priority"].isin(
            priority_filter
        )
    ]

    if search_text:

        search_lower = search_text.lower()

        filtered = filtered[
            filtered["CVE"]
            .fillna("")
            .str.lower()
            .str.contains(
                search_lower,
                regex=False
            )
            |
            filtered["Package"]
            .fillna("")
            .str.lower()
            .str.contains(
                search_lower,
                regex=False
            )
        ]

    st.write(
        f"Showing **{len(filtered)}** findings"
    )

    if not filtered.empty:

        st.dataframe(
            filtered[
                [
                    "Source",
                    "Resource",
                    "CVE",
                    "Severity",
                    "Risk Priority",
                    "Package",
                    "Fix",
                    "Score"
                ]
            ],
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "No findings match the selected filters."
        )

    return filtered


# ============================================================
# MAIN DASHBOARD
# ============================================================

try:

    df = load_data()

    if df.empty:

        st.warning(
            "No vulnerability findings were returned."
        )

        st.stop()

    # ========================================================
    # KPI COUNTS
    # ========================================================

    total = len(df)

    critical = len(
        df[
            df["Severity"] == "CRITICAL"
        ]
    )

    high = len(
        df[
            df["Severity"] == "HIGH"
        ]
    )

    medium = len(
        df[
            df["Severity"] == "MEDIUM"
        ]
    )

    low = len(
        df[
            df["Severity"] == "LOW"
        ]
    )

    untriaged = len(
        df[
            df["Severity"] == "UNTRIAGED"
        ]
    )

    immediate = len(
        df[
            df["Risk Priority"]
            == "P0 - Immediate"
        ]
    )

    # ========================================================
    # KPI DISPLAY
    # ========================================================

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Total Findings",
        total
    )

    col2.metric(
        "🔴 Critical",
        critical
    )

    col3.metric(
        "🟠 High",
        high
    )

    col4.metric(
        "🟡 Medium",
        medium
    )

    col5, col6, col7, col8 = st.columns(4)

    col5.metric(
        "🟢 Low",
        low
    )

    col6.metric(
        "⚪ Untriaged",
        untriaged
    )

    col7.metric(
        "🚨 P0 Immediate",
        immediate
    )

    col8.metric(
        "☁️ Resources",
        df["Resource"].nunique()
    )

    st.divider()

    # ========================================================
    # EXECUTIVE SUMMARY
    # ========================================================

    st.subheader(
        "📋 Security Overview"
    )

    st.write(
        f"CloudShield is currently monitoring "
        f"**{total:,} vulnerability findings** across "
        f"**{df['Resource'].nunique()} resources**."
    )

    st.write(
        f"There are **{critical:,} Critical**, "
        f"**{high:,} High**, "
        f"**{medium:,} Medium**, "
        f"**{low:,} Low**, and "
        f"**{untriaged:,} Untriaged** findings."
    )

    st.info(
        "CloudShield combines Amazon Inspector findings "
        "with risk prioritization and remediation guidance "
        "to help security teams focus on higher-risk findings."
    )

    # ========================================================
    # RISK EXPLANATION
    # ========================================================

    with st.expander(
        "ℹ️ How CloudShield prioritizes risk"
    ):

        st.write(
            "CloudShield combines vulnerability severity "
            "with the Amazon Inspector score."
        )

        st.write(
            "**P0 - Immediate:** Critical/high risk "
            "requiring immediate attention."
        )

        st.write(
            "**P1 - High:** High-risk vulnerability "
            "requiring prompt remediation."
        )

        st.write(
            "**P2 - Medium:** Vulnerability that should "
            "be addressed during normal remediation."
        )

        st.write(
            "**P3 - Low:** Lower-priority or untriaged finding."
        )

    # ========================================================
    # SEVERITY CHART
    # ========================================================

    col1, col2 = st.columns(2)

    with col1:

        st.subheader(
            "📊 Findings by Severity"
        )

        severity_order = [
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "UNTRIAGED"
        ]

        severity_counts = (
            df["Severity"]
            .value_counts()
            .reindex(
                severity_order,
                fill_value=0
            )
            .reset_index()
        )

        severity_counts.columns = [
            "Severity",
            "Count"
        ]

        fig1 = px.bar(
            severity_counts,
            x="Severity",
            y="Count",
            text="Count",
            title="Vulnerability Severity"
        )

        st.plotly_chart(
            fig1,
            use_container_width=True
        )

    # ========================================================
    # SOURCE CHART
    # ========================================================

    with col2:

        st.subheader(
            "☁️ Findings by Source"
        )

        source_counts = (
            df["Source"]
            .value_counts()
            .reset_index()
        )

        source_counts.columns = [
            "Source",
            "Count"
        ]

        fig2 = px.pie(
            source_counts,
            names="Source",
            values="Count",
            hole=0.45,
            title="EC2 vs ECR"
        )

        st.plotly_chart(
            fig2,
            use_container_width=True
        )

    # ========================================================
    # RISK CHART
    # ========================================================

    st.subheader(
        "🎯 CloudShield Risk Priority Distribution"
    )

    priority_order = [
        "P0 - Immediate",
        "P1 - High",
        "P2 - Medium",
        "P3 - Low"
    ]

    risk_counts = (
        df["Risk Priority"]
        .value_counts()
        .reindex(
            priority_order,
            fill_value=0
        )
        .reset_index()
    )

    risk_counts.columns = [
        "Risk Priority",
        "Count"
    ]

    fig3 = px.bar(
        risk_counts,
        x="Risk Priority",
        y="Count",
        text="Count",
        title="Risk Priority"
    )

    st.plotly_chart(
        fig3,
        use_container_width=True
    )

    st.divider()

    # ========================================================
    # DOWNLOAD CSV
    # ========================================================

    st.subheader(
        "📥 Export Security Findings"
    )

    csv_data = df.to_csv(
        index=False
    ).encode("utf-8")

    st.download_button(
        label="📥 Download Findings CSV",
        data=csv_data,
        file_name="cloudshield_findings.csv",
        mime="text/csv"
    )

    st.divider()

    # ========================================================
    # TABS
    # ========================================================

    tab1, tab2, tab3 = st.tabs(
        [
            "🔎 All Findings",
            "🖥️ EC2 Findings",
            "📦 ECR Findings"
        ]
    )

    # ========================================================
    # ALL FINDINGS
    # ========================================================

    with tab1:

        show_findings(
            df,
            "all"
        )

    # ========================================================
    # EC2 FINDINGS
    # ========================================================

    with tab2:

        ec2_df = df[
            df["Source"] == "EC2"
        ]

        st.info(
            f"Amazon EC2 findings: {len(ec2_df):,}"
        )

        show_findings(
            ec2_df,
            "ec2"
        )

    # ========================================================
    # ECR FINDINGS
    # ========================================================

    with tab3:

        ecr_df = df[
            df["Source"] == "ECR"
        ]

        st.info(
            f"Amazon ECR findings: {len(ecr_df):,}"
        )

        show_findings(
            ecr_df,
            "ecr"
        )

    # ========================================================
    # TOP PRIORITY FINDINGS
    # ========================================================

    st.divider()

    st.subheader(
        "🚨 Top Priority Findings"
    )

    priority_map = {
        "P0 - Immediate": 0,
        "P1 - High": 1,
        "P2 - Medium": 2,
        "P3 - Low": 3
    }

    priority_df = df.copy()

    priority_df["PriorityOrder"] = (
        priority_df["Risk Priority"]
        .map(priority_map)
    )

    priority_df = priority_df.sort_values(
        by=[
            "PriorityOrder",
            "Score"
        ],
        ascending=[
            True,
            False
        ]
    )

    top_findings = priority_df.head(10)

    st.dataframe(
        top_findings[
            [
                "Source",
                "CVE",
                "Severity",
                "Risk Priority",
                "Package",
                "Fix",
                "Score"
            ]
        ],
        use_container_width=True,
        hide_index=True
    )

    # ========================================================
    # REMEDIATION GUIDANCE
    # ========================================================

    st.divider()

    st.subheader(
        "🔧 Remediation Guidance"
    )

    remediation_df = priority_df[
        priority_df["Severity"].isin(
            [
                "CRITICAL",
                "HIGH"
            ]
        )
    ]

    if remediation_df.empty:

        st.success(
            "No Critical or High findings found."
        )

    else:

        for _, row in remediation_df.head(10).iterrows():

            with st.expander(
                f"🚨 {row['Risk Priority']} | "
                f"{row['Severity']} | "
                f"{row['CVE']}"
            ):

                st.write(
                    f"**Source:** {row['Source']}"
                )

                st.write(
                    f"**Resource:** {row['Resource']}"
                )

                st.write(
                    f"**Package:** {row['Package']}"
                )

                st.write(
                    f"**Inspector Score:** {row['Score']}"
                )

                if row["Fix"]:

                    st.success(
                        f"Recommended fixed version: "
                        f"{row['Fix']}"
                    )

                else:

                    st.warning(
                        "No fixed version is currently available."
                    )

                if row["Source"] == "EC2":

                    st.write(
                        "Recommended action: update the "
                        "affected package on the EC2 instance "
                        "and verify the vulnerability again "
                        "through Amazon Inspector."
                    )

                else:

                    st.write(
                        "Recommended action: update the "
                        "vulnerable package or base image, "
                        "rebuild the Docker image, push the "
                        "new image to Amazon ECR, and verify "
                        "the new scan results."
                    )

    # ========================================================
    # FOOTER
    # ========================================================

    st.divider()

    st.caption(
        "CloudShield | Amazon Inspector | Amazon EC2 | "
        "Amazon ECR | Region: ap-south-1"
    )

# ============================================================
# ERROR HANDLING
# ============================================================

except Exception as e:

    st.error(
        "CloudShield could not retrieve AWS vulnerability data."
    )

    st.exception(e)