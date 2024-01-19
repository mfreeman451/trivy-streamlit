import streamlit as st
import streamlit.web.cli as stcli
import sys
import json


# Severity Mapping: Higher numbers indicate higher severity
SEVERITY_ORDER = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "UNKNOWN": 1,
    "N/A": 0  # In case severity is not available
}


def start_app():
    sys.argv = ["streamlit", "run", "trivy_streamlit/main_module.py"]
    sys.exit(stcli.main())


class TrivyParser:
    def get_findings_from_json(self, json_data):
        if "Resources" in json_data:
            # JSON format from 'trivy k8s ...'
            return self.parse_k8s_format(json_data)
        elif "Results" in json_data:
            # JSON format from 'trivy image ...'
            return self.parse_image_format(json_data)
        else:
            # Unknown format
            return []

    def parse_k8s_format(self, json_data):
        findings = []

        resources = json_data.get("Resources", [])
        for resource in resources:
            namespace = resource.get('Namespace', 'N/A')
            kind = resource.get('Kind', 'N/A')
            name = resource.get('Name', 'N/A')
            resource_identifier = f"{namespace}/{kind}/{name}"

            for result in resource.get("Results", []):
                for vuln in result.get("Vulnerabilities", []):
                    finding = self.process_vulnerability(
                        vuln, resource_identifier
                    )
                    if finding:
                        findings.append(finding)

        return findings

    def parse_image_format(self, json_data):
        findings = []

        for result in json_data.get("Results", []):
            resource_identifier = result.get("Target", "N/A")

            for vuln in result.get("Vulnerabilities", []):
                finding = self.process_vulnerability(vuln, resource_identifier)
                if finding:
                    findings.append(finding)

        return findings

    def process_vulnerability(self, vuln, resource_identifier):
        vuln_id = vuln.get("VulnerabilityID", "N/A")
        pkg_name = vuln.get("PkgName", "N/A")
        severity = vuln.get("Severity", "N/A")
        installed_version = vuln.get("InstalledVersion", "N/A")
        fixed_version = vuln.get("FixedVersion", "N/A")
        description = vuln.get("Description", "N/A")

        finding = {
            "title": f"{vuln_id} in {pkg_name}",
            "severity": severity,
            "resource": resource_identifier,
            "installed_version": installed_version,
            "fixed_version": fixed_version,
            "description": description,
        }
        return finding
    
    def generate_markdown(self, findings):
        markdown_text = ""
        for finding in findings:
            markdown_text += f"- [ ] **{finding['title']}**: Severity - {finding['severity']}, Resource - {finding['resource']}, Installed Version - {finding['installed_version']}, Fixed Version - {finding['fixed_version']}\n"
        return markdown_text


# Streamlit app interface
st.title("Trivy Scan Results Viewer")

uploaded_file = st.file_uploader("Upload Trivy JSON File", type=['json'])

if uploaded_file is not None:
    # Read the file and load it as JSON
    json_data = json.load(uploaded_file)

    # Display raw JSON data for debugging purposes
    # st.json(json_data)

    # Create an instance of the parser and get findings
    parser = TrivyParser()
    findings = parser.get_findings_from_json(json_data)

    # Debugging: Display the count of findings
    st.write(f"Findings Count: {len(findings)}")

    if findings:

        findings.sort(
            key=lambda x: SEVERITY_ORDER.get(x['severity'], 0), 
            reverse=True
        )

        # Display findings in a more readable format
        for finding in findings:
            st.subheader(finding["title"])
            st.write(f"Severity: {finding['severity']}")
            st.write(f"Resource: {finding['resource']}")
            st.write(f"Installed Version: {finding['installed_version']}")
            st.write(f"Fixed Version: {finding['fixed_version']}")
            st.write("Description:", finding['description'])
            st.write("---")  # Line separator
        
        markdown_text = parser.generate_markdown(findings)

        # Save to file option
        st.download_button(
            label="Download Markdown",
            data=markdown_text,
            file_name="findings.md",
            mime="text/markdown"
        )
    else:
        st.write("No findings were detected in the uploaded file.")
    
