#!/usr/bin/env python3
"""
Build two XML files for the minimal-keyword experiment:
  1. xml/deploy/minimal-test.xml       -- every Keyword <Group> pruned to 1 <Term>
  2. xml/deploy/minimal-test-full.xml   -- original full keywords

Both are written as UTF-16 LE with BOM (Purview requirement).
"""

import xml.etree.ElementTree as ET
import copy
import os

FULL_XML = r"""<?xml version="1.0" encoding="utf-16"?>
<!-- TestPattern Bundle: minimal-test -->
<!-- 3 patterns | Generated 2026-03-14 -->
<!-- https://testpattern.dev -->
<RulePackage xmlns="http://schemas.microsoft.com/office/2011/mce">
  <RulePack id="86a6057b-9dfd-47ca-abef-d13cd3258764">
    <Version major="1" minor="0" build="0" revision="0" />
    <Publisher id="86a6057b-9dfd-47ca-abef-d13cd3258764" />
    <Details defaultLangCode="en-us">
      <LocalizedDetails langcode="en-us">
        <PublisherName>TestPattern</PublisherName>
        <Name>minimal-test</Name>
        <Description>TestPattern bundle with 3 patterns</Description>
      </LocalizedDetails>
    </Details>
  </RulePack>
  <Rules>
    <Entity id="2a272e46-f20f-494d-9d1a-ede077c20ef4" patternsProximity="300" recommendedConfidence="85" relaxProximity="false">
      <Pattern confidenceLevel="90">
        <IdMatch idRef="Regex_aws_access_key_global-aws-access-key" />
        <Match idRef="Pattern_global_aws_access_key_label_context_global-aws-access-key" />
        <Match idRef="Keyword_global_aws_access_key_domain_context_global-aws-access-key" />
        <Any minMatches="0" maxMatches="0">
          <Match idRef="Keyword_global_aws_access_key_noise_exclusion_global-aws-access-key" />
        </Any>
      </Pattern>
      <Pattern confidenceLevel="85">
        <IdMatch idRef="Regex_aws_access_key_global-aws-access-key" />
        <Match idRef="Keyword_aws_access_key_global-aws-access-key" />
        <Any minMatches="0" maxMatches="0">
          <Match idRef="Keyword_global_aws_access_key_noise_exclusion_global-aws-access-key" />
        </Any>
      </Pattern>
    </Entity>
    <Entity id="0ae36474-4f69-4977-856a-f015f2b716ba" patternsProximity="300" recommendedConfidence="85" relaxProximity="false">
      <Pattern confidenceLevel="90">
        <IdMatch idRef="Regex_general_password_global-general-password" />
        <Match idRef="Pattern_global_general_password_label_context_global-general-password" />
        <Match idRef="Keyword_global_general_password_domain_context_global-general-password" />
        <Any minMatches="0" maxMatches="0">
          <Match idRef="Keyword_global_general_password_noise_exclusion_global-general-password" />
        </Any>
      </Pattern>
      <Pattern confidenceLevel="85">
        <IdMatch idRef="Regex_general_password_global-general-password" />
        <Match idRef="Keyword_general_password_global-general-password" />
        <Any minMatches="0" maxMatches="0">
          <Match idRef="Keyword_global_general_password_noise_exclusion_global-general-password" />
        </Any>
      </Pattern>
    </Entity>
    <Entity id="85384545-fbee-49d6-81e6-ecc9af455267" patternsProximity="300" recommendedConfidence="85" relaxProximity="false">
      <Pattern confidenceLevel="90">
        <IdMatch idRef="Regex_slack_token_global-slack-token" />
        <Match idRef="Pattern_global_slack_token_label_context_global-slack-token" />
        <Match idRef="Keyword_global_slack_token_domain_context_global-slack-token" />
        <Any minMatches="0" maxMatches="0">
          <Match idRef="Keyword_global_slack_token_noise_exclusion_global-slack-token" />
        </Any>
      </Pattern>
      <Pattern confidenceLevel="85">
        <IdMatch idRef="Regex_slack_token_global-slack-token" />
        <Match idRef="Keyword_slack_token_global-slack-token" />
        <Any minMatches="0" maxMatches="0">
          <Match idRef="Keyword_global_slack_token_noise_exclusion_global-slack-token" />
        </Any>
      </Pattern>
    </Entity>
    <Regex id="Regex_aws_access_key_global-aws-access-key">\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b</Regex>
    <Regex id="Pattern_global_aws_access_key_label_context_global-aws-access-key">(?i)\\b(?:aws\\s+access\\s+key|aws|access|key)\\b</Regex>
    <Regex id="Regex_general_password_global-general-password">(?i)\b(?:password|passwd|pwd|pass)\s*[:=]\s*&quot;?[^\s&quot;&apos;]{6,}&quot;?</Regex>
    <Regex id="Pattern_global_general_password_label_context_global-general-password">(?i)\\b(?:general\\s+password|general|password)\\b</Regex>
    <Regex id="Regex_slack_token_global-slack-token">\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b</Regex>
    <Regex id="Pattern_global_slack_token_label_context_global-slack-token">(?i)\\b(?:slack\\s+token|slack|token)\\b</Regex>
    <Keyword id="Keyword_aws_access_key_global-aws-access-key">
      <Group matchStyle="word">
        <Term caseSensitive="false">aws</Term>
        <Term caseSensitive="false">access key</Term>
        <Term caseSensitive="false">access_key</Term>
        <Term caseSensitive="false">aws_access_key_id</Term>
        <Term caseSensitive="false">AKIA</Term>
        <Term caseSensitive="false">IAM</Term>
        <Term caseSensitive="false">secret key</Term>
        <Term caseSensitive="false">credentials</Term>
        <Term caseSensitive="false">amazon web services</Term>
        <Term caseSensitive="false">api key</Term>
      </Group>
    </Keyword>
    <Keyword id="Keyword_global_aws_access_key_domain_context_global-aws-access-key">
      <Group matchStyle="word">
        <Term caseSensitive="false">aws access key</Term>
        <Term caseSensitive="false">aws</Term>
        <Term caseSensitive="false">access</Term>
        <Term caseSensitive="false">key</Term>
        <Term caseSensitive="false">field</Term>
        <Term caseSensitive="false">identifier</Term>
        <Term caseSensitive="false">reference</Term>
      </Group>
    </Keyword>
    <Keyword id="Keyword_global_aws_access_key_noise_exclusion_global-aws-access-key">
      <Group matchStyle="word">
        <Term caseSensitive="false">sample</Term>
        <Term caseSensitive="false">template</Term>
        <Term caseSensitive="false">example</Term>
        <Term caseSensitive="false">dummy</Term>
        <Term caseSensitive="false">test data</Term>
        <Term caseSensitive="false">training data</Term>
        <Term caseSensitive="false">placeholder</Term>
        <Term caseSensitive="false">mock</Term>
        <Term caseSensitive="false">boilerplate</Term>
      </Group>
    </Keyword>
    <Keyword id="Keyword_general_password_global-general-password">
      <Group matchStyle="word">
        <Term caseSensitive="false">password</Term>
        <Term caseSensitive="false">passwd</Term>
        <Term caseSensitive="false">pwd</Term>
        <Term caseSensitive="false">credential</Term>
        <Term caseSensitive="false">login</Term>
        <Term caseSensitive="false">authentication</Term>
        <Term caseSensitive="false">secret</Term>
        <Term caseSensitive="false">passphrase</Term>
        <Term caseSensitive="false">connection string</Term>
        <Term caseSensitive="false">database password</Term>
        <Term caseSensitive="false">db password</Term>
        <Term caseSensitive="false">admin password</Term>
      </Group>
    </Keyword>
    <Keyword id="Keyword_global_general_password_domain_context_global-general-password">
      <Group matchStyle="word">
        <Term caseSensitive="false">general password</Term>
        <Term caseSensitive="false">general</Term>
        <Term caseSensitive="false">password</Term>
        <Term caseSensitive="false">field</Term>
        <Term caseSensitive="false">identifier</Term>
        <Term caseSensitive="false">reference</Term>
      </Group>
    </Keyword>
    <Keyword id="Keyword_global_general_password_noise_exclusion_global-general-password">
      <Group matchStyle="word">
        <Term caseSensitive="false">sample</Term>
        <Term caseSensitive="false">template</Term>
        <Term caseSensitive="false">example</Term>
        <Term caseSensitive="false">dummy</Term>
        <Term caseSensitive="false">test data</Term>
        <Term caseSensitive="false">training data</Term>
        <Term caseSensitive="false">placeholder</Term>
        <Term caseSensitive="false">mock</Term>
        <Term caseSensitive="false">boilerplate</Term>
      </Group>
    </Keyword>
    <Keyword id="Keyword_slack_token_global-slack-token">
      <Group matchStyle="word">
        <Term caseSensitive="false">slack</Term>
        <Term caseSensitive="false">xoxb</Term>
        <Term caseSensitive="false">xoxp</Term>
        <Term caseSensitive="false">bot token</Term>
        <Term caseSensitive="false">api token</Term>
        <Term caseSensitive="false">api key</Term>
        <Term caseSensitive="false">webhook</Term>
        <Term caseSensitive="false">workspace</Term>
        <Term caseSensitive="false">oauth token</Term>
        <Term caseSensitive="false">bearer token</Term>
        <Term caseSensitive="false">SLACK_TOKEN</Term>
        <Term caseSensitive="false">SLACK_BOT_TOKEN</Term>
      </Group>
    </Keyword>
    <Keyword id="Keyword_global_slack_token_domain_context_global-slack-token">
      <Group matchStyle="word">
        <Term caseSensitive="false">slack token</Term>
        <Term caseSensitive="false">slack</Term>
        <Term caseSensitive="false">token</Term>
        <Term caseSensitive="false">field</Term>
        <Term caseSensitive="false">identifier</Term>
        <Term caseSensitive="false">reference</Term>
      </Group>
    </Keyword>
    <Keyword id="Keyword_global_slack_token_noise_exclusion_global-slack-token">
      <Group matchStyle="word">
        <Term caseSensitive="false">sample</Term>
        <Term caseSensitive="false">template</Term>
        <Term caseSensitive="false">example</Term>
        <Term caseSensitive="false">dummy</Term>
        <Term caseSensitive="false">test data</Term>
        <Term caseSensitive="false">training data</Term>
        <Term caseSensitive="false">placeholder</Term>
        <Term caseSensitive="false">mock</Term>
        <Term caseSensitive="false">boilerplate</Term>
      </Group>
    </Keyword>
    <LocalizedStrings>
      <Resource idRef="2a272e46-f20f-494d-9d1a-ede077c20ef4">
        <Name default="true" langcode="en-us">TestPattern - AWS Access Key</Name>
        <Description default="true" langcode="en-us">Detects AWS Access Key patterns.</Description>
      </Resource>
      <Resource idRef="0ae36474-4f69-4977-856a-f015f2b716ba">
        <Name default="true" langcode="en-us">TestPattern - General Password</Name>
        <Description default="true" langcode="en-us">Detects general password patterns in documents and configuration files. This pattern is based on a Microsoft Purview built-in sensitive information type. In Purview, this is a broad, function-based detector. This keyword-based version flags documents that may contain passwords for further review.</Description>
      </Resource>
      <Resource idRef="85384545-fbee-49d6-81e6-ecc9af455267">
        <Name default="true" langcode="en-us">TestPattern - Slack Token</Name>
        <Description default="true" langcode="en-us">Detects Slack Token patterns. This pattern is based on a Microsoft Purview built-in sensitive information type. Users already running Purview may prefer to enable the built-in SIT directly, or use this version as a starting point for customisation.</Description>
      </Resource>
    </LocalizedStrings>
  </Rules>
</RulePackage>"""

NS = "http://schemas.microsoft.com/office/2011/mce"
ET.register_namespace("", NS)


def prune_keywords(xml_str: str) -> str:
    """Remove all but the first <Term> from every Keyword <Group>."""
    root = ET.fromstring(xml_str)

    for keyword in root.iter(f"{{{NS}}}Keyword"):
        for group in keyword.findall(f"{{{NS}}}Group"):
            terms = group.findall(f"{{{NS}}}Term")
            if len(terms) > 1:
                for term in terms[1:]:
                    group.remove(term)

    # Serialize back
    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode", xml_declaration=False)


def write_utf16(filepath: str, xml_content: str):
    """Write XML with UTF-16 LE BOM encoding as required by Purview."""
    # Ensure the XML declaration says utf-16
    full = '<?xml version="1.0" encoding="utf-16"?>\n' + xml_content
    with open(filepath, "wb") as f:
        f.write(b"\xff\xfe")  # UTF-16 LE BOM
        f.write(full.encode("utf-16-le"))


def main():
    out_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "xml", "deploy")
    os.makedirs(out_dir, exist_ok=True)

    # Strip the XML declaration from FULL_XML since we'll add our own
    xml_body = FULL_XML
    if xml_body.startswith("<?xml"):
        xml_body = xml_body[xml_body.index("?>") + 2:].lstrip("\n")

    # 1. Full version
    full_path = os.path.join(out_dir, "minimal-test-full.xml")
    write_utf16(full_path, xml_body)
    full_size = os.path.getsize(full_path)
    print(f"[OK] Full XML written: {full_path} ({full_size:,} bytes)")

    # 2. Minimal version (1 term per keyword group)
    # Parse the body (without declaration) to prune
    pruned_body = prune_keywords(xml_body)
    minimal_path = os.path.join(out_dir, "minimal-test.xml")
    write_utf16(minimal_path, pruned_body)
    minimal_size = os.path.getsize(minimal_path)
    print(f"[OK] Minimal XML written: {minimal_path} ({minimal_size:,} bytes)")

    # Stats
    # Count terms in each
    full_root = ET.fromstring(xml_body)
    min_root = ET.fromstring(pruned_body)
    full_terms = len(list(full_root.iter(f"{{{NS}}}Term")))
    min_terms = len(list(min_root.iter(f"{{{NS}}}Term")))

    full_keywords = len(list(full_root.iter(f"{{{NS}}}Keyword")))
    min_keywords = len(list(min_root.iter(f"{{{NS}}}Keyword")))

    print(f"\n--- Stats ---")
    print(f"Full:    {full_keywords} keyword groups, {full_terms} terms, {full_size:,} bytes")
    print(f"Minimal: {min_keywords} keyword groups, {min_terms} terms, {minimal_size:,} bytes")
    print(f"Reduction: {full_terms - min_terms} terms removed, {full_size - minimal_size:,} bytes saved ({(full_size - minimal_size)/full_size*100:.1f}%)")


if __name__ == "__main__":
    main()
