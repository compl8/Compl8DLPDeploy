# Changelog

All notable changes to the QGISCF DLP Deployment Toolkit will be documented in this file.

## [1.0.0] - 2026-02-23

Initial production release. JSON-driven DLP deployment with WhatIf, Cleanup, retry logic, and pre-flight validation.

- Sensitivity label deployment from `config/labels.json` with visual markings and label policy publishing
- DLP policy and rule deployment across 5 workloads (Exchange, OneDrive, SharePoint, Endpoint, Teams)
- Custom SIT rule package deployment with pre-flight comparison, auto-backup, version bumping, and capacity estimation
- Shared module (`QGISCF-DLP.psm1`) with config merging, SIT condition building, retry with backoff, and XML validation
- Change pack support for targeted rule modifications via CSV
- Classifier validation against tenant SIT inventory
- Data pipeline scripts for generating `classifiers.json` from risk analysis spreadsheet
