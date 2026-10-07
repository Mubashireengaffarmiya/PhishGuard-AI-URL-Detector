# 🛡️ PhishGuard AI

## AI-Powered Phishing Detection & Security Analysis Platform

<p align="center">
  <strong>Detect • Analyze • Explain • Protect</strong>
</p>

<p align="center">
  An intelligent cybersecurity platform that combines machine learning, URL analysis, QR scanning, image/OCR processing, threat intelligence, risk analysis, explainability, history, analytics, and security reporting.
</p>

<p align="center">

![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python)
![Streamlit](https://img.shields.io/badge/Streamlit-App-red?logo=streamlit)
![Machine Learning](https://img.shields.io/badge/ML-Ensemble-orange)
![Scikit Learn](https://img.shields.io/badge/Scikit--Learn-ML-F7931E?logo=scikit-learn)
![Pytest](https://img.shields.io/badge/Testing-Pytest-green?logo=pytest)
![GitHub](https://img.shields.io/badge/Repository-GitHub-black?logo=github)

</p>

---

# 📌 Table of Contents

- [Overview](#-overview)
- [Problem Statement](#-problem-statement)
- [Objectives](#-objectives)
- [Solution](#-solution)
- [Key Features](#-key-features)
- [System Architecture](#-system-architecture)
- [Complete Workflow](#-complete-workflow)
- [Working Modules](#-working-modules)
- [URL Detection Module](#-url-detection-module)
- [Feature Extraction](#-feature-extraction)
- [Machine Learning Module](#-machine-learning-module)
- [Ensemble Prediction](#-ensemble-prediction)
- [Explainable AI](#-explainable-ai)
- [Risk Analysis](#-risk-analysis)
- [QR Scanner](#-qr-scanner)
- [Image Scanner](#-image-scanner)
- [OCR Processing](#-ocr-processing)
- [Threat Intelligence](#-threat-intelligence)
- [Scan History](#-scan-history)
- [Security Reports](#-security-reports)
- [Analytics](#-analytics)
- [Health Monitoring](#-health-monitoring)
- [AI Analyst](#-ai-analyst)
- [Project Structure](#-project-structure)
- [Module Architecture](#-module-architecture)
- [Machine Learning Pipeline](#-machine-learning-pipeline)
- [Data Flow](#-data-flow)
- [Testing](#-testing)
- [Technology Stack](#-technology-stack)
- [Installation](#-installation)
- [Running the Application](#-running-the-application)
- [Security](#-security)
- [Limitations](#-limitations)
- [Future Scope](#-future-scope)
- [Project Highlights](#-project-highlights)
- [Disclaimer](#-disclaimer)

---

# 🌐 Overview

**PhishGuard AI** is an AI-powered cybersecurity platform designed to detect potentially malicious and phishing URLs.

Phishing attacks commonly use deceptive URLs, fake login pages, malicious QR codes, shortened links, suspicious domains, and visually misleading content to trick users into revealing sensitive information.

PhishGuard AI provides a centralized security platform where users can submit suspicious URLs, QR codes, or images and receive a structured security analysis.

The platform combines:

- 🤖 Machine Learning
- 🔗 URL Feature Extraction
- ⚖️ Ensemble Prediction
- 🧠 Explainable AI
- ⚠️ Risk Analysis
- 📷 QR Code Scanning
- 🖼️ Image Analysis
- 🔤 OCR Processing
- 🌐 Threat Intelligence
- 📜 Scan History
- 📄 Security Reports
- 📊 Analytics
- ❤️ Health Monitoring

The main objective is to move beyond a simple **SAFE / PHISHING** prediction and provide meaningful security context around the result.

---

# 🚨 Problem Statement

Phishing is one of the most common cybersecurity threats faced by internet users.

Attackers create URLs that appear legitimate but may redirect users to malicious websites designed to steal:

- Passwords
- Banking credentials
- Credit/debit card information
- Personal information
- Authentication credentials
- Payment information
- Corporate data

A normal user may not be able to determine whether a URL is suspicious simply by looking at it.

Malicious URLs may contain:

- IP addresses instead of domains
- Excessive subdomains
- Unusual characters
- Suspicious symbols
- Long URL structures
- Misleading paths
- Redirect patterns
- Excessive hyphens
- Unusual combinations of letters and numbers

Phishing links can also be distributed through QR codes and images.

Therefore, there is a need for an intelligent security platform that can automatically analyze suspicious content and provide an understandable security assessment.

---

# 🎯 Objectives

The main objectives of PhishGuard AI are:

1. Detect potentially phishing URLs.
2. Extract meaningful security features from URLs.
3. Apply multiple machine learning models.
4. Combine model predictions using an ensemble approach.
5. Provide explainable security analysis.
6. Analyze URLs obtained from QR codes.
7. Support image and OCR-based security workflows.
8. Provide additional threat intelligence.
9. Calculate and present risk information.
10. Maintain scan history.
11. Generate structured security reports.
12. Provide analytics for security activity.
13. Monitor application/service health.
14. Provide a modular and extensible cybersecurity architecture.

---

# 💡 Solution

PhishGuard AI uses a layered cybersecurity architecture.

A suspicious input is processed through multiple stages:

```text
User Input
    ↓
Input Validation
    ↓
URL Normalization
    ↓
Feature Extraction
    ↓
Machine Learning Models
    ↓
Ensemble Prediction
    ↓
Risk Analysis
    ↓
Explainability
    ↓
Threat Intelligence
    ↓
Security Result
    ↓
History / Analytics / Report
