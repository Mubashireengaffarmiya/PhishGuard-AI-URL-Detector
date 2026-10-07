"""
How PhishGuard Works & Academic Presentation View for PhishGuard AI.
Comprehensive educational deep-dive and presentation deck for faculty reviews,
viva defenses, and cybersecurity demonstrations.
"""

import streamlit as st


def render_how_it_works_view():
    """Renders the educational guide and presentation deck."""
    st.markdown("### 📚 How PhishGuard AI Works & Academic Presentation")
    st.caption("Comprehensive technical architecture, machine-learning methodology, and viva defense presentation deck.")

    tabs = st.tabs([
        "🎓 Faculty Presentation Deck",
        "🧠 Machine Learning Methodology",
        "📐 Feature Engineering & Math",
        "🖼️ Multi-Modal Intake (OCR & QR)",
        "🚀 Future Scope"
    ])

    with tabs[0]:
        st.markdown("#### 🎓 Project Defense: Presentation Deck")
        
        st.markdown(
            """
            ##### 1. Problem Statement & Motivation
            - **Global Threat Vector**: Phishing accounts for over **85% of initial corporate breaches** and over **$2.7B in reported annual losses** (IC3).
            - **Evasion Tactics**: Modern threat actors employ short-lived disposable domains, URL shorteners, multi-level subdomains, and obfuscated tokens that easily bypass static signature blocklists.
            - **Black-Box AI Limitation**: Standard deep-learning approaches provide opaque risk scores without explaining *why* an alert was generated, causing alert fatigue for security analysts.
            - **The Solution**: **PhishGuard AI** implements an explainable, multi-model ensemble URL security engine with multi-modal OCR and QR intake, passive network reconnaissance, and human-grounded indicator reasoning.

            ##### 2. System Architecture Overview
            - **Intake Layer**: Three input channels (Manual URL, QR Code via OpenCV, and Screenshot OCR via Tesseract).
            - **Sanitization & Normalization**: Strips dangerous wrapper characters, standardizes scheme, validates network hostname, and prevents command injection.
            - **Feature Extraction**: Deterministic extraction of 42 lexical, structural, statistical (Shannon entropy), and security indicators.
            - **Ensemble Core**: Heterogeneous ensemble combining Random Forest (50%), Decision Tree (25%), and Logistic Regression (25%).
            - **Explainability Layer**: Feature taxonomy attribution, indicator tables with technical limitations, and rule-based AI security analyst.
            - **Defensive Safeguards**: Zero automatic execution or web page rendering; 100% offline rule-based AI fallback.

            ##### 3. Dataset & Model Training
            - **Dataset Composition**: Balanced dataset with 2,416 URL samples (1,932 training split, 484 holdout test split).
            - **Algorithms Trained**:
              - *Random Forest Classifier*: 100 estimators, maximum depth 15, balanced class weights.
              - *Decision Tree Classifier*: CART algorithm, maximum depth 10.
              - *Logistic Regression*: L2 penalty, StandardScaled feature vectors.
            """
        )

    with tabs[1]:
        st.markdown("#### 🧠 Machine Learning Algorithms & Ensemble Mechanics")
        st.markdown(
            """
            ##### Why an Ensemble Approach?
            A single machine-learning model is susceptible to bias or high variance:
            - **Logistic Regression**: A linear model optimizing log-odds. Highly reliable for single extreme indicators, but incapable of capturing non-linear feature interactions.
            - **Decision Tree**: Rapid, interpretable orthogonal splits. Captures complex conditional logic (e.g. *if domain is short AND digit count is high*), but can be prone to overfitting.
            - **Random Forest**: An ensemble of 100 decorrelated decision trees using bootstrap aggregating (bagging). Drastically suppresses variance and provides robust generalization.

            ##### Weighted Voting & Disagreement Detection
            $$\\text{Ensemble Probability} = 0.50 \\times P(\\text{RF}) + 0.25 \\times P(\\text{DT}) + 0.25 \\times P(\\text{LR})$$

            When individual models disagree (e.g. Tree votes Phishing while Linear votes Safe), PhishGuard flags a **Model Divergence Alert** rather than masking variance.
            """
        )

    with tabs[2]:
        st.markdown("#### 📐 Feature Engineering & Mathematical Formulations")
        st.markdown(
            """
            ##### Shannon Character Entropy
            Measures the uncertainty and randomness of character sequences in a URL string:
            $$H(X) = - \\sum_{i=1}^{n} P(x_i) \\log_2 P(x_i)$$
            - High entropy ($>4.5$ bits/symbol) indicates algorithmically generated domains (DGA), pseudo-random victim IDs, or obfuscated hex parameters.
            - Natural domain names exhibit balanced entropy ($3.0 - 4.0$ bits/symbol).

            ##### Lexical & Structural Indicators (42 Total)
            1. **URL & Domain Lengths**: Truncation tactics on mobile screens.
            2. **Delimiter Frequencies**: Counting slashes, dots, hyphens, and equal signs.
            3. **Ratios**: Digit ratio, special character ratio, hyphen ratio, and vowel count.
            4. **Heuristic Flags**: Direct numeric IP addresses, userinfo redirection (`@`), non-standard ports (e.g. 8080), and link shorteners.
            """
        )

    with tabs[3]:
        st.markdown("#### 🖼️ Multi-Modal Intake: OCR & QR Decoding Pipeline")
        st.markdown(
            """
            ##### 1. Computer Vision QR Matrix Decoding
            - Utilizes OpenCV `QRCodeDetector` with Gaussian adaptive thresholding.
            - Extracts raw payload bytes and verifies whether the payload constitutes a usable web URL.
            - Prevents auto-navigation: URLs are displayed for human review before ML evaluation.

            ##### 2. Local Optical Character Recognition (Tesseract)
            - Converts screenshots of emails, SMS messages, and social media posts into character streams.
            - Computes average word confidence and isolates URL candidates via regex patterns.
            - **Conservative Error Correction**: Suggests user-reviewable corrections for common OCR confusions:
              - Digit `1` $\\leftrightarrow$ Letter `l` (e.g., `paypa1.com` $\\rightarrow$ `paypal.com`)
              - Digit `0` $\\leftrightarrow$ Letter `o` (e.g., `micr0soft.com` $\\rightarrow$ `microsoft.com`)
              - Ligature `rn` $\\leftrightarrow$ Letter `m`
            - **Bounding Box Annotation**: Draws coordinates around detected URLs on the screenshot for visual confirmation.
            """
        )

    with tabs[4]:
        st.markdown("#### 🚀 Future Scope & Production Roadmap")
        st.markdown(
            """
            ##### Near-Term Extensions
            - **Chromium / Firefox Browser Extension**: Real-time evaluation of clicked links in the browser toolbar with pre-click alerts.
            - **Email Gateway (Milter) Plugin**: Automated inbound scanning of email body hyperlinks for Postfix/Sendmail.
            - **Continuous Model Retraining Pipeline**: Automated scheduled ingestion of daily CISA and PhishTank threat feeds.

            ##### Advanced Research Directions
            - **DOM & Visual Similarity (Multimodal)**: Comparing rendered website screenshots against brand logos using Siamese Neural Networks.
            - **NLP Transformer Analysis**: Fine-tuned BERT for analyzing surrounding email context and psychological urgency cues.
            - **Federated Learning**: Collaborative model training across enterprise SOCs without sharing private user URL traffic.
            """
        )
