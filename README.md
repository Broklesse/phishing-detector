  PhishGuard 🛡️

A Flutter mobile app that detects phishing and malicious URLs in real-time.

  Screenshots

![Home](screenshots/Home.png)

![Medium Risk 1](screenshots/Medium%20Risk%201.png)

![Medium Risk 2](screenshots/Medium%20Risk%202.png)

![Medium Risk 3](screenshots/Medium%20Risk%203.png)

![Safe Risk 1](screenshots/Safe%20Risk%201.png)

![Safe Risk 2](screenshots/Safe%20Risk%202.png)

![Safe Risk 3](screenshots/Safe%20Risk%203.png)

![Scan History](screenshots/Scan%20History%20Section.png)

  Features

- Real-time URL scanning via VirusTotal (94+ engines)
- Google Safe Browsing API integration
- PhishTank pattern detection
- HTTPS status check
- Typosquatting detection
- Suspicious keyword analysis
- Scan history

  Setup

1. Clone the repo
2. Run flutter pub get
3. Add your API keys in lib/main.dart
4. Run flutter run

  API Keys needed

- VirusTotal: https://www.virustotal.com/gui/my-apikey
- Google Safe Browsing: https://console.cloud.google.com

  Built with

- Flutter 3.41
- VirusTotal API v3
- Google Safe Browsing API v4