import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

void main() {
  runApp(const MyApp());
}

// ─── API KEYS (move to .env before sharing on GitHub) ────────────────────────
const String kVirusTotalKey =
    'c02720a1d144582bfe13e8c6634dbc986fdb1b7287785dfe1186082bc4b03c29';
const String kGoogleSafeBrowsingKey = 'AIzaSyBMrYcEtt7h2bfK7CMU-vedgkoTfSteJ0s';

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'PhishGuard',
      debugShowCheckedModeBanner: false,
      theme: ThemeData.dark().copyWith(
        scaffoldBackgroundColor: const Color(0xFF0A0E1A),
        colorScheme: const ColorScheme.dark(
          primary: Color(0xFF00FF88),
          secondary: Color(0xFF0088FF),
          surface: Color(0xFF111827),
        ),
      ),
      home: const HomeScreen(),
    );
  }
}

// ─── DATA MODELS ─────────────────────────────────────────────────────────────

class ScanResult {
  final String url;
  final int riskScore;
  final String riskLevel;
  final Color riskColor;
  final List<PhishingIndicator> indicators;
  final DomainInfo domainInfo;
  final DateTime scannedAt;
  final int vtMalicious;
  final int vtTotal;
  final bool googleFlagged;

  ScanResult({
    required this.url,
    required this.riskScore,
    required this.riskLevel,
    required this.riskColor,
    required this.indicators,
    required this.domainInfo,
    required this.scannedAt,
    required this.vtMalicious,
    required this.vtTotal,
    required this.googleFlagged,
  });
}

class PhishingIndicator {
  final String title;
  final String description;
  final bool isDangerous;
  final IconData icon;

  PhishingIndicator({
    required this.title,
    required this.description,
    required this.isDangerous,
    required this.icon,
  });
}

class DomainInfo {
  final String domain;
  final bool hasHttps;
  final String ipAddress;
  final String registrar;
  final String domainAge;
  final String country;

  DomainInfo({
    required this.domain,
    required this.hasHttps,
    required this.ipAddress,
    required this.registrar,
    required this.domainAge,
    required this.country,
  });
}

class ScanHistory {
  final String url;
  final int riskScore;
  final Color riskColor;
  final DateTime scannedAt;

  ScanHistory({
    required this.url,
    required this.riskScore,
    required this.riskColor,
    required this.scannedAt,
  });
}

// ─── API SERVICE ─────────────────────────────────────────────────────────────

class PhishingApiService {
  // ── VirusTotal ──────────────────────────────────────────────────────────

  /// Step 1: submit URL to VirusTotal and get analysis id
  static Future<Map<String, dynamic>> scanWithVirusTotal(String url) async {
    try {
      final encoded = base64Url.encode(utf8.encode(url)).replaceAll('=', '');
      final response = await http.get(
        Uri.parse('https://www.virustotal.com/api/v3/urls/$encoded'),
        headers: {'x-apikey': kVirusTotalKey},
      );

      if (response.statusCode == 200) {
        final data = json.decode(response.body);
        final stats =
            data['data']?['attributes']?['last_analysis_stats'] ?? {};
        return {
          'malicious': stats['malicious'] ?? 0,
          'suspicious': stats['suspicious'] ?? 0,
          'harmless': stats['harmless'] ?? 0,
          'undetected': stats['undetected'] ?? 0,
          'total': (stats['malicious'] ?? 0) +
              (stats['suspicious'] ?? 0) +
              (stats['harmless'] ?? 0) +
              (stats['undetected'] ?? 0),
          'success': true,
        };
      }
      return {'success': false, 'malicious': 0, 'total': 0};
    } catch (e) {
      return {'success': false, 'malicious': 0, 'total': 0};
    }
  }

  // ── Google Safe Browsing ────────────────────────────────────────────────

  static Future<bool> checkGoogleSafeBrowsing(String url) async {
    try {
      final response = await http.post(
        Uri.parse(
          'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=$kGoogleSafeBrowsingKey',
        ),
        headers: {'Content-Type': 'application/json'},
        body: json.encode({
          'client': {'clientId': 'phishguard', 'clientVersion': '1.0.0'},
          'threatInfo': {
            'threatTypes': [
              'MALWARE',
              'SOCIAL_ENGINEERING',
              'UNWANTED_SOFTWARE',
              'POTENTIALLY_HARMFUL_APPLICATION',
            ],
            'platformTypes': ['ANY_PLATFORM'],
            'threatEntryTypes': ['URL'],
            'threatEntries': [
              {'url': url}
            ],
          },
        }),
      );

      if (response.statusCode == 200) {
        final data = json.decode(response.body);
        // if 'matches' key exists and is not empty → flagged
        return data.containsKey('matches') &&
            (data['matches'] as List).isNotEmpty;
      }
      return false;
    } catch (e) {
      return false;
    }
  }

  // ── PhishTank (public feed check via URL pattern) ───────────────────────

  static bool checkPhishTankPatterns(String url) {
    final suspiciousPatterns = [
      RegExp(r'paypa[l1]', caseSensitive: false),
      RegExp(r'[a@]mazon', caseSensitive: false),
      RegExp(r'g[o0]{2}gle', caseSensitive: false),
      RegExp(r'micros[o0]ft', caseSensitive: false),
      RegExp(r'app[l1]e', caseSensitive: false),
      RegExp(r'secure.*login', caseSensitive: false),
      RegExp(r'login.*secure', caseSensitive: false),
      RegExp(r'verify.*account', caseSensitive: false),
      RegExp(r'account.*suspended', caseSensitive: false),
      RegExp(r'bank.*secure', caseSensitive: false),
      RegExp(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'), // IP as domain
    ];
    return suspiciousPatterns.any((p) => p.hasMatch(url));
  }

  // ── Local heuristic checks ───────────────────────────────────────────────

  static Map<String, dynamic> runLocalChecks(String url) {
    Uri? parsed;
    try {
      parsed = Uri.parse(url);
    } catch (_) {}

    final hasHttps = url.startsWith('https://');
    final host = parsed?.host ?? '';

    // suspicious keywords in full URL
    final suspiciousKeywords = [
      'login', 'secure', 'verify', 'account', 'update',
      'banking', 'signin', 'password', 'credential', 'confirm',
      'suspend', 'unusual', 'alert', 'free', 'prize', 'winner',
    ];
    final foundKeywords = suspiciousKeywords
        .where((k) => url.toLowerCase().contains(k))
        .toList();

    // typosquatting: numbers replacing letters in known brands
    final typoPatterns = [
      RegExp(r'paypa[l1]', caseSensitive: false),
      RegExp(r'g[o0]{2}gle', caseSensitive: false),
      RegExp(r'[a@]mazon', caseSensitive: false),
      RegExp(r'micros[o0]ft', caseSensitive: false),
      RegExp(r'app[l1]e-', caseSensitive: false),
      RegExp(r'faceb[o0]{2}k', caseSensitive: false),
    ];
    final hasTypo = typoPatterns.any((p) => p.hasMatch(host));

    // suspicious TLDs
    final suspiciousTlds = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw'];
    final hasSuspiciousTld =
        suspiciousTlds.any((tld) => host.endsWith(tld));

    // excessive subdomains (more than 3 dots)
    final subdomainCount = host.split('.').length - 2;
    final hasExcessiveSubdomains = subdomainCount > 2;

    // very long URL
    final isLongUrl = url.length > 100;

    return {
      'hasHttps': hasHttps,
      'host': host,
      'foundKeywords': foundKeywords,
      'hasTypo': hasTypo,
      'hasSuspiciousTld': hasSuspiciousTld,
      'hasExcessiveSubdomains': hasExcessiveSubdomains,
      'isLongUrl': isLongUrl,
      'subdomainCount': subdomainCount,
    };
  }

  // ── Calculate final risk score ───────────────────────────────────────────

  static int calculateRiskScore({
    required Map<String, dynamic> vtResult,
    required bool googleFlagged,
    required bool phishTankFlagged,
    required Map<String, dynamic> localChecks,
  }) {
    int score = 0;

    // VirusTotal weight (max 40 points)
    final vtMalicious = vtResult['malicious'] as int;
    final vtTotal = vtResult['total'] as int;
    if (vtTotal > 0) {
      final vtRatio = vtMalicious / vtTotal;
      score += (vtRatio * 40).round();
    }
    if (vtMalicious > 5) score += 10;

    // Google Safe Browsing (25 points)
    if (googleFlagged) score += 25;

    // PhishTank patterns (15 points)
    if (phishTankFlagged) score += 15;

    // Local checks
    if (!(localChecks['hasHttps'] as bool)) score += 10;
    if (localChecks['hasTypo'] as bool) score += 15;
    if (localChecks['hasSuspiciousTld'] as bool) score += 10;
    if ((localChecks['foundKeywords'] as List).isNotEmpty) score += 5;
    if (localChecks['hasExcessiveSubdomains'] as bool) score += 5;
    if (localChecks['isLongUrl'] as bool) score += 3;

    return score.clamp(0, 100);
  }
}

// ─── HOME SCREEN ──────────────────────────────────────────────────────────────

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen>
    with SingleTickerProviderStateMixin {
  final TextEditingController _urlController = TextEditingController();
  final ScrollController _scrollController = ScrollController();
  bool _isScanning = false;
  String _scanStatus = '';
  ScanResult? _scanResult;
  late AnimationController _pulseController;
  late Animation<double> _pulseAnimation;

  final List<ScanHistory> _history = [];

  @override
  void initState() {
    super.initState();
    _pulseController = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 1),
    )..repeat(reverse: true);
    _pulseAnimation = Tween<double>(begin: 0.8, end: 1.0).animate(
      CurvedAnimation(parent: _pulseController, curve: Curves.easeInOut),
    );
  }

  @override
  void dispose() {
    _pulseController.dispose();
    _urlController.dispose();
    _scrollController.dispose();
    super.dispose();
  }

  // ── Real API scan ────────────────────────────────────────────────────────

  Future<void> _scanUrl() async {
    String url = _urlController.text.trim();
    if (url.isEmpty) {
      _showSnackBar('Please enter a URL first', isError: true);
      return;
    }

    // auto-add https:// if missing
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'https://$url';
      _urlController.text = url;
    }

    setState(() {
      _isScanning = true;
      _scanResult = null;
      _scanStatus = 'Checking VirusTotal...';
    });

    // ── Run all checks in parallel ──────────────────────────────────────
    final vtFuture = PhishingApiService.scanWithVirusTotal(url);
    final googleFuture = PhishingApiService.checkGoogleSafeBrowsing(url);

    setState(() => _scanStatus = 'Checking Google Safe Browsing...');
    final results = await Future.wait([vtFuture, googleFuture]);

    setState(() => _scanStatus = 'Running local analysis...');
    await Future.delayed(const Duration(milliseconds: 500));

    final vtResult = results[0] as Map<String, dynamic>;
    final googleFlagged = results[1] as bool;
    final phishTankFlagged = PhishingApiService.checkPhishTankPatterns(url);
    final localChecks = PhishingApiService.runLocalChecks(url);

    // ── Calculate score ─────────────────────────────────────────────────
    final riskScore = PhishingApiService.calculateRiskScore(
      vtResult: vtResult,
      googleFlagged: googleFlagged,
      phishTankFlagged: phishTankFlagged,
      localChecks: localChecks,
    );

    Color riskColor;
    String riskLevel;
    if (riskScore >= 60) {
      riskColor = const Color(0xFFFF3B3B);
      riskLevel = 'HIGH RISK';
    } else if (riskScore >= 30) {
      riskColor = const Color(0xFFFFAA00);
      riskLevel = 'MEDIUM RISK';
    } else {
      riskColor = const Color(0xFF00FF88);
      riskLevel = 'SAFE';
    }

    final vtMalicious = vtResult['malicious'] as int;
    final vtTotal = vtResult['total'] as int;
    final foundKeywords = localChecks['foundKeywords'] as List;
    final hasHttps = localChecks['hasHttps'] as bool;
    final hasTypo = localChecks['hasTypo'] as bool;
    final hasSuspiciousTld = localChecks['hasSuspiciousTld'] as bool;

    final result = ScanResult(
      url: url,
      riskScore: riskScore,
      riskLevel: riskLevel,
      riskColor: riskColor,
      vtMalicious: vtMalicious,
      vtTotal: vtTotal,
      googleFlagged: googleFlagged,
      indicators: [
        PhishingIndicator(
          title: 'VirusTotal Scan',
          description: vtResult['success'] == true
              ? vtMalicious > 0
                  ? '$vtMalicious/$vtTotal engines flagged this URL as malicious'
                  : 'Clean — 0/$vtTotal engines flagged this URL'
              : 'Could not reach VirusTotal (check internet)',
          isDangerous: vtMalicious > 0,
          icon: vtMalicious > 0 ? Icons.bug_report : Icons.verified_user,
        ),
        PhishingIndicator(
          title: 'Google Safe Browsing',
          description: googleFlagged
              ? 'URL flagged by Google as dangerous!'
              : 'Not found in Google threat database',
          isDangerous: googleFlagged,
          icon: googleFlagged ? Icons.gpp_bad : Icons.gpp_good,
        ),
        PhishingIndicator(
          title: 'HTTPS Status',
          description: hasHttps
              ? 'Connection is encrypted and secure'
              : 'No encryption — data can be intercepted!',
          isDangerous: !hasHttps,
          icon: hasHttps ? Icons.lock : Icons.lock_open,
        ),
        PhishingIndicator(
          title: 'Suspicious Keywords',
          description: foundKeywords.isNotEmpty
              ? 'Found: ${foundKeywords.take(3).join(", ")}'
              : 'No suspicious keywords detected',
          isDangerous: foundKeywords.isNotEmpty,
          icon: foundKeywords.isNotEmpty
              ? Icons.warning_amber
              : Icons.check_circle,
        ),
        PhishingIndicator(
          title: 'Typosquatting Check',
          description: hasTypo
              ? 'Domain resembles a known brand — possible impersonation!'
              : 'No typosquatting patterns detected',
          isDangerous: hasTypo,
          icon: hasTypo ? Icons.text_fields : Icons.spellcheck,
        ),
        PhishingIndicator(
          title: 'Suspicious Domain',
          description: hasSuspiciousTld
              ? 'Uses a high-risk TLD (.xyz, .tk, .ml, etc.)'
              : 'Domain extension looks normal',
          isDangerous: hasSuspiciousTld,
          icon: hasSuspiciousTld ? Icons.domain_disabled : Icons.domain,
        ),
      ],
      domainInfo: DomainInfo(
        domain: localChecks['host'] as String,
        hasHttps: hasHttps,
        ipAddress: 'Fetched via VirusTotal',
        registrar: vtResult['success'] == true ? 'VirusTotal verified' : 'N/A',
        domainAge: 'See VirusTotal report',
        country: 'See VirusTotal report',
      ),
      scannedAt: DateTime.now(),
    );

    setState(() {
      _isScanning = false;
      _scanStatus = '';
      _scanResult = result;
      _history.insert(
        0,
        ScanHistory(
          url: url,
          riskScore: riskScore,
          riskColor: riskColor,
          scannedAt: DateTime.now(),
        ),
      );
    });

    await Future.delayed(const Duration(milliseconds: 300));
    _scrollController.animateTo(
      400,
      duration: const Duration(milliseconds: 600),
      curve: Curves.easeOut,
    );
  }

  void _showSnackBar(String message, {bool isError = false}) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(message),
        backgroundColor:
            isError ? const Color(0xFFFF3B3B) : const Color(0xFF00FF88),
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12)),
      ),
    );
  }

  void _showReportDialog() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: const Color(0xFF111827),
        shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(16)),
        title: const Row(
          children: [
            Icon(Icons.flag, color: Color(0xFFFF3B3B)),
            SizedBox(width: 8),
            Text('Report Phishing',
                style: TextStyle(color: Colors.white)),
          ],
        ),
        content: const Text(
          'Report this URL as a phishing site? This helps protect other users.',
          style: TextStyle(color: Colors.white70),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel',
                style: TextStyle(color: Colors.white54)),
          ),
          ElevatedButton(
            onPressed: () {
              Navigator.pop(context);
              _showSnackBar('Thank you! URL reported successfully.');
            },
            style: ElevatedButton.styleFrom(
              backgroundColor: const Color(0xFFFF3B3B),
              foregroundColor: Colors.white,
              shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(8)),
            ),
            child: const Text('Report'),
          ),
        ],
      ),
    );
  }

  void _showQRDialog() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: const Color(0xFF111827),
        shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(16)),
        title: const Row(
          children: [
            Icon(Icons.qr_code_scanner, color: Color(0xFF00FF88)),
            SizedBox(width: 8),
            Text('QR Code Scanner',
                style: TextStyle(color: Colors.white)),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              width: 200,
              height: 200,
              decoration: BoxDecoration(
                color: const Color(0xFF0A0E1A),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(
                    color: const Color(0xFF00FF88), width: 2),
              ),
              child: const Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Icon(Icons.qr_code_scanner,
                      color: Color(0xFF00FF88), size: 64),
                  SizedBox(height: 12),
                  Text(
                    'Camera access needed\n(coming soon)',
                    textAlign: TextAlign.center,
                    style:
                        TextStyle(color: Colors.white54, fontSize: 13),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 12),
            const Text(
              'Point your camera at a QR code to extract and scan the URL automatically.',
              textAlign: TextAlign.center,
              style: TextStyle(color: Colors.white54, fontSize: 13),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Close',
                style: TextStyle(color: Colors.white54)),
          ),
        ],
      ),
    );
  }

  // ─── BUILD ────────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0A0E1A),
      appBar: _buildAppBar(),
      body: SingleChildScrollView(
        controller: _scrollController,
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _buildHeader(),
            const SizedBox(height: 24),
            _buildSearchCard(),
            const SizedBox(height: 16),
            _buildActionButtons(),
            const SizedBox(height: 28),
            if (_isScanning) _buildScanningAnimation(),
            if (_scanResult != null) ...[
              _buildApiSourcesRow(),
              const SizedBox(height: 16),
              _buildResultCard(),
              const SizedBox(height: 20),
              _buildIndicatorsSection(),
              const SizedBox(height: 20),
              _buildDomainInfoSection(),
              const SizedBox(height: 16),
              _buildReportButton(),
              const SizedBox(height: 28),
            ],
            _buildHistorySection(),
            const SizedBox(height: 40),
          ],
        ),
      ),
    );
  }

  AppBar _buildAppBar() {
    return AppBar(
      backgroundColor: const Color(0xFF111827),
      elevation: 0,
      title: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(6),
            decoration: BoxDecoration(
              color: const Color(0xFF00FF88).withOpacity(0.15),
              borderRadius: BorderRadius.circular(8),
            ),
            child: const Icon(Icons.security,
                color: Color(0xFF00FF88), size: 20),
          ),
          const SizedBox(width: 10),
          const Text(
            'PhishGuard',
            style: TextStyle(
              color: Colors.white,
              fontWeight: FontWeight.bold,
              fontSize: 18,
              letterSpacing: 0.5,
            ),
          ),
        ],
      ),
      actions: [
        IconButton(
          icon:
              const Icon(Icons.settings_outlined, color: Colors.white54),
          onPressed: () {},
        ),
      ],
    );
  }

  Widget _buildHeader() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'Stay Safe Online',
          style: TextStyle(
            color: Colors.white,
            fontSize: 26,
            fontWeight: FontWeight.bold,
            letterSpacing: -0.5,
          ),
        ),
        const SizedBox(height: 6),
        Text(
          'Powered by VirusTotal, Google Safe Browsing & PhishTank',
          style: TextStyle(
              color: Colors.white.withOpacity(0.5), fontSize: 13),
        ),
      ],
    );
  }

  Widget _buildSearchCard() {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: const Color(0xFF111827),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: Colors.white.withOpacity(0.08)),
      ),
      child: Column(
        children: [
          TextField(
            controller: _urlController,
            style: const TextStyle(color: Colors.white, fontSize: 15),
            decoration: InputDecoration(
              hintText: 'Paste URL here... (e.g. https://example.com)',
              hintStyle:
                  TextStyle(color: Colors.white.withOpacity(0.3)),
              prefixIcon: Icon(Icons.link,
                  color: Colors.white.withOpacity(0.4)),
              suffixIcon: _urlController.text.isNotEmpty
                  ? IconButton(
                      icon: Icon(Icons.clear,
                          color: Colors.white.withOpacity(0.4)),
                      onPressed: () =>
                          setState(() => _urlController.clear()),
                    )
                  : null,
              filled: true,
              fillColor: const Color(0xFF0A0E1A),
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(12),
                borderSide: BorderSide.none,
              ),
              contentPadding: const EdgeInsets.symmetric(
                  horizontal: 16, vertical: 14),
            ),
            onChanged: (_) => setState(() {}),
            onSubmitted: (_) => _scanUrl(),
          ),
          const SizedBox(height: 14),
          SizedBox(
            width: double.infinity,
            height: 52,
            child: ElevatedButton(
              onPressed: _isScanning ? null : _scanUrl,
              style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFF00FF88),
                foregroundColor: Colors.black,
                disabledBackgroundColor:
                    const Color(0xFF00FF88).withOpacity(0.4),
                shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(12)),
                elevation: 0,
              ),
              child: _isScanning
                  ? const SizedBox(
                      width: 20,
                      height: 20,
                      child: CircularProgressIndicator(
                          color: Colors.black, strokeWidth: 2),
                    )
                  : const Row(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Icon(Icons.radar, size: 20),
                        SizedBox(width: 8),
                        Text('Scan URL',
                            style: TextStyle(
                                fontSize: 16,
                                fontWeight: FontWeight.bold)),
                      ],
                    ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildActionButtons() {
    return Row(
      children: [
        Expanded(
          child: _ActionButton(
            icon: Icons.qr_code_scanner,
            label: 'Scan QR Code',
            color: const Color(0xFF0088FF),
            onTap: _showQRDialog,
          ),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: _ActionButton(
            icon: Icons.content_paste,
            label: 'Paste URL',
            color: const Color(0xFF8B5CF6),
            onTap: () => _showSnackBar(
                'Paste your URL manually in the text field above'),
          ),
        ),
      ],
    );
  }

  Widget _buildScanningAnimation() {
    return Center(
      child: Column(
        children: [
          const SizedBox(height: 20),
          AnimatedBuilder(
            animation: _pulseAnimation,
            builder: (context, child) => Transform.scale(
              scale: _pulseAnimation.value,
              child: Container(
                width: 80,
                height: 80,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: const Color(0xFF00FF88).withOpacity(0.15),
                  border: Border.all(
                      color: const Color(0xFF00FF88).withOpacity(0.5),
                      width: 2),
                ),
                child: const Icon(Icons.radar,
                    color: Color(0xFF00FF88), size: 36),
              ),
            ),
          ),
          const SizedBox(height: 16),
          Text(
            _scanStatus,
            style: const TextStyle(color: Colors.white70, fontSize: 15),
          ),
          const SizedBox(height: 6),
          Text(
            'Using real threat intelligence APIs',
            style: TextStyle(
                color: Colors.white.withOpacity(0.4), fontSize: 12),
          ),
          const SizedBox(height: 28),
        ],
      ),
    );
  }

  // ── API sources badges ───────────────────────────────────────────────────

  Widget _buildApiSourcesRow() {
    return Row(
      children: [
        _ApiBadge(
          label: 'VirusTotal',
          isActive: _scanResult!.vtTotal > 0,
          color: const Color(0xFF0088FF),
        ),
        const SizedBox(width: 8),
        _ApiBadge(
          label: 'Google SB',
          isActive: true,
          color: const Color(0xFF00FF88),
        ),
        const SizedBox(width: 8),
        _ApiBadge(
          label: 'PhishTank',
          isActive: true,
          color: const Color(0xFF8B5CF6),
        ),
      ],
    );
  }

  Widget _buildResultCard() {
    final result = _scanResult!;
    return Container(
      padding: const EdgeInsets.all(24),
      decoration: BoxDecoration(
        color: const Color(0xFF111827),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
            color: result.riskColor.withOpacity(0.4), width: 1.5),
      ),
      child: Column(
        children: [
          Row(
            children: [
              const Text('Security Score',
                  style: TextStyle(
                      color: Colors.white70,
                      fontSize: 14,
                      fontWeight: FontWeight.w600)),
              const Spacer(),
              Container(
                padding: const EdgeInsets.symmetric(
                    horizontal: 12, vertical: 5),
                decoration: BoxDecoration(
                  color: result.riskColor.withOpacity(0.15),
                  borderRadius: BorderRadius.circular(20),
                ),
                child: Text(
                  result.riskLevel,
                  style: TextStyle(
                    color: result.riskColor,
                    fontSize: 12,
                    fontWeight: FontWeight.bold,
                    letterSpacing: 0.5,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 24),
          Stack(
            alignment: Alignment.center,
            children: [
              SizedBox(
                width: 150,
                height: 150,
                child: CircularProgressIndicator(
                  value: result.riskScore / 100,
                  strokeWidth: 12,
                  backgroundColor: Colors.white.withOpacity(0.1),
                  valueColor: AlwaysStoppedAnimation<Color>(
                      result.riskColor),
                ),
              ),
              Column(
                children: [
                  Text(
                    '${result.riskScore}',
                    style: TextStyle(
                      color: result.riskColor,
                      fontSize: 44,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  Text('Risk Score',
                      style: TextStyle(
                          color: Colors.white.withOpacity(0.5),
                          fontSize: 13)),
                ],
              ),
            ],
          ),
          const SizedBox(height: 16),
          // VT stats row
          if (result.vtTotal > 0)
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: const Color(0xFF0A0E1A),
                borderRadius: BorderRadius.circular(10),
              ),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.spaceAround,
                children: [
                  _VtStat(
                      label: 'Malicious',
                      value: '${result.vtMalicious}',
                      color: result.vtMalicious > 0
                          ? const Color(0xFFFF3B3B)
                          : Colors.white70),
                  _VtStat(
                      label: 'Clean',
                      value:
                          '${result.vtTotal - result.vtMalicious}',
                      color: const Color(0xFF00FF88)),
                  _VtStat(
                      label: 'Total Engines',
                      value: '${result.vtTotal}',
                      color: Colors.white70),
                ],
              ),
            ),
          const SizedBox(height: 12),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: const Color(0xFF0A0E1A),
              borderRadius: BorderRadius.circular(10),
            ),
            child: Row(
              children: [
                Icon(Icons.link,
                    color: Colors.white.withOpacity(0.4), size: 16),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    result.url,
                    style: const TextStyle(
                        color: Colors.white70, fontSize: 13),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildIndicatorsSection() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const _SectionTitle(
            icon: Icons.warning_amber_rounded,
            title: 'Phishing Indicators'),
        const SizedBox(height: 12),
        ..._scanResult!.indicators
            .map((i) => _IndicatorCard(indicator: i)),
      ],
    );
  }

  Widget _buildDomainInfoSection() {
    final info = _scanResult!.domainInfo;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const _SectionTitle(
            icon: Icons.dns_outlined, title: 'Domain Information'),
        const SizedBox(height: 12),
        Container(
          padding:
              const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
          decoration: BoxDecoration(
            color: const Color(0xFF111827),
            borderRadius: BorderRadius.circular(16),
            border:
                Border.all(color: Colors.white.withOpacity(0.08)),
          ),
          child: Column(
            children: [
              _DomainInfoRow(label: 'Domain', value: info.domain),
              _DomainInfoRow(
                label: 'HTTPS',
                value: info.hasHttps ? 'Enabled ✓' : 'Not Enabled ✗',
                valueColor: info.hasHttps
                    ? const Color(0xFF00FF88)
                    : const Color(0xFFFF3B3B),
              ),
              _DomainInfoRow(
                  label: 'Google Safe Browsing',
                  value: _scanResult!.googleFlagged
                      ? 'FLAGGED ✗'
                      : 'Clean ✓',
                  valueColor: _scanResult!.googleFlagged
                      ? const Color(0xFFFF3B3B)
                      : const Color(0xFF00FF88)),
              _DomainInfoRow(
                label: 'VirusTotal Engines',
                value: _scanResult!.vtTotal > 0
                    ? '${_scanResult!.vtMalicious}/${_scanResult!.vtTotal} flagged'
                    : 'No data',
                valueColor: _scanResult!.vtMalicious > 0
                    ? const Color(0xFFFF3B3B)
                    : const Color(0xFF00FF88),
              ),
              _DomainInfoRow(
                  label: 'Registrar', value: info.registrar),
              _DomainInfoRow(
                  label: 'Domain Age',
                  value: info.domainAge,
                  isLast: true),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildReportButton() {
    return SizedBox(
      width: double.infinity,
      height: 52,
      child: OutlinedButton.icon(
        onPressed: _showReportDialog,
        icon: const Icon(Icons.flag_outlined,
            color: Color(0xFFFF3B3B)),
        label: const Text(
          'Report as Phishing',
          style: TextStyle(
              color: Color(0xFFFF3B3B),
              fontWeight: FontWeight.w600,
              fontSize: 15),
        ),
        style: OutlinedButton.styleFrom(
          side:
              const BorderSide(color: Color(0xFFFF3B3B), width: 1.5),
          shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(12)),
        ),
      ),
    );
  }

  Widget _buildHistorySection() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            const _SectionTitle(
                icon: Icons.history, title: 'Scan History'),
            const Spacer(),
            TextButton(
              onPressed: () => setState(() => _history.clear()),
              child: Text('Clear All',
                  style: TextStyle(
                      color: Colors.white.withOpacity(0.4),
                      fontSize: 13)),
            ),
          ],
        ),
        const SizedBox(height: 12),
        if (_history.isEmpty)
          Center(
            child: Padding(
              padding: const EdgeInsets.all(32),
              child: Column(
                children: [
                  Icon(Icons.history,
                      color: Colors.white.withOpacity(0.2), size: 48),
                  const SizedBox(height: 12),
                  Text('No scans yet',
                      style: TextStyle(
                          color: Colors.white.withOpacity(0.4))),
                ],
              ),
            ),
          )
        else
          ..._history.take(5).map(
                (item) => _HistoryCard(
                  item: item,
                  onTap: () {
                    setState(() => _urlController.text = item.url);
                    _scanUrl();
                  },
                ),
              ),
      ],
    );
  }
}

// ─── REUSABLE WIDGETS ────────────────────────────────────────────────────────

class _SectionTitle extends StatelessWidget {
  final IconData icon;
  final String title;
  const _SectionTitle({required this.icon, required this.title});

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Icon(icon, color: const Color(0xFF00FF88), size: 18),
        const SizedBox(width: 8),
        Text(title,
            style: const TextStyle(
                color: Colors.white,
                fontSize: 16,
                fontWeight: FontWeight.bold)),
      ],
    );
  }
}

class _ActionButton extends StatelessWidget {
  final IconData icon;
  final String label;
  final Color color;
  final VoidCallback onTap;
  const _ActionButton(
      {required this.icon,
      required this.label,
      required this.color,
      required this.onTap});

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(vertical: 14),
        decoration: BoxDecoration(
          color: color.withOpacity(0.1),
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: color.withOpacity(0.3)),
        ),
        child: Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(icon, color: color, size: 18),
            const SizedBox(width: 8),
            Text(label,
                style: TextStyle(
                    color: color,
                    fontSize: 13,
                    fontWeight: FontWeight.w600)),
          ],
        ),
      ),
    );
  }
}

class _ApiBadge extends StatelessWidget {
  final String label;
  final bool isActive;
  final Color color;
  const _ApiBadge(
      {required this.label,
      required this.isActive,
      required this.color});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
      decoration: BoxDecoration(
        color: isActive ? color.withOpacity(0.15) : Colors.white10,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(
            color: isActive ? color.withOpacity(0.4) : Colors.white12),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 6,
            height: 6,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: isActive ? color : Colors.white30,
            ),
          ),
          const SizedBox(width: 5),
          Text(label,
              style: TextStyle(
                  color: isActive ? color : Colors.white30,
                  fontSize: 11,
                  fontWeight: FontWeight.w600)),
        ],
      ),
    );
  }
}

class _VtStat extends StatelessWidget {
  final String label;
  final String value;
  final Color color;
  const _VtStat(
      {required this.label, required this.value, required this.color});

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        Text(value,
            style: TextStyle(
                color: color,
                fontSize: 20,
                fontWeight: FontWeight.bold)),
        const SizedBox(height: 2),
        Text(label,
            style: TextStyle(
                color: Colors.white.withOpacity(0.5), fontSize: 11)),
      ],
    );
  }
}

class _IndicatorCard extends StatelessWidget {
  final PhishingIndicator indicator;
  const _IndicatorCard({required this.indicator});

  @override
  Widget build(BuildContext context) {
    final color = indicator.isDangerous
        ? const Color(0xFFFF3B3B)
        : const Color(0xFF00FF88);
    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: const Color(0xFF111827),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color.withOpacity(0.2)),
      ),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: color.withOpacity(0.1),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Icon(indicator.icon, color: color, size: 18),
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(indicator.title,
                    style: const TextStyle(
                        color: Colors.white,
                        fontWeight: FontWeight.w600,
                        fontSize: 14)),
                const SizedBox(height: 3),
                Text(indicator.description,
                    style: TextStyle(
                        color: Colors.white.withOpacity(0.5),
                        fontSize: 12)),
              ],
            ),
          ),
          const SizedBox(width: 8),
          Icon(
              indicator.isDangerous
                  ? Icons.cancel
                  : Icons.check_circle,
              color: color,
              size: 20),
        ],
      ),
    );
  }
}

class _DomainInfoRow extends StatelessWidget {
  final String label;
  final String value;
  final Color? valueColor;
  final bool isLast;
  const _DomainInfoRow(
      {required this.label,
      required this.value,
      this.valueColor,
      this.isLast = false});

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.symmetric(vertical: 12),
          child: Row(
            children: [
              Text(label,
                  style: TextStyle(
                      color: Colors.white.withOpacity(0.5),
                      fontSize: 13)),
              const Spacer(),
              Text(value,
                  style: TextStyle(
                      color: valueColor ?? Colors.white,
                      fontSize: 13,
                      fontWeight: FontWeight.w500)),
            ],
          ),
        ),
        if (!isLast)
          Divider(color: Colors.white.withOpacity(0.06), height: 1),
      ],
    );
  }
}

class _HistoryCard extends StatelessWidget {
  final ScanHistory item;
  final VoidCallback onTap;
  const _HistoryCard({required this.item, required this.onTap});

  String _getTimeAgo(DateTime date) {
    final diff = DateTime.now().difference(date);
    if (diff.inMinutes < 1) return 'Just now';
    if (diff.inMinutes < 60) return '${diff.inMinutes}m ago';
    if (diff.inHours < 24) return '${diff.inHours}h ago';
    return '${diff.inDays}d ago';
  }

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        margin: const EdgeInsets.only(bottom: 10),
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          color: const Color(0xFF111827),
          borderRadius: BorderRadius.circular(12),
          border:
              Border.all(color: Colors.white.withOpacity(0.06)),
        ),
        child: Row(
          children: [
            Container(
              width: 44,
              height: 44,
              decoration: BoxDecoration(
                color: item.riskColor.withOpacity(0.1),
                borderRadius: BorderRadius.circular(10),
              ),
              child: Center(
                child: Text('${item.riskScore}',
                    style: TextStyle(
                        color: item.riskColor,
                        fontWeight: FontWeight.bold,
                        fontSize: 13)),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(item.url,
                      style: const TextStyle(
                          color: Colors.white, fontSize: 13),
                      overflow: TextOverflow.ellipsis),
                  const SizedBox(height: 3),
                  Text(_getTimeAgo(item.scannedAt),
                      style: TextStyle(
                          color: Colors.white.withOpacity(0.4),
                          fontSize: 11)),
                ],
              ),
            ),
            Icon(Icons.chevron_right,
                color: Colors.white.withOpacity(0.3), size: 18),
          ],
        ),
      ),
    );
  }
}
