export type SafetyStatus = 'safe' | 'phishing';

export interface DetectionResult {
  status: SafetyStatus;
  confidence: number;
  reasons: string[];
  checkedAt: string;
}

export interface URLCheck {
  url: string;
  result: DetectionResult;
}

// Suspicious keywords commonly used in phishing
const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'verify', 'verification', 'account',
  'bank', 'password', 'credential', 'secure', 'update',
  'confirm', 'validate', 'authenticate', 'billing', 'payment',
  'paypal', 'appleid', 'microsoft', 'amazon', 'netflix',
  'urgent', 'suspended', 'locked', 'limited', 'restricted',
  'click', 'here', 'verify-now', 'update-now', 'secure-login'
];

// Known safe domains for comparison
const TRUSTED_DOMAINS = [
  'google.com', 'youtube.com', 'facebook.com', 'twitter.com',
  'github.com', 'microsoft.com', 'apple.com', 'amazon.com',
  'linkedin.com', 'reddit.com', 'wikipedia.org', 'netflix.com'
];

// URL shortening services
const SHORTENING_SERVICES = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
  'short.link', 'is.gd', 'buff.ly', 'adf.ly', 'shorturl.at'
];

/**
 * Rule-based phishing detection engine
 */
export class PhishingDetector {
  /**
   * Main detection method - analyzes URL and returns safety status
   */
  static checkURL(url: string): DetectionResult {
    const reasons: string[] = [];
    let riskScore = 0;

    try {
      // Normalize URL
      const normalizedUrl = this.normalizeURL(url);
      const urlObj = new URL(normalizedUrl);
      const hostname = urlObj.hostname.toLowerCase();
      const fullUrl = normalizedUrl.toLowerCase();

      // Check 1: IP address in URL
      if (this.hasIPAddress(hostname)) {
        riskScore += 30;
        reasons.push('URL contains IP address instead of domain name');
      }

      // Check 2: Excessive subdomains
      const subdomainCount = this.countSubdomains(hostname);
      if (subdomainCount > 3) {
        riskScore += 20;
        reasons.push(`Excessive subdomains detected (${subdomainCount})`);
      }

      // Check 3: URL length
      if (fullUrl.length > 100) {
        riskScore += 10;
        reasons.push('Unusually long URL');
      }

      // Check 4: Suspicious keywords
      const keywordMatches = this.findSuspiciousKeywords(fullUrl);
      if (keywordMatches.length > 0) {
        riskScore += keywordMatches.length * 15;
        reasons.push(`Suspicious keywords found: ${keywordMatches.slice(0, 3).join(', ')}`);
      }

      // Check 5: URL shortening service
      if (this.isShorteningService(hostname)) {
        riskScore += 15;
        reasons.push('URL shortening service detected');
      }

      // Check 6: Multiple special characters
      const specialCharCount = (fullUrl.match(/[-_]/g) || []).length;
      if (specialCharCount > 5) {
        riskScore += 10;
        reasons.push('Excessive special characters in URL');
      }

      // Check 7: HTTPS usage (slight positive indicator)
      if (urlObj.protocol === 'https:') {
        riskScore -= 5;
      } else {
        riskScore += 10;
        reasons.push('Connection not secure (no HTTPS)');
      }

      // Check 8: Brand impersonation
      const impersonationScore = this.checkBrandImpersonation(hostname, fullUrl);
      if (impersonationScore > 0) {
        riskScore += impersonationScore;
        reasons.push('Potential brand impersonation detected');
      }

      // Determine status based on risk score
      const { status, confidence } = this.calculateStatus(riskScore);

      return {
        status,
        confidence,
        reasons: reasons.length > 0 ? reasons : ['No suspicious patterns detected'],
        checkedAt: new Date().toISOString()
      };

    } catch (error) {
      return {
        status: 'phishing',
        confidence: 50,
        reasons: ['Invalid or malformed URL'],
        checkedAt: new Date().toISOString()
      };
    }
  }

  /**
   * Normalize URL - add protocol if missing
   */
  private static normalizeURL(url: string): string {
    url = url.trim();
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'https://' + url;
    }
    return url;
  }

  /**
   * Check if hostname contains IP address
   */
  private static hasIPAddress(hostname: string): boolean {
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    return ipPattern.test(hostname);
  }

  /**
   * Count number of subdomains
   */
  private static countSubdomains(hostname: string): number {
    const parts = hostname.split('.');
    // Remove TLD and main domain
    return Math.max(0, parts.length - 2);
  }

  /**
   * Find suspicious keywords in URL
   */
  private static findSuspiciousKeywords(url: string): string[] {
    const matches: string[] = [];
    for (const keyword of SUSPICIOUS_KEYWORDS) {
      if (url.includes(keyword)) {
        matches.push(keyword);
      }
    }
    return matches;
  }

  /**
   * Check if using URL shortening service
   */
  private static isShorteningService(hostname: string): boolean {
    return SHORTENING_SERVICES.some(service => hostname.includes(service));
  }

  /**
   * Check for potential brand impersonation
   */
  private static checkBrandImpersonation(hostname: string, _fullUrl: string): number {
    let score = 0;

    for (const trusted of TRUSTED_DOMAINS) {
      const brandName = trusted.split('.')[0];

      // Check if brand name appears in subdomain of different domain
      if (hostname.includes(brandName) && !hostname.endsWith(trusted)) {
        score += 25;
      }

      // Check for common typosquatting patterns
      const typoPatterns = [
        brandName + '-',
        brandName + '0',
        '0' + brandName,
        brandName.replace('o', '0'),
        brandName.replace('l', '1'),
        brandName.replace('i', '1')
      ];

      for (const pattern of typoPatterns) {
        if (hostname.includes(pattern) && !hostname.endsWith(trusted)) {
          score += 20;
        }
      }
    }

    return score;
  }

  /**
   * Calculate final status and confidence based on risk score
   */
  private static calculateStatus(riskScore: number): { status: SafetyStatus; confidence: number } {
    // Clamp risk score
    riskScore = Math.max(0, Math.min(100, riskScore));

    if (riskScore >= 25) {
      // Anything previously considered "suspicious" (score >= 25) is now flagged as phishing
      return { status: 'phishing', confidence: Math.min(95, riskScore + 20) };
    } else {
      return { status: 'safe', confidence: 100 - riskScore };
    }
  }

  /**
   * Validate URL format
   */
  static isValidURL(url: string): boolean {
    try {
      const normalized = this.normalizeURL(url);
      new URL(normalized);
      return true;
    } catch {
      return false;
    }
  }
}

export default PhishingDetector;
