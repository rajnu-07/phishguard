import { useState, useEffect } from 'react';
import {
  Shield,
  ShieldCheck,
  Search,
  History,
  Trash2,
  CheckCircle,
  XCircle,
  Info,
  ExternalLink,
  BarChart3
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';

import { ScrollArea } from '@/components/ui/scroll-area';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog';
import { PhishingDetector, type DetectionResult, type SafetyStatus, type URLCheck } from './services/phishingDetector';
import { HistoryService } from './services/historyService';
import './App.css';

function App() {
  const [url, setUrl] = useState('');
  const [isChecking, setIsChecking] = useState(false);
  const [result, setResult] = useState<DetectionResult | null>(null);
  const [error, setError] = useState('');
  const [history, setHistory] = useState<URLCheck[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  const [stats, setStats] = useState({ total: 0, safe: 0, phishing: 0 });

  // Load history on mount
  useEffect(() => {
    loadHistory();
  }, []);

  const loadHistory = async () => {
    const historyData = await HistoryService.getHistory();
    setHistory(historyData);
    setStats(HistoryService.getStats(historyData));
  };

  const handleCheck = async () => {
    setError('');
    setResult(null);

    // Validate URL
    if (!url.trim()) {
      setError('Please enter a URL');
      return;
    }

    if (!PhishingDetector.isValidURL(url)) {
      setError('Please enter a valid URL');
      return;
    }

    setIsChecking(true);

    const normalizedUrl = url.trim().startsWith('http') ? url.trim() : `https://${url.trim()}`;
    let isReachable = true;

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 8000);

      await fetch(normalizedUrl, {
        mode: 'no-cors',
        signal: controller.signal,
        cache: 'no-store'
      });

      clearTimeout(timeoutId);
    } catch (err) {
      console.error("Reachability check failed:", err);
      isReachable = false;
    }

    const baseResult = PhishingDetector.checkURL(url);
    const detectionResult = { ...baseResult };

    if (!isReachable) {
      detectionResult.status = 'phishing';
      detectionResult.confidence = Math.max(detectionResult.confidence, 95);
      const filteredReasons = detectionResult.reasons.filter(r => r !== 'No suspicious patterns detected');
      detectionResult.reasons = [
        'Website is not reachable or domain does not exist',
        ...filteredReasons
      ];
    } else {
      // Simulate slight API delay for better UX if it was fast
      await new Promise(resolve => setTimeout(resolve, 500));
    }

    setResult(detectionResult);

    // Save to history
    const urlCheck: URLCheck = {
      url: url.trim(),
      result: detectionResult
    };
    await HistoryService.addToHistory(urlCheck);
    await loadHistory();

    setIsChecking(false);
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleCheck();
    }
  };

  const clearHistory = async () => {
    await HistoryService.clearHistory();
    await loadHistory();
  };

  const removeFromHistory = async (urlToRemove: string) => {
    await HistoryService.removeFromHistory(urlToRemove);
    await loadHistory();
  };

  const getStatusIcon = (status: SafetyStatus) => {
    switch (status) {
      case 'safe':
        return <ShieldCheck className="w-16 h-16 text-green-500" />;
      case 'phishing':
        return <Shield className="w-16 h-16 text-red-500" />;
    }
  };

  const getStatusBadge = (status: SafetyStatus) => {
    switch (status) {
      case 'safe':
        return (
          <Badge className="bg-green-100 text-green-800 hover:bg-green-100 text-sm px-3 py-1">
            <CheckCircle className="w-4 h-4 mr-1" />
            Safe
          </Badge>
        );
      case 'phishing':
        return (
          <Badge className="bg-red-100 text-red-800 hover:bg-red-100 text-sm px-3 py-1">
            <XCircle className="w-4 h-4 mr-1" />
            Phishing
          </Badge>
        );
    }
  };

  const getStatusColor = (status: SafetyStatus) => {
    switch (status) {
      case 'safe':
        return 'border-green-200 bg-green-50';
      case 'phishing':
        return 'border-red-200 bg-red-50';
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100">
      {/* Header */}
      <header className="bg-white border-b border-slate-200 sticky top-0 z-10">
        <div className="max-w-4xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="bg-blue-600 p-2 rounded-lg">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-slate-900">PhishGuard</h1>
              <p className="text-xs text-slate-500">URL Safety Checker</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setShowHistory(true)}
              className="gap-2"
            >
              <History className="w-4 h-4" />
              History
              {history.length > 0 && (
                <Badge variant="secondary" className="ml-1 text-xs">
                  {history.length}
                </Badge>
              )}
            </Button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-4xl mx-auto px-4 py-8">
        {/* Hero Section */}
        <div className="text-center mb-8">
          <h2 className="text-3xl font-bold text-slate-900 mb-3">
            Check URL Safety Instantly
          </h2>
          <p className="text-slate-600 max-w-lg mx-auto">
            Enter a URL below to analyze it for phishing indicators, suspicious patterns, and potential security threats.
          </p>
        </div>

        {/* URL Input Section */}
        <Card className="mb-6 shadow-lg border-slate-200">
          <CardContent className="pt-6">
            <div className="flex gap-3">
              <div className="flex-1 relative">
                <Input
                  placeholder="Enter URL (e.g., example.com or https://example.com)"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  onKeyPress={handleKeyPress}
                  className="h-12 pl-4 pr-4 text-base"
                  disabled={isChecking}
                />
              </div>
              <Button
                onClick={handleCheck}
                disabled={isChecking}
                className="h-12 px-6 bg-blue-600 hover:bg-blue-700"
              >
                {isChecking ? (
                  <div className="flex items-center gap-2">
                    <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                    Checking...
                  </div>
                ) : (
                  <div className="flex items-center gap-2">
                    <Search className="w-4 h-4" />
                    Check URL
                  </div>
                )}
              </Button>
            </div>

            {error && (
              <Alert variant="destructive" className="mt-4">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
          </CardContent>
        </Card>

        {/* Result Section */}
        {result && (
          <Card className={`mb-6 shadow-lg border-2 ${getStatusColor(result.status)}`}>
            <CardContent className="pt-6">
              <div className="flex flex-col md:flex-row items-center gap-6">
                <div className="flex-shrink-0">
                  {getStatusIcon(result.status)}
                </div>
                <div className="flex-1 text-center md:text-left">
                  <div className="flex items-center justify-center md:justify-start gap-3 mb-2">
                    <h3 className="text-2xl font-bold">
                      {result.status === 'safe' && 'This URL appears safe'}
                      {result.status === 'phishing' && 'Phishing detected!'}
                    </h3>
                    {getStatusBadge(result.status)}
                  </div>
                  <p className="text-slate-600 mb-4">
                    Confidence: <span className="font-semibold">{result.confidence}%</span>
                  </p>

                  <div className="bg-white/70 rounded-lg p-4">
                    <h4 className="font-semibold text-sm text-slate-700 mb-2 flex items-center gap-2">
                      <Info className="w-4 h-4" />
                      Analysis Results:
                    </h4>
                    <ul className="space-y-1">
                      {result.reasons.map((reason, index) => (
                        <li key={index} className="text-sm text-slate-600 flex items-start gap-2">
                          <span className="text-slate-400 mt-1">•</span>
                          {reason}
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Stats Section */}
        {stats.total > 0 && (
          <Card className="mb-6 border-slate-200">
            <CardHeader className="pb-3">
              <CardTitle className="text-lg flex items-center gap-2">
                <BarChart3 className="w-5 h-5" />
                Your Scan Statistics
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-3 gap-4">
                <div className="text-center p-3 bg-slate-50 rounded-lg">
                  <div className="text-2xl font-bold text-slate-900">{stats.total}</div>
                  <div className="text-xs text-slate-500">Total</div>
                </div>
                <div className="text-center p-3 bg-green-50 rounded-lg">
                  <div className="text-2xl font-bold text-green-600">{stats.safe}</div>
                  <div className="text-xs text-green-600">Safe</div>
                </div>
                <div className="text-center p-3 bg-red-50 rounded-lg">
                  <div className="text-2xl font-bold text-red-600">{stats.phishing}</div>
                  <div className="text-xs text-red-600">Phishing</div>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* How It Works */}
        <Card className="border-slate-200">
          <CardHeader>
            <CardTitle className="text-lg">How It Works</CardTitle>
            <CardDescription>
              Our rule-based detection system analyzes URLs for common phishing indicators
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid md:grid-cols-3 gap-4">
              <div className="p-4 bg-slate-50 rounded-lg">
                <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center mb-3">
                  <Search className="w-5 h-5 text-blue-600" />
                </div>
                <h4 className="font-semibold text-sm mb-1">Pattern Analysis</h4>
                <p className="text-xs text-slate-600">Detects suspicious keywords, IP addresses, and excessive subdomains</p>
              </div>
              <div className="p-4 bg-slate-50 rounded-lg">
                <div className="w-10 h-10 bg-purple-100 rounded-lg flex items-center justify-center mb-3">
                  <Shield className="w-5 h-5 text-purple-600" />
                </div>
                <h4 className="font-semibold text-sm mb-1">Brand Protection</h4>
                <p className="text-xs text-slate-600">Identifies potential brand impersonation and typosquatting attempts</p>
              </div>
              <div className="p-4 bg-slate-50 rounded-lg">
                <div className="w-10 h-10 bg-green-100 rounded-lg flex items-center justify-center mb-3">
                  <CheckCircle className="w-5 h-5 text-green-600" />
                </div>
                <h4 className="font-semibold text-sm mb-1">Risk Scoring</h4>
                <p className="text-xs text-slate-600">Calculates confidence score based on multiple security factors</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </main>

      {/* Footer */}
      <footer className="bg-white border-t border-slate-200 mt-12">
        <div className="max-w-4xl mx-auto px-4 py-6">
          <p className="text-center text-sm text-slate-500">
            PhishGuard MVP - Rule-based phishing detection for educational purposes
          </p>
        </div>
      </footer>

      {/* History Dialog */}
      <Dialog open={showHistory} onOpenChange={setShowHistory}>
        <DialogContent className="max-w-2xl max-h-[80vh] flex flex-col">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <History className="w-5 h-5" />
              Scan History
            </DialogTitle>
            <DialogDescription>
              View your previously checked URLs and their results
            </DialogDescription>
          </DialogHeader>

          <div className="flex justify-between items-center py-2">
            <span className="text-sm text-slate-500">
              {history.length} {history.length === 1 ? 'URL' : 'URLs'} scanned
            </span>
            {history.length > 0 && (
              <Button
                variant="destructive"
                size="sm"
                onClick={clearHistory}
                className="gap-2"
              >
                <Trash2 className="w-4 h-4" />
                Clear All
              </Button>
            )}
          </div>

          <ScrollArea className="flex-1 border rounded-lg">
            {history.length === 0 ? (
              <div className="p-8 text-center text-slate-500">
                <History className="w-12 h-12 mx-auto mb-3 opacity-50" />
                <p>No scan history yet</p>
                <p className="text-sm">Check some URLs to see them here</p>
              </div>
            ) : (
              <div className="divide-y">
                {history.map((item, index) => (
                  <div key={index} className="p-4 hover:bg-slate-50 flex items-center justify-between gap-4">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="font-medium text-sm truncate">{item.url}</span>
                        <a
                          href={item.url.startsWith('http') ? item.url : `https://${item.url}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-slate-400 hover:text-blue-600 flex-shrink-0"
                        >
                          <ExternalLink className="w-3 h-3" />
                        </a>
                      </div>
                      <div className="flex items-center gap-3 text-xs text-slate-500">
                        <span>{new Date(item.result.checkedAt).toLocaleString()}</span>
                        <span>•</span>
                        <span>{item.result.confidence}% confidence</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {getStatusBadge(item.result.status)}
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => removeFromHistory(item.url)}
                        className="text-slate-400 hover:text-red-600"
                      >
                        <Trash2 className="w-4 h-4" />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </ScrollArea>
        </DialogContent>
      </Dialog>
    </div>
  );
}

export default App;
