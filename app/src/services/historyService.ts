import type { URLCheck } from './phishingDetector';

const API_BASE = 'http://localhost:3001/api/history';

export class HistoryService {
  /**
   * Get all checked URLs from history
   */
  static async getHistory(): Promise<URLCheck[]> {
    try {
      const response = await fetch(API_BASE);
      if (!response.ok) throw new Error('Failed to fetch history');
      const data = await response.json();
      // Map API response back to frontend interface
      return data.map((item: any) => ({
        url: item.url,
        result: {
          status: item.status,
          confidence: item.confidence,
          reasons: item.reasons,
          checkedAt: item.checkedAt
        }
      }));
    } catch (error) {
      console.error('Error reading history:', error);
      return [];
    }
  }

  /**
   * Add a URL check to history
   */
  static async addToHistory(urlCheck: URLCheck): Promise<void> {
    try {
      await fetch(API_BASE, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          url: urlCheck.url,
          status: urlCheck.result.status,
          confidence: urlCheck.result.confidence,
          reasons: urlCheck.result.reasons,
          checkedAt: urlCheck.result.checkedAt
        })
      });
    } catch (error) {
      console.error('Error saving history:', error);
    }
  }

  /**
   * Clear all history
   */
  static async clearHistory(): Promise<void> {
    try {
      await fetch(API_BASE, { method: 'DELETE' });
    } catch (error) {
      console.error('Error clearing history:', error);
    }
  }

  /**
   * Remove a specific URL from history
   */
  static async removeFromHistory(url: string): Promise<void> {
    try {
      await fetch(`${API_BASE}/${encodeURIComponent(url)}`, { method: 'DELETE' });
    } catch (error) {
      console.error('Error removing from history:', error);
    }
  }

  /**
   * Get statistics from history array
   */
  static getStats(history: URLCheck[]): { total: number; safe: number; phishing: number } {
    return {
      total: history.length,
      safe: history.filter(h => h.result.status === 'safe').length,
      phishing: history.filter(h => h.result.status === 'phishing').length
    };
  }
}

export default HistoryService;
