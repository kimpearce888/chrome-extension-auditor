/**
 * Native messaging client (§155). Strict JSON-RPC style: every request has a
 * requestId; responses and progress events are matched back to callers.
 * The host is the ONLY component with filesystem access (§158).
 */

export interface NativeResponse<T = unknown> {
  requestId: string;
  success: boolean;
  result?: T;
  error?: { code: string; message: string };
  event?: string;
}

export interface ProgressEvent {
  type: string;
  stage: string;
  current: number;
  total: number;
  message: string;
}

type Pending = {
  resolve: (v: any) => void;
  reject: (e: Error) => void;
  onEvent?: (ev: string, payload: any) => void;
};

const HOST_NAME = 'com.local.extensionauditor.scanner';

export class NativeHost {
  private port: chrome.runtime.Port | null = null;
  private pending = new Map<string, Pending>();
  private seq = 0;
  private connected = false;
  private statusListeners: Array<(up: boolean) => void> = [];

  connect(): void {
    if (this.port) return;
    try {
      this.port = chrome.runtime.connectNative(HOST_NAME);
    } catch (e) {
      this.setStatus(false);
      return;
    }
    this.port.onMessage.addListener((msg: NativeResponse) => this.onMessage(msg));
    this.port.onDisconnect.addListener(() => {
      this.port = null;
      this.connected = false;
      this.setStatus(false);
      // fail all pending with a clear error state (§108)
      for (const [, p] of this.pending) {
        p.reject(new Error('NATIVE_HOST_DISCONNECTED'));
      }
      this.pending.clear();
    });
    this.connected = true;
    this.setStatus(true);
  }

  get isConnected(): boolean {
    return this.connected && this.port !== null;
  }

  onStatusChange(cb: (up: boolean) => void): void {
    this.statusListeners.push(cb);
  }

  private setStatus(up: boolean): void {
    for (const cb of this.statusListeners) cb(up);
  }

  private onMessage(msg: NativeResponse): void {
    const p = this.pending.get(msg.requestId);
    if (!p) return;
    if (msg.event && p.onEvent) {
      p.onEvent(msg.event, msg.result);
      return;
    }
    this.pending.delete(msg.requestId);
    if (msg.success) {
      p.resolve(msg.result);
    } else {
      const err = new Error(msg.error ? `${msg.error.code}: ${msg.error.message}` : 'UNKNOWN');
      (err as any).code = msg.error ? msg.error.code : 'UNKNOWN';
      p.reject(err);
    }
  }

  /** Sends an action with options; onEvent receives progress streams (§88). */
  request<T = unknown>(
    action: string,
    options: Record<string, unknown> = {},
    onEvent?: (ev: string, payload: any) => void,
  ): Promise<T> {
    this.connect();
    if (!this.port) {
      return Promise.reject(new Error('NATIVE_HOST_UNAVAILABLE'));
    }
    const requestId = `req-${++this.seq}-${Date.now()}`;
    return new Promise<T>((resolve, reject) => {
      this.pending.set(requestId, { resolve, reject, onEvent });
      try {
        this.port!.postMessage({ requestId, action, options });
      } catch (e) {
        this.pending.delete(requestId);
        reject(new Error('NATIVE_HOST_SEND_FAILED'));
      }
      // Safety timeout for requests without progress; scans set their own.
      if (action !== 'scanAll' && action !== 'scanExtension') {
        setTimeout(() => {
          if (this.pending.has(requestId)) {
            this.pending.delete(requestId);
            reject(new Error('NATIVE_HOST_TIMEOUT'));
          }
        }, 120_000);
      }
    });
  }

  async cancelScan(): Promise<void> {
    if (!this.port) return;
    await this.request('cancelScan', {}).catch(() => undefined);
  }
}

export const nativeHost = new NativeHost();
