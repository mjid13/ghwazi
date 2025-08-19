/**
 * Service Worker for Money Tracker
 * Provides offline functionality and caching
 */

const CACHE_NAME = 'money-tracker-v1';
const STATIC_CACHE = 'money-tracker-static-v1';
const DYNAMIC_CACHE = 'money-tracker-dynamic-v1';

// Assets to cache on install
const STATIC_ASSETS = [
  '/',
  '/static/css/styles.css',
  '/static/css/modern.css',
  '/static/css/enhanced.css',
  '/static/css/responsive.css',
  '/static/css/animations.css',
  '/static/js/app.js',
  '/static/js/modules/utils.js',
  '/static/js/modules/ui.js',
  '/static/js/modules/dashboard.js',
  '/static/js/modules/realtime.js',
  '/static/images/logo/logo.png',
  '/static/images/logo/logo_with_brand_name.png',
  'https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css',
  'https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css',
  'https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js',
  'https://code.jquery.com/jquery-3.7.0.min.js',
  'https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.js'
];

// API endpoints to cache with network-first strategy
const API_ENDPOINTS = [
  '/api/dashboard/charts',
  '/api/accounts/summary',
  '/api/transactions/recent'
];

// Install event - cache static assets
self.addEventListener('install', (event) => {
  console.log('Service Worker: Installing...');
  
  event.waitUntil(
    Promise.all([
      caches.open(STATIC_CACHE).then((cache) => {
        console.log('Service Worker: Caching static assets');
        return cache.addAll(STATIC_ASSETS);
      }),
      self.skipWaiting() // Activate immediately
    ])
  );
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
  console.log('Service Worker: Activating...');
  
  event.waitUntil(
    Promise.all([
      // Clean up old caches
      caches.keys().then((cacheNames) => {
        return Promise.all(
          cacheNames.map((cacheName) => {
            if (cacheName !== STATIC_CACHE && 
                cacheName !== DYNAMIC_CACHE && 
                cacheName !== CACHE_NAME) {
              console.log('Service Worker: Deleting old cache:', cacheName);
              return caches.delete(cacheName);
            }
          })
        );
      }),
      self.clients.claim() // Take control immediately
    ])
  );
});

// Fetch event - implement caching strategies
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Skip non-GET requests
  if (request.method !== 'GET') {
    return;
  }

  // Skip chrome-extension requests
  if (url.protocol === 'chrome-extension:') {
    return;
  }

  // Different strategies for different types of requests
  if (isStaticAsset(request)) {
    event.respondWith(cacheFirstStrategy(request));
  } else if (isAPIRequest(request)) {
    event.respondWith(networkFirstStrategy(request));
  } else if (isImageRequest(request)) {
    event.respondWith(cacheFirstStrategy(request));
  } else if (isHTMLRequest(request)) {
    event.respondWith(networkFirstWithFallback(request));
  } else {
    event.respondWith(networkFirstStrategy(request));
  }
});

// Cache-first strategy (for static assets)
async function cacheFirstStrategy(request) {
  try {
    const cacheResponse = await caches.match(request);
    if (cacheResponse) {
      return cacheResponse;
    }

    const networkResponse = await fetch(request);
    if (networkResponse.ok) {
      const cache = await caches.open(STATIC_CACHE);
      cache.put(request, networkResponse.clone());
    }
    return networkResponse;
  } catch (error) {
    console.error('Cache-first strategy failed:', error);
    return new Response('Offline', { status: 503 });
  }
}

// Network-first strategy (for API requests)
async function networkFirstStrategy(request) {
  try {
    const networkResponse = await fetch(request);
    if (networkResponse.ok) {
      const cache = await caches.open(DYNAMIC_CACHE);
      cache.put(request, networkResponse.clone());
    }
    return networkResponse;
  } catch (error) {
    console.log('Network failed, trying cache:', request.url);
    const cacheResponse = await caches.match(request);
    if (cacheResponse) {
      return cacheResponse;
    }
    return createOfflineResponse(request);
  }
}

// Network-first with fallback to offline page
async function networkFirstWithFallback(request) {
  try {
    const networkResponse = await fetch(request);
    if (networkResponse.ok) {
      const cache = await caches.open(DYNAMIC_CACHE);
      cache.put(request, networkResponse.clone());
    }
    return networkResponse;
  } catch (error) {
    const cacheResponse = await caches.match(request);
    if (cacheResponse) {
      return cacheResponse;
    }
    
    // Return offline page for navigation requests
    if (request.mode === 'navigate') {
      return caches.match('/offline.html') || createOfflinePage();
    }
    
    return createOfflineResponse(request);
  }
}

// Helper functions
function isStaticAsset(request) {
  const url = new URL(request.url);
  return url.pathname.includes('/static/') || 
         url.hostname.includes('cdn.jsdelivr.net') ||
         url.hostname.includes('code.jquery.com');
}

function isAPIRequest(request) {
  const url = new URL(request.url);
  return url.pathname.startsWith('/api/');
}

function isImageRequest(request) {
  const url = new URL(request.url);
  return /\.(jpg|jpeg|png|gif|webp|svg|ico)$/i.test(url.pathname);
}

function isHTMLRequest(request) {
  return request.headers.get('accept')?.includes('text/html');
}

function createOfflineResponse(request) {
  if (isAPIRequest(request)) {
    return new Response(JSON.stringify({
      error: 'Offline',
      message: 'You are currently offline. Please check your connection.'
    }), {
      status: 503,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  return new Response('Offline', { 
    status: 503,
    statusText: 'Service Unavailable'
  });
}

function createOfflinePage() {
  const offlineHTML = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Offline - Money Tracker</title>
      <style>
        body {
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
          display: flex;
          justify-content: center;
          align-items: center;
          min-height: 100vh;
          margin: 0;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          text-align: center;
        }
        .container {
          max-width: 400px;
          padding: 2rem;
        }
        .icon {
          font-size: 4rem;
          margin-bottom: 1rem;
        }
        h1 {
          font-size: 2rem;
          margin-bottom: 1rem;
        }
        p {
          font-size: 1.1rem;
          margin-bottom: 2rem;
          opacity: 0.9;
        }
        .btn {
          display: inline-block;
          padding: 0.75rem 1.5rem;
          background: rgba(255, 255, 255, 0.2);
          color: white;
          text-decoration: none;
          border-radius: 8px;
          border: 1px solid rgba(255, 255, 255, 0.3);
          transition: all 0.3s ease;
        }
        .btn:hover {
          background: rgba(255, 255, 255, 0.3);
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="icon">📱</div>
        <h1>You're Offline</h1>
        <p>It looks like you've lost your internet connection. Some features may not be available until you're back online.</p>
        <a href="/" class="btn" onclick="window.location.reload()">Try Again</a>
      </div>
    </body>
    </html>
  `;
  
  return new Response(offlineHTML, {
    headers: { 'Content-Type': 'text/html' }
  });
}

// Background sync for offline actions
self.addEventListener('sync', (event) => {
  console.log('Service Worker: Background sync triggered:', event.tag);
  
  if (event.tag === 'sync-transactions') {
    event.waitUntil(syncTransactions());
  } else if (event.tag === 'sync-forms') {
    event.waitUntil(syncOfflineForms());
  }
});

async function syncTransactions() {
  try {
    // Get pending transactions from IndexedDB
    const pendingTransactions = await getStoredData('pending-transactions');
    
    for (const transaction of pendingTransactions) {
      try {
        await fetch('/api/transactions', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
          },
          body: JSON.stringify(transaction)
        });
        
        // Remove from pending queue
        await removeStoredData('pending-transactions', transaction.id);
      } catch (error) {
        console.error('Failed to sync transaction:', error);
      }
    }
  } catch (error) {
    console.error('Background sync failed:', error);
  }
}

async function syncOfflineForms() {
  try {
    const pendingForms = await getStoredData('pending-forms');
    
    for (const formData of pendingForms) {
      try {
        await fetch(formData.action, {
          method: formData.method || 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
          },
          body: JSON.stringify(formData.data)
        });
        
        await removeStoredData('pending-forms', formData.id);
      } catch (error) {
        console.error('Failed to sync form:', error);
      }
    }
  } catch (error) {
    console.error('Form sync failed:', error);
  }
}

// Push notification handling
self.addEventListener('push', (event) => {
  console.log('Service Worker: Push received');
  
  const options = {
    body: 'You have new transaction updates',
    icon: '/static/images/logo/logo.png',
    badge: '/static/images/logo/logo.png',
    vibrate: [100, 50, 100],
    data: {
      dateOfArrival: Date.now(),
      primaryKey: 1
    },
    actions: [
      {
        action: 'explore',
        title: 'View Dashboard',
        icon: '/static/images/icons/dashboard.png'
      },
      {
        action: 'close',
        title: 'Close',
        icon: '/static/images/icons/close.png'
      }
    ]
  };
  
  if (event.data) {
    const data = event.data.json();
    options.body = data.body || options.body;
    options.title = data.title || 'Money Tracker';
  }
  
  event.waitUntil(
    self.registration.showNotification('Money Tracker', options)
  );
});

// Notification click handling
self.addEventListener('notificationclick', (event) => {
  console.log('Service Worker: Notification clicked');
  
  event.notification.close();
  
  if (event.action === 'explore') {
    event.waitUntil(
      clients.openWindow('/dashboard')
    );
  } else if (event.action === 'close') {
    // Just close the notification
  } else {
    // Default action
    event.waitUntil(
      clients.openWindow('/')
    );
  }
});

// Message handling from the main thread
self.addEventListener('message', (event) => {
  console.log('Service Worker: Message received:', event.data);
  
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

// Helper functions for IndexedDB operations
async function getStoredData(storeName) {
  // This would integrate with IndexedDB
  // For now, return empty array
  return [];
}

async function removeStoredData(storeName, id) {
  // This would remove from IndexedDB
  console.log(`Removing ${id} from ${storeName}`);
}

// Periodic background sync for data updates
self.addEventListener('periodicsync', (event) => {
  if (event.tag === 'background-sync') {
    event.waitUntil(doBackgroundSync());
  }
});

async function doBackgroundSync() {
  try {
    // Sync critical data in the background
    await fetch('/api/sync/background', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      }
    });
  } catch (error) {
    console.error('Background sync failed:', error);
  }
}