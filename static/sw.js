// Service Worker for NetFlow Analytics Dashboard
// Provides offline caching for static assets and graceful degradation

const CACHE_NAME = 'netflow-dashboard-v2.6.1';
const STATIC_ASSETS = [
    '/',
    '/static/style.css',
    '/static/app.js',
    '/static/chart.min.js',
    '/static/alpine.min.js',
    '/static/alpine-collapse.min.js',
    '/static/vis-network.min.js'
];

// Cache durations (in seconds)
const API_CACHE_TTL = 60;  // API responses cached for 60s

// Install event - cache static assets
self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(cache => {
                console.log('[SW] Caching static assets');
                return cache.addAll(STATIC_ASSETS);
            })
            .then(() => self.skipWaiting())
    );
});

// Activate event - cleanup old caches
self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys()
            .then(keys => {
                return Promise.all(
                    keys.filter(key => key !== CACHE_NAME)
                        .map(key => {
                            console.log('[SW] Removing old cache:', key);
                            return caches.delete(key);
                        })
                );
            })
            .then(() => self.clients.claim())
    );
});

// Fetch event - serve from cache or network
self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);
    
    // Skip non-GET requests
    if (event.request.method !== 'GET') return;
    
    // Skip SSE streams (firewall realtime)
    if (url.pathname.includes('/stream')) return;
    
    // Static assets - cache first
    if (STATIC_ASSETS.some(asset => url.pathname.endsWith(asset) || url.pathname === asset)) {
        event.respondWith(
            caches.match(event.request)
                .then(cached => {
                    if (cached) return cached;
                    return fetch(event.request)
                        .then(response => {
                            if (response.status === 200) {
                                const clone = response.clone();
                                caches.open(CACHE_NAME)
                                    .then(cache => cache.put(event.request, clone));
                            }
                            return response;
                        });
                })
        );
        return;
    }
    
    // API requests - network first with cache fallback
    if (url.pathname.startsWith('/api/')) {
        event.respondWith(
            fetch(event.request)
                .then(response => {
                    // Cache successful API responses
                    if (response.status === 200) {
                        const clone = response.clone();
                        caches.open(CACHE_NAME)
                            .then(cache => cache.put(event.request, clone));
                    }
                    return response;
                })
                .catch(() => {
                    // Network failed, try cache
                    return caches.match(event.request)
                        .then(cached => {
                            if (cached) {
                                console.log('[SW] Serving cached API:', url.pathname);
                                return cached;
                            }
                            // Return empty response for API failures
                            return new Response(JSON.stringify({ error: 'Offline', cached: false }), {
                                status: 503,
                                headers: { 'Content-Type': 'application/json' }
                            });
                        });
                })
        );
        return;
    }
    
    // Default - network first
    event.respondWith(
        fetch(event.request)
            .catch(() => caches.match(event.request))
    );
});

// Message handler for cache control
self.addEventListener('message', (event) => {
    if (event.data === 'skipWaiting') {
        self.skipWaiting();
    }
    if (event.data === 'clearCache') {
        caches.delete(CACHE_NAME);
    }
});
