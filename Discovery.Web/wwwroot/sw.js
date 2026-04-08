// Progressive Web App Service Worker for On-Prem Network InfraIQ
// Version 2.0.0

const CACHE_NAME = 'on-prem-network-infraiq-v2.1.0';
const urlsToCache = [
    '/',
    '/Dashboard/Scanner',
    '/Dashboard/Results',
    '/css/dashboard.css',
    '/js/dashboard.js',
    '/js/scanner.js',
    '/js/results.js',
    'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css',
    'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css',
    'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js'
];

// Install event - cache resources
self.addEventListener('install', function(event) {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(function(cache) {
                console.log('Opened cache');
                return cache.addAll(urlsToCache);
            })
    );
});

// Fetch event - serve from cache when offline with improved error handling
self.addEventListener('fetch', function(event) {
    // Skip cross-origin requests and non-GET requests
    if (!event.request.url.startsWith(self.location.origin) || event.request.method !== 'GET') {
        return;
    }

    // Skip GitHub dev authentication URLs
    if (event.request.url.includes('github.dev') || event.request.url.includes('pf-signin')) {
        return;
    }

    event.respondWith(
        caches.match(event.request)
            .then(function(response) {
                // Cache hit - return response
                if (response) {
                    return response;
                }

                return fetch(event.request).then(
                    function(response) {
                        // Check if we received a valid response
                        if (!response || response.status !== 200 || response.type !== 'basic') {
                            return response;
                        }

                        // Only cache GET requests for same origin
                        if (event.request.method === 'GET' && event.request.url.startsWith(self.location.origin)) {
                            // Clone the response
                            var responseToCache = response.clone();

                            caches.open(CACHE_NAME)
                                .then(function(cache) {
                                    cache.put(event.request, responseToCache);
                                })
                                .catch(function(error) {
                                    console.log('Cache put failed:', error);
                                });
                        }

                        return response;
                    }
                ).catch(function(error) {
                    console.log('Fetch failed:', error);
                    // Return a fallback response for navigation requests
                    if (event.request.mode === 'navigate') {
                        return caches.match('/Dashboard') || new Response('Offline - Please check your connection', {
                            status: 503,
                            statusText: 'Service Unavailable'
                        });
                    }
                    throw error;
                });
            })
    );
});

// Activate event - clean up old caches
self.addEventListener('activate', function(event) {
    event.waitUntil(
        caches.keys().then(function(cacheNames) {
            return Promise.all(
                cacheNames.map(function(cacheName) {
                    if (cacheName !== CACHE_NAME) {
                        console.log('Deleting old cache:', cacheName);
                        return caches.delete(cacheName);
                    }
                })
            );
        })
    );
});

// Background sync for offline scanning
self.addEventListener('sync', function(event) {
    if (event.tag === 'background-scan') {
        event.waitUntil(doBackgroundScan());
    }
});

function doBackgroundScan() {
    // Implement background scanning logic
    return fetch('/api/NetworkScan/status')
        .then(response => response.json())
        .then(data => {
            console.log('Background sync completed');
        })
        .catch(err => {
            console.log('Background sync failed:', err);
        });
}

// Push notifications
self.addEventListener('push', function(event) {
    const options = {
        body: event.data ? event.data.text() : 'New scan results available',
        icon: '/icon-192x192.png',
        badge: '/badge-72x72.png',
        vibrate: [100, 50, 100],
        data: {
            dateOfArrival: Date.now(),
            primaryKey: '2'
        },
        actions: [
            {
                action: 'explore',
                title: 'View Results',
                icon: '/images/checkmark.png'
            },
            {
                action: 'close',
                title: 'Close',
                icon: '/images/xmark.png'
            }
        ]
    };

    event.waitUntil(
        self.registration.showNotification('On-Prem Network InfraIQ', options)
    );
});

// Notification click handling
self.addEventListener('notificationclick', function(event) {
    event.notification.close();

    if (event.action === 'explore') {
        event.waitUntil(
            clients.openWindow('/Dashboard/Results')
        );
    }
});