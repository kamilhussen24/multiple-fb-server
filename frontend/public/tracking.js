// Configuration object for each website
const config = {
  pixel_id: 'YOUR_PIXEL_ID',
  api_url: 'https://your-api-endpoint.com/api/track',
  api_key: 'YOUR_API_KEY'
};

// Load configuration from script tag
function loadConfig() {
  const scriptTag = document.currentScript || document.querySelector('script[data-tracking-config]');
  if (scriptTag && scriptTag.dataset.trackingConfig) {
    try {
      const dynamicConfig = JSON.parse(scriptTag.dataset.trackingConfig);
      Object.assign(config, dynamicConfig);
    } catch (error) {
      logError('Error parsing tracking config', { error: error.message });
    }
  } else {
    logError('No tracking config found in script tag');
  }
}

// Send error logs to backend
async function logError(message, details = {}) {
  try {
    await fetch(config.api_url.replace('/track', '/log-error'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message, details, origin: window.location.origin })
    });
  } catch (error) {
    // Silent fail to avoid infinite loops
  }
}

// Initialize Facebook Pixel
!function(f,b,e,v,n,t,s)
{if(f.fbq)return;n=f.fbq=function(){n.callMethod?
n.callMethod.apply(n,arguments):n.queue.push(arguments)};
if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';
n.queue=[];t=b.createElement(e);t.async=!0;
t.src=v;s=b.getElementsByTagName(e)[0];
s.parentNode.insertBefore(t,s)}(window, document,'script',
'https://connect.facebook.net/en_US/fbevents.js');

// Load config and initialize Pixel
loadConfig();
if (config.pixel_id !== 'YOUR_PIXEL_ID') {
  fbq('init', config.pixel_id);
  fbq('track', 'PageView');
} else {
  logError('Pixel ID not provided. Skipping Pixel initialization.');
}

// Helper function to get cookie
function getCookieValue(name) {
  const match = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
  const value = match ? match[2] : null;
  if (value && (name === '_fbp' || name === '_fbc')) {
    const regex = name === '_fbp' ? /^fb\.\d+\.\d+\.\d+$/ : /^fb\.\d+\.\d+\..+$/;
    if (!regex.test(value)) {
      logError(`Invalid ${name} cookie format`, { value });
      const newValue = name === '_fbp' ? generateFbp() : '';
      if (name === '_fbp') {
        document.cookie = `${name}=${newValue}; path=/; max-age=7776000; SameSite=Lax; Secure`;
      }
      return newValue;
    } else if (name === '_fbc') {
      const fbcParts = value.split('.');
      if (fbcParts.length >= 4) {
        const creationTime = parseInt(fbcParts[2], 10);
        const currentTime = Math.floor(Date.now() / 1000);
        if (isNaN(creationTime) || creationTime < currentTime - 7 * 24 * 60 * 60 || creationTime > currentTime + 60) {
          logError(`Invalid _fbc creation time`, { creationTime });
          return '';
        }
      }
      return value;
    }
  }
  return value;
}

// Helper function to generate fbp
function generateFbp() {
  const version = 'fb';
  const subdomainIndex = 1;
  const creationTime = Math.floor(Date.now() / 1000);
  const randomNumber = Math.floor(Math.random() * 10000000000);
  const fbp = `${version}.${subdomainIndex}.${creationTime}.${randomNumber}`;
  return fbp;
}

// Helper function to generate fbc
function generateFbc(fbclid) {
  const version = 'fb';
  const subdomainIndex = 1;
  const creationTime = Math.floor(Date.now() / 1000);
  const fbc = `${version}.${subdomainIndex}.${creationTime}.${fbclid}`;
  return fbc;
}

// Helper function to validate fbp
function validateFbp(fbp) {
  const fbpRegex = /^fb\.\d+\.\d+\.\d+$/;
  if (fbp && fbpRegex.test(fbp)) {
    const creationTime = parseInt(fbp.split('.')[2], 10);
    const currentTime = Math.floor(Date.now() / 1000);
    if (creationTime < currentTime - 7 * 24 * 60 * 60 || creationTime > currentTime + 60) {
      logError('Invalid fbp creation time, generating new fbp', { fbp });
      return generateFbp();
    }
    return fbp;
  }
  logError('Invalid fbp format, generating new fbp', { fbp });
  return generateFbp();
}

// Helper function to validate fbc
function validateFbc(fbc, fbclid) {
  const fbcRegex = /^fb\.\d+\.\d+\..+$/;
  const currentTime = Math.floor(Date.now() / 1000);
  if (fbc && fbcRegex.test(fbc)) {
    const creationTime = parseInt(fbc.split('.')[2], 10);
    if (isNaN(creationTime) || creationTime < currentTime - 7 * 24 * 60 * 60 || creationTime > currentTime + 60) {
      logError('Invalid fbc creation time, generating new fbc', { fbc });
      return fbclid ? generateFbc(fbclid) : '';
    }
    return fbc;
  }
  return fbclid ? generateFbc(fbclid) : '';
}

// Helper function to generate unique event ID
function generateEventId(name) {
  return `${name}-${crypto.randomUUID()}`;
}

// Initialize fbp and fbc
const currentTime = Math.floor(Date.now() / 1000);
const fbclid = new URLSearchParams(window.location.search).get('fbclid');
const rawFbp = getCookieValue('_fbp') || generateFbp();
const rawFbc = getCookieValue('_fbc') || (fbclid ? generateFbc(fbclid) : '');
const fbp = validateFbp(rawFbp);
const fbc = validateFbc(rawFbc, fbclid);
const userAgent = navigator.userAgent;

// Event tracking function
async function trackEvent(event_name, options = {}) {
  try {
    const { value = null, currency = null, url = null, content_ids = null, content_type = null, content_category = null, custom_data = {} } = options;
    const event_id = generateEventId(event_name);

    // Validate event_time
    let event_time = Math.floor(Date.now() / 1000);
    if (event_time < currentTime - 7 * 24 * 60 * 60 || event_time > currentTime + 60) {
      logError('Invalid event_time, using current time', { event_name, event_time });
      event_time = currentTime;
    }

    const payload = {
      event_name,
      event_source_url: window.location.href,
      event_id,
      event_time,
      user_data: {
        fbp,
        fbc,
        client_user_agent: userAgent
      },
      custom_data: {
        ...(value !== null ? { value } : {}),
        ...(currency !== null ? { currency } : {}),
        ...(content_ids !== null ? { content_ids } : {}),
        ...(content_type !== null ? { content_type } : {}),
        ...(content_category !== null ? { content_category } : {}),
        ...custom_data
      }
    };

    if (window.fbq && config.pixel_id !== 'YOUR_PIXEL_ID') {
      fbq('trackCustom', event_name, {
        eventID: event_id,
        ...(value !== null ? { value, currency } : {}),
        ...(content_ids !== null ? { content_ids } : {}),
        ...(content_type !== null ? { content_type } : {}),
        ...(content_category !== null ? { content_category } : {}),
        ...custom_data
      });
    } else {
      logError('Facebook Pixel not initialized', { event_name });
    }

    const response = await fetch(config.api_url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': config.api_key
      },
      body: JSON.stringify(payload)
    });
    if (!response.ok) {
      throw new Error(`Server responded with status: ${response.status}`);
    }

    if (url) {
      setTimeout(() => {
        window.location.href = url;
      }, 500); // Reduced delay for better UX
    }
  } catch (error) {
    logError(`Error in trackEvent for ${event_name}`, { error: error.message });
  }
}

// PageView event
window.addEventListener('DOMContentLoaded', () => {
  try {
    let event_time = Math.floor(Date.now() / 1000);
    if (event_time < currentTime - 7 * 24 * 60 * 60 || event_time > currentTime + 60) {
      logError('Invalid event_time for PageView, using current time', { event_time });
      event_time = currentTime;
    }

    const payload = {
      event_name: 'PageView',
      event_source_url: window.location.href,
      event_id: generateEventId('PageView'),
      event_time,
      user_data: {
        fbp,
        fbc,
        client_user_agent: userAgent
      },
      custom_data: {}
    };

    if (window.fbq && config.pixel_id !== 'YOUR_PIXEL_ID') {
      fbq('track', 'PageView', { eventID: payload.event_id });
    }

    fetch(config.api_url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': config.api_key
      },
      body: JSON.stringify(payload)
    })
      .then((response) => {
        if (!response.ok) {
          throw new Error(`Server responded with status: ${response.status}`);
        }
      })
      .catch((error) => {
        logError('Error sending PageView event to server', { error: error.message });
      });
  } catch (error) {
    logError('Error in PageView event handler', { error: error.message });
  }
});
// Expose trackEvent globally
window.trackEvent = trackEvent;