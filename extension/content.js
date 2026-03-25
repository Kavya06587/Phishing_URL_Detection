// content.js
// Extract features → send to background → receive result

(function () {

  function extractFeatures(url) {
    const parser = document.createElement('a');
    parser.href = url;

    const hostname = parser.hostname;
    const path = parser.pathname;
    const query = parser.search;
    const fullurl = url;
    const scheme = parser.protocol.replace(':', '');

    const count = (str, char) => (str.split(char).length - 1);
    const hasIP = (host) => /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
    const digits = (str) => (str.match(/\d/g) || []).length;

    // ── Lexical features ──
    const length_url = fullurl.length;
    const length_hostname = hostname.length;
    const ip = hasIP(hostname) ? 1 : 0;
    const nb_dots = count(fullurl, '.');
    const nb_hyphens = count(fullurl, '-');
    const nb_at = count(fullurl, '@');
    const nb_qm = count(fullurl, '?');
    const nb_and = count(fullurl, '&');
    const nb_or = count(fullurl, '|');
    const nb_eq = count(fullurl, '=');
    const nb_underscore = count(fullurl, '_');
    const nb_tilde = count(fullurl, '~');
    const nb_percent = count(fullurl, '%');
    const nb_slash = count(fullurl, '/');
    const nb_star = count(fullurl, '*');
    const nb_colon = count(fullurl, ':');
    const nb_comma = count(fullurl, ',');
    const nb_semicolumn = count(fullurl, ';');
    const nb_dollar = count(fullurl, '$');
    const nb_space = count(fullurl, ' ');
    const nb_www = (fullurl.toLowerCase().match(/www/g) || []).length;
    const nb_com = (fullurl.toLowerCase().match(/\.com/g) || []).length;
    const nb_dslash = count(fullurl, '//');
    const http_in_path = path.toLowerCase().includes('http') ? 1 : 0;
    const https_token = scheme === 'https' ? 1 : 0;
    const ratio_digits_url = digits(fullurl) / length_url;
    const ratio_digits_host = digits(hostname) / (length_hostname || 1);

    // ── Obfuscation ──
    const punycode = hostname.includes('xn--') ? 1 : 0;
    const port = parser.port ? parseInt(parser.port) : 0;
    const tld_in_path = /\.(com|net|org|info|biz)/.test(path) ? 1 : 0;

    const parts = hostname.split('.');
    const tld_in_subdomain = parts.slice(0, -2).some(p =>
      ['com', 'net', 'org', 'info'].includes(p)) ? 1 : 0;

    const abnormal_subdomain = parts.length > 3 ? 1 : 0;
    const nb_subdomains = Math.max(0, parts.length - 2);
    const prefix_suffix = hostname.includes('-') ? 1 : 0;

    const domain = parts[0];
    const vowels = (domain.match(/[aeiou]/gi) || []).length;
    const random_domain = vowels / (domain.length || 1) < 0.2 ? 1 : 0;

    const shortening_service = /bit\.ly|tinyurl|goo\.gl|t\.co/.test(fullurl) ? 1 : 0;
    const path_extension = /\.(exe|php|asp|jsp|cgi|bat|sh)$/.test(path) ? 1 : 0;
    const nb_redirection = count(path, '//');
    const nb_external_redirection = count(query, 'http');

    // ── HTML features ──
    const anchors = document.querySelectorAll('a');
    const allLinks = anchors.length || 1;

    const extLinks = Array.from(anchors).filter(a =>
      a.hostname && a.hostname !== hostname).length;

    const intLinks = allLinks - extLinks;

    const nb_hyperlinks = allLinks;
    const ratio_intHyperlinks = intLinks / allLinks;
    const ratio_extHyperlinks = extLinks / allLinks;

    const login_form = document.querySelector('input[type="password"]') ? 1 : 0;

    const iframe = document.querySelectorAll('iframe').length > 0 ? 1 : 0;

    return {
      length_url, length_hostname, ip, nb_dots, nb_hyphens,
      nb_at, nb_qm, nb_and, nb_or, nb_eq, nb_underscore,
      nb_tilde, nb_percent, nb_slash, nb_star, nb_colon,
      nb_comma, nb_semicolumn, nb_dollar, nb_space,
      nb_www, nb_com, nb_dslash, http_in_path, https_token,
      ratio_digits_url, ratio_digits_host,
      punycode, port, tld_in_path, tld_in_subdomain,
      abnormal_subdomain, nb_subdomains, prefix_suffix,
      random_domain, shortening_service, path_extension,
      nb_redirection, nb_external_redirection,
      nb_hyperlinks, ratio_intHyperlinks, ratio_extHyperlinks,
      login_form, iframe
    };
  }

  function analyzeURL(url) {
    const features = extractFeatures(url);

    chrome.runtime.sendMessage({
      type: 'ANALYZE_URL',
      url: url,
      features: features
    });
  }

  // Receive result from background
  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === 'PREDICTION_RESULT') {
      console.log("Phishing Result:", message.result);
    }
  });

  // Run automatically
  analyzeURL(window.location.href);

})();