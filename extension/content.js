// content.js — runs on every page the user visits
// Extracts features from the URL and page HTML
// Sends them to the Flask API for prediction

(function() {

  function extractFeatures(url) {
    const parser    = document.createElement('a');
    parser.href     = url;

    const hostname  = parser.hostname;
    const path      = parser.pathname;
    const query     = parser.search;
    const fullurl   = url;
    const scheme    = parser.protocol.replace(':', '');

    // helper functions
    const count     = (str, char) => (str.split(char).length - 1);
    const hasIP     = (host) => /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
    const digits    = (str) => (str.match(/\d/g) || []).length;

    // ── Lexical features ──
    const length_url        = fullurl.length;
    const length_hostname   = hostname.length;
    const ip                = hasIP(hostname) ? 1 : 0;
    const nb_dots           = count(fullurl, '.');
    const nb_hyphens        = count(fullurl, '-');
    const nb_at             = count(fullurl, '@');
    const nb_qm             = count(fullurl, '?');
    const nb_and            = count(fullurl, '&');
    const nb_or             = count(fullurl, '|');
    const nb_eq             = count(fullurl, '=');
    const nb_underscore     = count(fullurl, '_');
    const nb_tilde          = count(fullurl, '~');
    const nb_percent        = count(fullurl, '%');
    const nb_slash          = count(fullurl, '/');
    const nb_star           = count(fullurl, '*');
    const nb_colon          = count(fullurl, ':');
    const nb_comma          = count(fullurl, ',');
    const nb_semicolumn     = count(fullurl, ';');
    const nb_dollar         = count(fullurl, '$');
    const nb_space          = count(fullurl, ' ');
    const nb_www            = (fullurl.toLowerCase().match(/www/g) || []).length;
    const nb_com            = (fullurl.toLowerCase().match(/\.com/g) || []).length;
    const nb_dslash         = count(fullurl, '//');
    const http_in_path      = path.toLowerCase().includes('http') ? 1 : 0;
    const https_token       = scheme === 'https' ? 1 : 0;
    const ratio_digits_url  = digits(fullurl) / length_url;
    const ratio_digits_host = digits(hostname) / (length_hostname || 1);

    // ── Obfuscation features ──
    const punycode          = hostname.includes('xn--') ? 1 : 0;
    const port              = parser.port ? parseInt(parser.port) : 0;
    const tld_in_path       = /\.(com|net|org|info|biz)/.test(path) ? 1 : 0;
    const tld_in_subdomain  = (() => {
      const parts = hostname.split('.');
      return parts.slice(0, -2).some(p =>
        ['com','net','org','info'].includes(p)) ? 1 : 0;
    })();
    const abnormal_subdomain= hostname.split('.').length > 3 ? 1 : 0;
    const nb_subdomains     = Math.max(0, hostname.split('.').length - 2);
    const prefix_suffix     = hostname.includes('-') ? 1 : 0;
    const random_domain     = (() => {
      const domain = hostname.split('.')[0];
      const vowels = (domain.match(/[aeiou]/gi) || []).length;
      return vowels / (domain.length || 1) < 0.2 ? 1 : 0;
    })();
    const shortening_service= /bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly/.test(fullurl) ? 1 : 0;
    const path_extension    = /\.(exe|php|asp|jsp|cgi|bat|sh)$/.test(path) ? 1 : 0;
    const nb_redirection    = count(path, '//');
    const nb_external_redirection = count(query, 'http');

    // ── Word-based features ──
    const words_raw         = fullurl.split(/[\W_]+/).filter(w => w.length > 0);
    const words_host        = hostname.split(/[\W_]+/).filter(w => w.length > 0);
    const words_path        = path.split(/[\W_]+/).filter(w => w.length > 0);

    const length_words_raw      = words_raw.length;
    const char_repeat           = (() => {
      let max = 0, cur = 1;
      for (let i = 1; i < fullurl.length; i++) {
        cur = fullurl[i] === fullurl[i-1] ? cur + 1 : 1;
        max = Math.max(max, cur);
      }
      return max;
    })();
    const shortest_words_raw    = words_raw.length ?
      Math.min(...words_raw.map(w => w.length)) : 0;
    const shortest_word_host    = words_host.length ?
      Math.min(...words_host.map(w => w.length)) : 0;
    const shortest_word_path    = words_path.length ?
      Math.min(...words_path.map(w => w.length)) : 0;
    const longest_words_raw     = words_raw.length ?
      Math.max(...words_raw.map(w => w.length)) : 0;
    const longest_word_host     = words_host.length ?
      Math.max(...words_host.map(w => w.length)) : 0;
    const longest_word_path     = words_path.length ?
      Math.max(...words_path.map(w => w.length)) : 0;
    const avg_words_raw         = words_raw.length ?
      words_raw.reduce((s,w) => s + w.length, 0) / words_raw.length : 0;
    const avg_word_host         = words_host.length ?
      words_host.reduce((s,w) => s + w.length, 0) / words_host.length : 0;
    const avg_word_path         = words_path.length ?
      words_path.reduce((s,w) => s + w.length, 0) / words_path.length : 0;

    // ── Phishing hints ──
    const phishWords = ['secure','login','verify','account','update',
                        'confirm','banking','signin','ebayisapi','webscr'];
    const phish_hints = phishWords.reduce((n, w) =>
      n + (fullurl.toLowerCase().split(w).length - 1), 0);

    // ── Brand features ──
    const brands = ['paypal','google','amazon','apple','microsoft',
                    'facebook','netflix','instagram','twitter','bank'];
    const domain_in_brand   = brands.some(b =>
      hostname.toLowerCase().includes(b)) ? 1 : 0;
    const brand_in_subdomain= (() => {
      const sub = hostname.split('.').slice(0,-2).join('.');
      return brands.some(b => sub.toLowerCase().includes(b)) ? 1 : 0;
    })();
    const brand_in_path     = brands.some(b =>
      path.toLowerCase().includes(b)) ? 1 : 0;

    // ── Suspicious TLD ──
    const suspTLDs = ['.xyz','.top','.club','.online','.site',
                      '.info','.biz','.tk','.ml','.ga'];
    const suspecious_tld    = suspTLDs.some(t =>
      hostname.endsWith(t)) ? 1 : 0;
    const statistical_report= 0; // requires external API

    // ── HTML/JS features (from live page) ──
    const anchors           = document.querySelectorAll('a');
    const allLinks          = anchors.length || 1;
    const extLinks          = Array.from(anchors).filter(a =>
      a.hostname && a.hostname !== hostname).length;
    const intLinks          = allLinks - extLinks;
    const nullLinks         = Array.from(anchors).filter(a =>
      !a.href || a.href === '#' || a.href === 'javascript:void(0)').length;

    const nb_hyperlinks         = allLinks;
    const ratio_intHyperlinks   = intLinks / allLinks;
    const ratio_extHyperlinks   = extLinks / allLinks;
    const ratio_nullHyperlinks  = nullLinks / allLinks;
    const nb_extCSS             = Array.from(
      document.querySelectorAll('link[rel="stylesheet"]')).filter(l =>
      l.href && !l.href.includes(hostname)).length;

    const iframes           = document.querySelectorAll('iframe');
    const intIframes        = Array.from(iframes).filter(i =>
      i.src && i.src.includes(hostname)).length;
    const extIframes        = iframes.length - intIframes;

    const ratio_intRedirection  = iframes.length ?
      intIframes / iframes.length : 0;
    const ratio_extRedirection  = iframes.length ?
      extIframes / iframes.length : 0;

    const imgs              = document.querySelectorAll('img');
    const extImgs           = Array.from(imgs).filter(i =>
      i.src && !i.src.includes(hostname)).length;
    const ratio_intMedia    = imgs.length ?
      (imgs.length - extImgs) / imgs.length : 0;
    const ratio_extMedia    = imgs.length ?
      extImgs / imgs.length : 0;

    // Error links
    const brokenInt = Array.from(anchors).filter(a =>
      a.hostname === hostname && (!a.href || a.href === '')).length;
    const brokenExt = Array.from(anchors).filter(a =>
      a.hostname !== hostname && (!a.href || a.href === '')).length;
    const ratio_intErrors   = allLinks ? brokenInt / allLinks : 0;
    const ratio_extErrors   = allLinks ? brokenExt / allLinks : 0;

    const login_form        = document.querySelector(
      'input[type="password"]') ? 1 : 0;
    const external_favicon  = (() => {
      const fav = document.querySelector('link[rel*="icon"]');
      return fav && fav.href && !fav.href.includes(hostname) ? 1 : 0;
    })();
    const links_in_tags     = document.querySelectorAll(
      'meta[http-equiv], base').length;
    const submit_email      = Array.from(
      document.querySelectorAll('form')).some(f =>
      f.action && f.action.includes('mailto:')) ? 1 : 0;
    const sfh               = (() => {
      const forms = document.querySelectorAll('form');
      if (!forms.length) return 0;
      const blank = Array.from(forms).filter(f =>
        !f.action || f.action === '' || f.action === 'about:blank').length;
      return blank / forms.length;
    })();
    const iframe            = iframes.length > 0 ? 1 : 0;
    const popup_window      = 0; // can't detect reliably
    const safe_anchor       = Array.from(anchors).filter(a =>
      a.href && (a.href.startsWith('#') ||
      a.href.toLowerCase() === 'javascript:void(0)')).length / allLinks;
    const onmouseover       = document.querySelector(
      '[onmouseover]') ? 1 : 0;
    const right_clic        = document.querySelector(
      '[oncontextmenu]') ? 1 : 0;
    const empty_title       = !document.title ||
      document.title.trim() === '' ? 1 : 0;
    const domain_in_title   = document.title.toLowerCase().includes(
      hostname.toLowerCase().split('.')[0]) ? 1 : 0;
    const domain_with_copyright = document.body.innerHTML.toLowerCase().includes(
      hostname.split('.')[0].toLowerCase()) ? 1 : 0;

    const whois_registered_domain = 1;
    const domain_registration_length = 365;
    const domain_age          = 500; // unknown without WHOIS API
    const web_traffic         = 3;  // unknown without Alexa API
    const dns_record          = 1;  // assume DNS exists
    const google_index        = 0.5;  // unknown without Google API
    const page_rank           = 3;  // unknown without API

    return {
      length_url, length_hostname, ip, nb_dots, nb_hyphens,
      nb_at, nb_qm, nb_and, nb_or, nb_eq, nb_underscore,
      nb_tilde, nb_percent, nb_slash, nb_star, nb_colon,
      nb_comma, nb_semicolumn, nb_dollar, nb_space,
      nb_www, nb_com, nb_dslash, http_in_path, https_token,
      ratio_digits_url, ratio_digits_host, punycode, port,
      tld_in_path, tld_in_subdomain, abnormal_subdomain,
      nb_subdomains, prefix_suffix, random_domain,
      shortening_service, path_extension, nb_redirection,
      nb_external_redirection, length_words_raw, char_repeat,
      shortest_words_raw, shortest_word_host, shortest_word_path,
      longest_words_raw, longest_word_host, longest_word_path,
      avg_words_raw, avg_word_host, avg_word_path,
      phish_hints, domain_in_brand, brand_in_subdomain,
      brand_in_path, suspecious_tld, statistical_report,
      nb_hyperlinks, ratio_intHyperlinks, ratio_extHyperlinks,
      ratio_nullHyperlinks, nb_extCSS, ratio_intRedirection,
      ratio_extRedirection, ratio_intErrors, ratio_extErrors,
      login_form, external_favicon, links_in_tags, submit_email,
      ratio_intMedia, ratio_extMedia, sfh, iframe, popup_window,
      safe_anchor, onmouseover, right_clic, empty_title,
      domain_in_title, domain_with_copyright,
      whois_registered_domain, domain_registration_length,
      domain_age, web_traffic, dns_record, google_index, page_rank
    };
  }

  // ── SEND TO FLASK API ────────────────────────────────────

  function analyzeURL(url) {
    const features = extractFeatures(url);

    fetch('http://127.0.0.1:5000/predict', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ url, features })
    })
    .then(r => r.json())
    .then(result => {
      // Send result to background script
      chrome.runtime.sendMessage({
        type:   'PREDICTION_RESULT',
        result: result,
        url:    url
      });
    })
    .catch(err => {
      console.error('Phishing detector error:', err);
    });
  }

  // Run when page loads
  analyzeURL(window.location.href);

})();