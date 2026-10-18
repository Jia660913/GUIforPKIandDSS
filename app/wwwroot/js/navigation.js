(() => {
    const back = document.querySelector('[data-back-link]');
    if (!back) return;
    // Return to a known GET page without replaying a submitted form or leaving this tool.
    try {
        const previous = new URL(document.referrer);
        const current = new URL(window.location.href);
        const pages = /^\/(?:Pki|Dss|Admin|History|Account\/ChangePassword)?\/?$/i;
        if (previous.origin === current.origin && previous.href !== current.href &&
            pages.test(previous.pathname) && !previous.searchParams.has('handler')) {
            back.href = previous.pathname + previous.search;
            back.removeAttribute('aria-disabled');
            back.removeAttribute('tabindex');
        }
    } catch { /* A direct visit has no previous tool page; keep the server fallback. */ }
})();
