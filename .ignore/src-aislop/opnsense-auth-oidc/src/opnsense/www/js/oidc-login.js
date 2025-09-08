// Inject OIDC login button on OPNsense login page (simple draft)
(function () {
    function ready(fn) { if (document.readyState !== 'loading') { fn(); } else document.addEventListener('DOMContentLoaded', fn); }
    ready(function () {
        var form = document.querySelector('form[action="/index.php"]');
        if (!form) return;
        var btn = document.createElement('a');
        btn.className = 'btn btn-info btn-sm';
        btn.style.marginLeft = '8px';
        btn.textContent = 'Login with OIDC';
        btn.href = '/oidc/login';
        form.appendChild(btn);
    });
})();
