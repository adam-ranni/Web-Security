/* Client enhancements; all validation and authorization also run on the server. */
document.addEventListener('DOMContentLoaded', function () {
    const banner = document.getElementById('greeting-banner');
    if (banner && window.location.hash) {
        try { banner.textContent = decodeURIComponent(window.location.hash.slice(1)); }
        catch { banner.textContent = window.location.hash.slice(1); }
    }
    document.querySelectorAll('.alert-dismissible').forEach(function (element) {
        if (window.bootstrap) setTimeout(function () {
            bootstrap.Alert.getOrCreateInstance(element).close();
        }, 5000);
    });
    document.querySelectorAll('.danger-confirm').forEach(function (form) {
        form.addEventListener('submit', function (event) {
            if (!confirm('Are you sure? This action cannot be undone.')) event.preventDefault();
        });
    });
    document.querySelectorAll('.qty-input').forEach(function (input) {
        input.addEventListener('change', function () {
            const quantity = Number(this.value);
            this.setCustomValidity(Number.isInteger(quantity) && quantity >= 1 && quantity <= 100 ? '' : 'Choose a quantity from 1 to 100');
        });
    });
    const checkout = document.getElementById('checkout-form');
    if (checkout) checkout.addEventListener('submit', function (event) {
        const balance = Number.parseFloat(document.getElementById('user-balance').dataset.balance);
        const total = Number.parseFloat(document.getElementById('order-total').dataset.total);
        if (total > balance) { event.preventDefault(); alert('Insufficient balance.'); }
    });
    const username = document.querySelector('#register-form #username');
    if (username) {
        let timeout;
        username.addEventListener('input', function () {
            clearTimeout(timeout);
            const value = this.value;
            const feedback = document.getElementById('username-feedback');
            feedback.textContent = '';
            if (value.length < 3) return;
            timeout = setTimeout(async function () {
                try {
                    const response = await fetch('/api/check_username?username=' + encodeURIComponent(value));
                    if (!response.ok) throw new Error('Unavailable');
                    const data = await response.json();
                    if (username.value === value) feedback.textContent = data.exists ? 'Username is taken' : 'Username is available';
                } catch { if (username.value === value) feedback.textContent = 'Availability check unavailable'; }
            }, 500);
        });
    }
    const coupon = document.getElementById('check-coupon-btn');
    if (coupon) coupon.addEventListener('click', async function () {
        const code = document.getElementById('coupon-code-input').value;
        const feedback = document.getElementById('coupon-feedback');
        feedback.textContent = '';
        if (!code) return;
        try {
            const response = await fetch('/api/check_coupon?code=' + encodeURIComponent(code));
            if (!response.ok) throw new Error('Unavailable');
            const data = await response.json();
            feedback.textContent = data.valid ? 'Valid! ' + data.discount + '% off' : 'Invalid coupon';
        } catch { feedback.textContent = 'Coupon check unavailable'; }
    });
    const toggle = document.getElementById('password-toggle');
    if (toggle) toggle.addEventListener('click', function () {
        const password = document.getElementById('password');
        const icon = document.getElementById('toggleIcon');
        const hidden = password.type === 'password';
        password.type = hidden ? 'text' : 'password';
        icon.classList.replace(hidden ? 'fa-eye' : 'fa-eye-slash', hidden ? 'fa-eye-slash' : 'fa-eye');
    });
    const back = document.getElementById('go-back');
    if (back) back.addEventListener('click', function () { window.history.back(); });
    const hero = document.querySelector('.hero-section');
    if (hero) createMatrixRain(hero);
});

function createMatrixRain(container) {
    var canvas = document.createElement('canvas');
    canvas.style.cssText = 'position:absolute;top:0;left:0;width:100%;height:100%;pointer-events:none;opacity:0.1;z-index:0;';
    container.style.position = 'relative';
    container.style.overflow = 'hidden';
    container.insertBefore(canvas, container.firstChild);

    var ctx = canvas.getContext('2d');
    canvas.width = container.offsetWidth;
    canvas.height = container.offsetHeight;

    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*()';
    var fontSize = 14;
    var columns = Math.floor(canvas.width / fontSize);
    var drops = new Array(columns).fill(1);

    function draw() {
        ctx.fillStyle = 'rgba(10, 10, 10, 0.05)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = '#00ff41';
        ctx.font = fontSize + 'px monospace';

        for (var i = 0; i < drops.length; i++) {
            var text = chars[Math.floor(Math.random() * chars.length)];
            ctx.fillText(text, i * fontSize, drops[i] * fontSize);
            if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                drops[i] = 0;
            }
            drops[i]++;
        }
    }

    setInterval(draw, 50);
}
