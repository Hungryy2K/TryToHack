(function() {
    'use strict';
    window.addEventListener('DOMContentLoaded', () => {
        includeHTML();
    });
    let shoppingCart = [];
    function setupEventListeners() {
        document.getElementById('overlayContinueBtn')?.addEventListener('click', removeWidget);
        document.getElementById('overlayPayBtn')?.addEventListener('click', () => alert('Du sollst doch den anderen Button hacken! 😉'));


        document.getElementById('loginForm')?.addEventListener('submit', (event) => {
            event.preventDefault();
            login();
        });

        document.getElementById('decryptForm')?.addEventListener('submit', (event) => {
            event.preventDefault();
            decryptArticle();
        });

        document.querySelectorAll('.add-to-cart-btn').forEach(button => {
            button.addEventListener('click', () => {
                const itemElement = button.closest('.shopping-item');
                const name = itemElement.dataset.itemName;
                const price = parseFloat(itemElement.dataset.itemPrice);
                addToCart(name, price);
            });
        });

        document.querySelectorAll('.checkout-btn').forEach(button => {
            button.addEventListener('click', checkoutCart);
        });
    }


    function login() {
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;

        if (username === 'Junus' && password === 'StrengGeheim!') {
            window.location.href = './login-success.html';
        } else {
            alert('Passwort falsch!');
        }
    }

    function addToCart(item, price) {
        shoppingCart.push({ amount: 1, item: item, price: price });
        renderCart();
    }

    function decryptArticle() {
        const enteredPassword = document.getElementById('password').value;
        const encryptedPassword = sha256(enteredPassword);
        if (encryptedPassword === 'e78c46d45241892f95c27a76b6b37e2a75af2acef4e5391d58e113f33bf0521e') {
            const decryptCard = document.getElementById('decryptCard');
            decryptCard.innerHTML = `<p>${decrypt('82-111-124-132-118-115-109-114-111-120-42-81-118-262-109-117-129-127-120-125-109-114-43-42-78-127-42-114-107-125-126-42-110-107-125-42-90-107-125-125-129-121-124-126-42-111-124-112-121-118-113-124-111-115-109-114-42-113-111-114-107-109-117-126-43-70-108-124-72-84-111-126-132-126-42-108-115-125-126-42-110-127-42-111-115-120-42-121-112-112-115-132-115-111-118-118-111-124-42-82-107-109-117-111-124-43-42-78-115-111-125-111-42-75-127-112-113-107-108-111-42-129-107-124-42-111-114-124-118-115-109-114-42-113-111-125-107-113-126-42-120-115-109-114-126-42-113-107-120-132-42-111-115-120-112-107-109-114-56-42-78-107-125-42-94-111-107-119-42-110-111-124-42-78-111-128-111-118-121-122-111-124-42-75-117-107-110-111-119-115-111-42-115-125-126-42-125-126-121-118-132-54-42-129-111-120-120-42-110-127-42-110-115-111-125-111-42-75-127-112-113-107-108-111-42-125-111-118-108-125-126-125-126-238-120-110-115-113-42-113-111-118-256-125-126-42-114-107-125-126-56')}</p>`;
        } else {
            alert('Versuche es erneut!');
        }
    }

    function checkoutCart() {
        const sum = shoppingCart.map(i => i.price).reduce((ac, a) => ac + a, 0);
        const totalPrice = sum + 4.99;
        if (totalPrice <= 0) {
            alert('Herzlichen Glückwunsch! Du hast uns gehackt!!');
            if (typeof confetti === 'function') {
              confetti({ particleCount: 100, spread: 70, origin: { y: 0.6 } });
            }
        } else {
            alert('Die Gesamtsumme beträgt ' + totalPrice.toFixed(2) + '€');
        }
    }

    function renderCart() {
        const orderedItems = document.getElementById('orderedItems');
        if (!orderedItems) return;
        orderedItems.innerHTML = '';
        let sum = 0;

        if (shoppingCart.length === 0) {
            orderedItems.innerHTML = '<div class="mb-8">Der Einkaufswagen ist leer</div>';
            return;
        }

        shoppingCart.forEach((elem) => {
            orderedItems.innerHTML += `
                <div class="space-between mb-8">
                    <div>${elem.amount}x ${elem.item}</div>
                    <div>${elem.price.toFixed(2)}€</div>
                </div>`;
            sum += elem.price;
        });

        orderedItems.innerHTML += `
            <div class="space-between mb-8 mt-8"><b>Gesamtsumme</b> <div>${sum.toFixed(2)}€</div></div>
            <div class="space-between mb-8"><b>Versandkosten</b> <div>${4.99}€</div></div>
            <div class="space-between mb-8"><b>Total</b> <div>${(sum + 4.99).toFixed(2)}€</div></div>`;
    }

    function removeWidget() {
        document.getElementById('overlayWidget')?.remove();
    }

    function decrypt(value) {
        return value.split("-").map(char => String.fromCharCode(char - 10)).join('');
    }

    function includeHTML() {
        const elements = document.querySelectorAll("[w3-include-html]");
        let promises = [];

        elements.forEach(el => {
            const file = el.getAttribute("w3-include-html");
            if (file) {
                const promise = fetch(file)
                    .then(response => {
                        if (response.status === 200) return response.text();
                        if (response.status === 404) return "Page not found.";
                        return "Error loading file.";
                    })
                    .then(data => {
                        el.innerHTML = data;
                        el.removeAttribute("w3-include-html");
                    });
                promises.push(promise);
            }
        });
        
        Promise.all(promises).then(() => {
            setupEventListeners();
        });
    }

})();