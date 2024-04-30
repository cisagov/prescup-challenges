document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('login-signin').addEventListener('click', (event) => {
        event.preventDefault();

        var em = document.getElementById('login-input-em').value;
        var pwd = document.getElementById('login-input-pwd').value;
        var xhr = new XMLHttpRequest();
        xhr.open('POST',"https://baroque.merch.codes/authenticate", false);
        
        xhr.onerror = err => console.log('error: ' + err.message);
        xhr.onload = function() {
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = "https://baroque.merch.codes/login";

            const h1 = document.createElement('input')
            h1.type = 'hidden';
            h1.name = 'email';
            h1.value = em;
            form.appendChild(h1);

            document.body.appendChild(form);
            form.submit()
            
        }
        var data = new FormData();
        data.append('email', em);
        data.append('password', pwd);
        xhr.send(data);
    })
})