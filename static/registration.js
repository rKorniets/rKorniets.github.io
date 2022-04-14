async function register(){
    let username = document.getElementsByName("login")[0].value;
    let password1 = document.getElementsByName("password")[0].value;
    let password2 = document.getElementsByName("password")[0].value;
    let email = document.getElementsByName("email")[0].value;
    const url = '/User'
    if (password1 != password2){
        return false;
    }

    let data = {
        'username': username,
        'password': password1,
        'email': email
    }

    const response = await fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(data)
    });

    if (response.ok){
        window.location.replace("/signin")
    }
}