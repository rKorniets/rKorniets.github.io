function getCookie(cname) {
  let name = cname + "=";
  let decodedCookie = decodeURIComponent(document.cookie);
  let ca = decodedCookie.split(';');
  for(let i = 0; i <ca.length; i++) {
    let c = ca[i];
    while (c.charAt(0) == ' ') {
      c = c.substring(1);
    }
    if (c.indexOf(name) == 0) {
      return c.substring(name.length, c.length);
    }
  }
  return "";
}

async function log_out() {
    let token = getCookie('token');
    let response = await fetch('/User/logout', {
        method: 'GET',
        headers: {
            'Bearer': token
        }
    });

    if (response.status == 200) {
        document.cookie = "token=;";
        alert("You have been logged out.");
        window.location.href = "/";
    }
    else {
        alert("Something went wrong.");
    }
}

async function set_buttons(){
    const login_button = document.getElementById("login-button");
    const registration_button = document.getElementById("registration-button");
    const token = getCookie('token');
    const response = await fetch('/api/isLoggedIn', {
        method: 'GET',
        headers: {
            'Bearer': token,
            'Content-Type': 'application/json'
        }
    });
    if (!response.ok) {
        console.log('Unauthorized before')
    } else {
        console.log('Logged before!' + response)
        login_button.innerText = 'Мій акаунт'
        login_button.href = ''
        registration_button.innerText = 'Вийти'
        registration_button.removeAttribute('href');
        registration_button.onclick = function(){log_out()};
    }
}

set_buttons();

