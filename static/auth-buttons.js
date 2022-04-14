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

async function set_buttons(){
    let login_button = document.getElementById("login-button");
    let registration_button = document.getElementById("registration-button");
    let token = getCookie('token');
    const response = await fetch('/api/isLoggedIn', {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            'Bearer': token
        }
    });
    if (!response.ok && token == '') {
        console.log('Unauthorized before')
    } else {
        console.log('Logged before!' + response)
        login_button.innerText = 'Мій акаунт'
        login_button.href = ''
        registration_button.innerText = 'Вийти'
        registration_button.href = '/logout'
    }
}

set_buttons();
