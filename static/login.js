async function login(){
    let username = document.getElementById("username-form").value;
    let password = document.getElementById("password-form").value;
    const url = '/User/login'
    const response = await fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Basic ' + btoa(username + ":" + password)
        }
    });
    if (!response.ok){
        alert("Wrong credentials!")
        console.log("Wrong credentials!")
    }
    else{
        let json = await response.json();
        let token = json.token;
        console.log('Token received:' + json.token);
        document.cookie = 'token=' + token;
        window.open("/", "_self");
    }
}