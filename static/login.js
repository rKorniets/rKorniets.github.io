async function login(){
    const username = document.getElementById("username-form").value;
    const password = document.getElementById("password-form").value;
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
        const json = await response.json();
        const token = json.token;
        console.log('Token received:' + json.token);
        document.cookie = 'token=' + token;
        window.open("/", "_self");
    }
}