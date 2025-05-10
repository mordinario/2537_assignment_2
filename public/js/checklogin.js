// Gets the authentication status of this session
async function getAuth()
{
    // Fetch the session's status
    const res = await fetch('/getAuth');
    const auth = await res.json();
    var firstButton = document.getElementById("firstButton");
    var secondButton = document.getElementById("secondButton");
    // If auth status exists
    if(auth.auth != 'None')
    {
        // Display menu page for authenticated user
        document.getElementById("welcome").innerText = "Welcome! You're authenticated.";
        firstButton.onclick = ()=>window.location.replace('/loggedin');
        firstButton.innerText = "Go to Members Page";
        secondButton.onclick = ()=>window.location.replace('/logout');
        secondButton.innerText = "Log Out";
    }
    else
    {
        // Display menu page for unauthenticated user
        firstButton.onclick = ()=>window.location.replace('/signup');
        firstButton.innerText = "Sign Up";
        secondButton.onclick = ()=>window.location.replace('/login');
        secondButton.innerText = "Log In";
    }
}
// Call the function
getAuth();