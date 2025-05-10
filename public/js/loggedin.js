async function getName()
{
    const res = await fetch('/getName');
    const session = await res.json();
    console.log(session);
    if(session.name)
    {
        document.getElementById("name").innerText += " " + session.name + "!";
    }
}

function getImage()
{
    let images = ["yisang.jpg", "faust.jpg", "donqui.jpg", "ryoshu.jpg",
                  "meursault.jpg", "honglu.jpg", "heathcliff.jpg", "ishmael.jpg",
                  "rodion.jpg", "sinclair.jpg", "outis.jpg", "gregor.jpg"];
    document.getElementById("image").src = "img/" + images[Math.floor(Math.random() * images.length)];
};

getName();
getImage();