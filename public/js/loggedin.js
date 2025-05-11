function getImage()
{
    let images = ["yisang.jpg", "faust.jpg", "donqui.jpg", "ryoshu.jpg",
                  "meursault.jpg", "honglu.jpg", "heathcliff.jpg", "ishmael.jpg",
                  "rodion.jpg", "sinclair.jpg", "outis.jpg", "gregor.jpg"];
    document.getElementById("image").src = "img/" + images[Math.floor(Math.random() * images.length)];
};

getImage();