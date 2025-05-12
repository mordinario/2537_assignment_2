// Image names
let images = ["yisang.jpg", "faust.jpg", "donqui.jpg", "ryoshu.jpg",
              "meursault.jpg", "honglu.jpg", "heathcliff.jpg", "ishmael.jpg",
              "rodion.jpg", "sinclair.jpg", "outis.jpg", "gregor.jpg"];
// Element IDs
let ids    = ["first_img", "second_img", "third_img"];

for(let i = 0; i < ids.length; i++)
{
    // Get random character
    let index = Math.floor(Math.random() * images.length);
    // Show it on screen
    document.getElementById(ids[i]).src = "img/" + images[index];
    // Remove character from array
    images.splice(index, 1);
}