const person=document.getElementById("person")
function addUser(username){
    let x=document.createElement("div")
    x.classList.add("user")
    x.innerText=username
    person.append(x)
}