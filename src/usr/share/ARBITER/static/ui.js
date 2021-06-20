function managerPanelClear(isFull) {
    if (isFull == true) {
        document.getElementById("empty-manage-hint").style.display = "none";
    }
    else {
        document.getElementById("empty-manage-hint").style.display = "initial";
    }
    document.getElementById("add-agent").style.display = "none";
    document.getElementById("selected-agent").style.display = "none";
    document.getElementById("manage-directives").style.display = "none";
}

function managerPanelAddAgent() {
    managerPanelClear(true);
    document.getElementById("add-agent").style.display = "initial";
}

function managerPanelCreateAlert(isError, alertMessage) {
    let template = `
<div class="alert" style="background-color: {{ color }}">
    <span class="closebtn" onclick="this.parentElement.style.display='none';">&times;</span>   
    <strong>[{{ status }}]</strong> {{ message }}
</div>`;
    let alertColor = "var(--blue);";
    let alertStatus = "Success";
    if (isError == true) {
        alertColor = "var(--red);";
        alertStatus = "Failure";
    }
    nunjucks.configure({autoescape: false});
    document.getElementById("manager-errors").innerHTML += nunjucks.renderString(template, {color: alertColor, status: alertStatus, message: alertMessage});
}
