var socket = io();
var tableDataCache = [];

socket.on("eventUpdate", data => {
    if (data["type"] == "TEXT") {
        /* set value for textarea and textContent for paragraphs */
        document.getElementById(data["id"]).value = data["data"];
        document.getElementById(data["id"]).textContent = data["data"];
    }
    else if (data["type"] == "TABLE") {
        /* scripting for populating target table */
        document.getElementById(data["id"]).innerHTML = "";
        for (row in data["data"]) {
            tableRow = document.createElement("tr");
            for (column in data["data"][row]) {
                tableRow.innerHTML += ("<td>" + data["data"][row][column] + "</td>");
            }
            /* add select button to all agents */
            tableRow.innerHTML += ('<td><button onclick="' + "select('" + data["data"][row][0] + "');" + '">Select</button></td>'); 
            document.getElementById(data["id"]).appendChild(tableRow);
        }
        tableDataCache = data["data"];
    }
});

socket.on("logError", data => {
    document.getElementById("errors").style.display = "initial";
    document.getElementById("error-log").innerHTML += "<p>[" + data["timestamp"] + "]: " + data["message"] + "</p>";
});

function dispatchCommand(command, type, payload) {
    socket.emit("command", {"command": command, "requestType": type, "payload": payload});
}

function addAgent() {
    document.getElementById("empty-manage-hint").style.display = "none";
}

function select(uuid) {
    /* todo */
}
