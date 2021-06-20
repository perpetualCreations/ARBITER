var socket = io();
var tableDataCache = [];

socket.on("eventUpdate", data => {
    if (data["type"] == "STATE") {
        if (data["id"] == "add-agent") {
            if (Boolean(data["data"]) == true) {
                managerPanelCreateAlert(false, "A user-defined agent was found, and was referred to an ARBITER server.")
                document.getElementById("add-agent-input-host").value = "";
            }
            else {
                managerPanelCreateAlert(true, "A user-defined agent could not be found.")
            }
            document.getElementById("add-agent-connect-button").classList.remove("disabled");
            document.getElementById("add-agent-cancel-button").classList.remove("disabled");
            document.getElementById("add-agent-waiting-message").style.display = "none";
        }
    }
    else if (data["type"] == "TABLE") {
        // scripting for populating target table
        document.getElementById(data["id"]).innerHTML = "";
        for (row in data["data"]) {
            tableRow = document.createElement("tr");
            for (column in data["data"][row]) {
                if (data["data"][row][column] == null) {
                    data["data"][row][column] = "";
                }
                tableRow.innerHTML += ("<td>" + data["data"][row][column] + "</td>");
            }
            if (data["id"] == "agents-table-content") {
                // add select button to all agents
                tableRow.innerHTML += ('<td><button onclick="' + "select('" + data["data"][row][0] + "');" + '">Select</button></td>'); 
                document.getElementById(data["id"]).appendChild(tableRow);
                // when table content is for agents, cache into variable
                tableDataCache = data["data"];
            }
        }
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
    dispatchCommand("ADD_AGENT", "PAYLOAD", document.getElementById("add-agent-input-host").value);
    document.getElementById("add-agent-connect-button").classList.add("disabled");
    document.getElementById("add-agent-cancel-button").classList.add("disabled");
    document.getElementById("add-agent-waiting-message").style.display = "initial";
}

function select(uuid) {
    managerPanelClear(true);
    let template = `
<h3>{{ agentNameAndUUID }}</h3>
<p>{{ agentDirective }}</p>
<p>{{ agentDirectiveType }}</p>
<p>{{ agentConnectionStatus }}</p>
    `
    // class add/remove spam, next time create a dummy class for buttons that are connection dependent, and select elements by that class
    document.getElementById("selected-agent-stop-directive-button").classList.add("disabled");
    document.getElementById("selected-agent-start-directive-button").classList.add("disabled");
    document.getElementById("selected-agent-restart-directive-button").classList.add("disabled");
    document.getElementById("selected-agent-disconnect-button").classList.add("disabled");
    for (row in tableDataCache) {
        if (tableDataCache[row][0] == uuid) {
            document.getElementById("selected-agent").style.display = "initial";
            let connectionStatus = "Disconnected";
            if (tableDataCache[row][4] == true) {
                document.getElementById("selected-agent-stop-directive-button").classList.remove("disabled");
                document.getElementById("selected-agent-start-directive-button").classList.remove("disabled");
                document.getElementById("selected-agent-restart-directive-button").classList.remove("disabled");
                document.getElementById("selected-agent-disconnect-button").classList.remove("disabled");
                connectionStatus = "Connected";
            }
            nunjucks.configure({autoescape: false});
            document.getElementById("selected-agent-data").innerHTML = nunjucks.renderString(template, 
                {
                    agentNameAndUUID: tableDataCache[row][0] + ", " + tableDataCache[row][1],
                    agentDirective: "Directive: " + tableDataCache[row][2],
                    agentDirectiveType: "Directive Type: " + tableDataCache[row][3],
                    agentConnectionStatus: "Status: " + connectionStatus
                });
        }
    }
}
