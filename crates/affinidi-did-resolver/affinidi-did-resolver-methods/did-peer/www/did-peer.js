import init, * as wasm from "./pkg/did_peer.js";

init().then(() => {
    console.log("Wasm module loaded");
});

var keyRows = 0;
var serviceRows = 0;

window.initialize = function initialize() {
    addKeyRow();
    addServiceRow(true);
}

window.clearBox = function clearBox(elementID) {
    document.getElementById(elementID).innerHTML = "";
    toggleHighlight(elementID, false);
}

window.toggleHighlight = function toggleHighlight(elementId, on) {
    var el = document.getElementById(elementId);

    el.style['display'] = on ? 'block' : 'none';
}

window.addKeyRow = function addKeyRow() {
    if (keyRows > 0) {
        // remove previous buttons
        document.getElementById("add_key_row").remove();
        if (document.getElementById("delete_key_row")) {
            document.getElementById("delete_key_row").remove();
        }
    }

    keyRows++;
    var table = document.querySelector('#new-keys');
    var row = table.insertRow(-1);
    var cell1 = row.insertCell(0);
    var cell2 = row.insertCell(1);
    var cell3 = row.insertCell(2);
    var cell4 = row.insertCell(3);
    var cell5 = row.insertCell(4);
    cell1.innerHTML = '#key-' + keyRows;
    cell2.innerHTML = '<select name="keys-purpose-' + keyRows + '" id="keys-purpose-' + keyRows + '" required><option value="verification">Verification</option><option value="encryption">Encryption</option></select>';
    cell3.innerHTML = '<select name="keys-type-' + keyRows + '" id="keys-type-' + keyRows + '" required><option value="ed25519">Ed25519</option><option value="secp256k1">Secp256K1</option><option value="p256">P256</option></select>';
    cell4.innerHTML = '<input type="text" id="keys-multibase-' + keyRows + '" name="keys-multibase-' + keyRows + '" placeholder="-- auto creates keys if blank --" size="52">';
    cell5.innerHTML = '<button id="add_key_row" onclick="addKeyRow()">Add another key?</button>' + (keyRows != 1 ? '&ensp;<button style="background-color: red;" id="delete_key_row" onclick="deleteKeyRow()">Delete Key ?</button>' : '');

}

window.deleteKeyRow = function deleteKeyRow() {
    if (keyRows > 0) {
        document.getElementById("add_key_row").remove();
        document.getElementById("delete_key_row").remove();
        document.getElementById("new-keys").deleteRow(-1);
        keyRows--;

        // Add buttons back
        var table = document.querySelector('#new-keys');
        var row = table.rows[table.rows.length - 1];
        var cell = row.cells[row.cells.length - 1];
        cell.innerHTML = '<button id="add_key_row" onclick="addKeyRow()">Add another key?</button>' + (keyRows != 1 ? '&ensp;<button style="background-color: red;" id="delete_key_row" onclick="deleteKeyRow()">Delete Key?</button>' : '');
    }
}

window.addServiceRow = function addServiceRow(initialize = false) {

    var table = document.querySelector('#new-services');

    if (initialize) {
        // No services, so add a button to create and return
        var row = table.insertRow(-1);
        row.insertCell(0).innerHTML = '<button id="add_service_row" onclick="addServiceRow()">Add service?</button>';
        return;
    }
    if (serviceRows == 0) {
        // Need to delete the first row and add a header row
        table.deleteRow(-1);
        var row = table.insertRow(-1);

        row.insertCell(0).innerHTML = '<b>Service ID</b>';
        row.insertCell(1).innerHTML = '<b>Type</b>';
        row.insertCell(2).innerHTML = '<b>URI</b>';
        row.insertCell(3).innerHTML = '<b>Accept</b>';
        row.insertCell(4).innerHTML = '<b>Routing Keys</b>';
    }
    if (serviceRows > 0) {
        // remove previous buttons
        document.getElementById("add_service_row").remove();
        if (document.getElementById("delete_service_row")) {
            document.getElementById("delete_service_row").remove();
        }
    }

    serviceRows++;
    var row = table.insertRow(-1);
    var cell1 = row.insertCell(0);
    var cell2 = row.insertCell(1);
    var cell3 = row.insertCell(2);
    var cell4 = row.insertCell(3);
    var cell5 = row.insertCell(4);
    var cell6 = row.insertCell(5);
    cell1.innerHTML = '#service' + (serviceRows > 1 ? "-" + (serviceRows - 1) : "");
    cell2.innerHTML = 'DIDCommMessaging';
    cell3.innerHTML = '<input type="text" id="service-uri-' + serviceRows + '" name="service-uri-' + serviceRows + '" value="https://127.0.0.1:7037" size="20">';
    cell4.innerHTML = '<input type="text" id="service-accept-' + serviceRows + '" name="service-accept-' + serviceRows + '" value="didcomm/v2;" size="30">';
    cell5.innerHTML = '<input type="text" id="service-routing-' + serviceRows + '" name="service-routing-' + serviceRows + '" placeholder="-- did:peer:2...#key-id; --" size="40">';
    cell6.innerHTML = '<button id="add_service_row" onclick="addServiceRow()">Add another service?</button>&ensp;<button style="background-color: red;" id="delete_service_row" onclick="deleteServiceRow()">Delete Service?</button>';
}

window.deleteServiceRow = function deleteServiceRow() {
    if (serviceRows > 0) {
        document.getElementById("add_service_row").remove();
        document.getElementById("delete_service_row").remove();
        document.getElementById("new-services").deleteRow(-1);
        serviceRows--;

        if (serviceRows == 0) {
            // re-initialize the services table
            document.getElementById("new-services").deleteRow(-1);
            addServiceRow(true);
        } else {
            // Add buttons back to previous row
            var table = document.querySelector('#new-services');
            var row = table.rows[table.rows.length - 1];
            var cell = row.cells[row.cells.length - 1];
            cell.innerHTML = '<button id="add_service_row" onclick="addServiceRow()">Add another service?</button>&ensp;<button style="background-color: red;" id="delete_service_row" onclick="deleteServiceRow()">Delete Service?</button>';
        }
    }
}

window.copyDid = function copyDid(id) {
    // Get the text field
    var copyText = document.getElementById(id);


    // Copy the text inside the text field
    navigator.clipboard.writeText(copyText.innerHTML);

}

window.resolveDID = function resolveDID() {
    let did = document.getElementById('did_resolve').value;
    try {
        wasm.resolve_did_peer(did).then((didDocument) => {
            if (didDocument == undefined) {
                console.log("ERROR");
            } else {
                let test = JSON.parse(didDocument);
                document.getElementById("resolve-result").innerHTML = "<pre>" + JSON.stringify(test, null, 2) + "</pre>";
                toggleHighlight("resolve-result", true);
            }
        }).catch((e) => {
            document.getElementById("resolve-result").innerHTML = e;
            toggleHighlight("resolve-result", true);
        })
    } catch (e) {
        console.log(e);
    }
}

window.createDID = function createDID() {
    // create an array of keys specified
    var table = document.querySelector('#new-keys');
    var rows = table.rows;
    let keys = [];
    // We start at 1 as this table has a header.
    for (let i = 1; i < rows.length; i++) {
        let keyPurpose = 0;
        let e = document.getElementById('keys-purpose-' + i);
        let v = e.value;
        switch (e.options[e.selectedIndex].text) {
            case "Verification":
                keyPurpose = wasm.DIDPeerKeys.Verification;
                break;
            case "Encryption":
                keyPurpose = wasm.DIDPeerKeys.Encryption;
                break;
            default:
                console.log("ERROR");
        }

        let keyType = 0;
        e = document.getElementById('keys-type-' + i);
        v = e.value;
        switch (e.options[e.selectedIndex].text) {
            case "Ed25519":
                keyType = wasm.DIDPeerKeyType.Ed25519;
                break;
            case "Secp256K1":
                keyType = wasm.DIDPeerKeyType.Secp256k1;
                break;
            case "P256":
                keyType = wasm.DIDPeerKeyType.P256;
                break;

            default:
                console.log("ERROR");
        }
        let multibase = document.getElementById('keys-multibase-' + i).value;
        keys.push(new wasm.DIDPeerCreateKeys(keyPurpose, keyType, multibase == "" ? null : multibase));
    }

    // create a list of services specified
    table = document.querySelector('#new-services');
    rows = table.rows;
    let services = [];
    // We start at 1 as this table has a header.
    for (let i = 1; i < rows.length; i++) {
        var t = document.getElementById('service-uri-' + i);
        let v = t.value;
        let uri = document.getElementById('service-uri-' + i).value;
        let accept = String(document.getElementById('service-accept-' + i).value).replace(/;+$/, "").split(";");
        let rk = String(document.getElementById('service-routing-' + i).value);
        let routingKeys = rk == "" ? [] : rk.split(";");
        services.push(new wasm.DIDService(uri, accept, routingKeys));
    }

    let result = wasm.create_did_peer(new wasm.DidPeerCreate(keys, services));
    document.getElementById("create-result-did").innerHTML = "<b>Peer DID Identifier</b><br><br>" + result.did + '<br><br>';
    toggleHighlight("create-result-did", true);

    document.getElementById("create-result-keys").innerHTML = "<b>Private Key Materials</b><br>";
    let e = document.getElementById("create-result-keys");
    e.innerHTML = '<table id="key-table"></table>';
    table = document.getElementById("key-table");
    for (let i = 0; i < result.keys.length; i++) {
        if (i > 0) {
            table.insertRow().insertCell(0).innerHTML = "<br>";

        }

        let row = table.insertRow();
        let cell = row.insertCell(0);
        cell.innerHTML = "<b>Key ID</b>";
        cell = row.insertCell(1);
        cell.innerHTML = "<b>#key-" + (i + 1) + '<br>';

        row = table.insertRow();
        cell = row.insertCell(0);
        cell.innerHTML = "<b>Multibase Key</b>";
        cell = row.insertCell(1);
        cell.innerHTML = result.keys[i].key_multibase;

        row = table.insertRow();
        cell = row.insertCell(0);
        cell.innerHTML = "<b>Curve</b>";
        cell = row.insertCell(1);
        cell.innerHTML = result.keys[i].curve;

        row = table.insertRow();
        cell = row.insertCell(0);
        cell.innerHTML = "<b>Private Key (d)</b>";
        cell = row.insertCell(1);
        cell.innerHTML = result.keys[i].d;

        row = table.insertRow();
        cell = row.insertCell(0);
        cell.innerHTML = "<b>Public Key (x)</b>";
        cell = row.insertCell(1);
        cell.innerHTML = result.keys[i].x;

        if (result.keys[i].y != null) {
            row = table.insertRow();
            cell = row.insertCell(0);
            cell.innerHTML = "<b>Public Key (y)</b>";
            cell = row.insertCell(1);
            cell.innerHTML = result.keys[i].y;
        }
    }
    toggleHighlight("create-result-keys", true);
}