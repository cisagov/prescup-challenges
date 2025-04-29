`use strict`;

var opcua = require("node-opcua");
var config = require("./config.json");
var modbusHandler = require("./modbushandler")


var server = new opcua.OPCUAServer({
    port: config.port,
    resourcePath: config.url
});

server.buildInfo.productName = "ModbusUAServer";
server.buildInfo.buildNumber = "1";
server.buildInfo.buildDate = new Date();


server.initialize(
    function () {
        console.log("OPC UA Server initialized");
        construct_address_space();
        server.start(function () {
            console.log("Server is now listening...");
        });
    }
);

function construct_address_space() {
    var devicesnode = server.engine.addressSpace.addFolder("RootFolder", { browseName: "Modbus Devices" });
    config.modbusdevices.forEach(
        function (device) {
            modbusHandler.CreateModbusDevice(device.modbushost, device.modbusport, device.unit);
            var dnodefname = device.modbushost + ":" + device.modbusport + " unit: " + device.unit;
            console.log("creating folder: " + dnodefname)
            var dnode = server.engine.addressSpace.addFolder(
                devicesnode, { browseName: dnodefname }
            );
            device.deviceaddressspace.forEach(function (info) {
                console.log("Creating folder: " + info.type);
                var registertype = server.engine.addressSpace.addFolder(
                    dnode, { browseName: info.type }
                );
                info.addresses.forEach(function (ainfo) {
                    create_modbus_variables(modbusHandler, dnode.browseName + registertype.browseName, registertype, info.type, ainfo.address, ainfo.count, device);
                });
            });
        });
}

function create_modbus_variables(modbushandler, rootname, register, type, address, count, device) {
   var StartAddress = address;
   if(device.onebased && address>0){
       StartAddress = address - 1;
   } else if(address==0){
       console.log("Can not apply the onebased mode with a starting address of 0");
   }
   else if(address<0){
       console.log("address is invalid, starting address must be a positive number if in onebased mode, otherwise address can be 0 or more");
       return;
   }
    modbushandler.StartPoll(rootname, type, StartAddress, count, device.pollrate);
    for (var i = 0; i < count; i++) {
        //console.log("creating variable: " + (address + count).toString());
        var node = function (register,type,address, i) {
            var servernode = {
                componentOf: register,
                browseName: (address + i).toString(),
                minimumSamplingInterval: device.pollrate,
                dataType: modbushandler.GetDataTypeString(type),
                value: {
                    get: function () {
                        return modbushandler.ReadValue(rootname + (StartAddress + i).toString());
                    },
                    set: function (variant) {
                        modbushandler.WriteValue(type, StartAddress +i,variant);
                        return opcua.StatusCodes.Good;
                    }
                }
            }
            return servernode;
        } (register,type,address, i);
        server.engine.addressSpace.addVariable(node);
    }
}


