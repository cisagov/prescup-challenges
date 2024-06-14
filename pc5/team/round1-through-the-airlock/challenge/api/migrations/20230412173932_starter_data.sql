-- Copyright 2024 Carnegie Mellon University.
-- Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
-- root or contact permission@sei.cmu.edu for full terms.

-- Airlocks.
INSERT INTO airlock_controls (id) VALUES ('docking');
INSERT INTO airlock_controls (id) VALUES ('aft');
INSERT INTO airlock_controls (id) VALUES ('port');
INSERT INTO airlock_controls (id) VALUES ('cargo');

-- Cameras.
INSERT INTO camera_controls (id) VALUES ('controlroom_1');
INSERT INTO camera_controls (id) VALUES ('controlroom_2');
INSERT INTO camera_controls (id) VALUES ('controlroom_3');
INSERT INTO camera_controls (id) VALUES ('controlroom_4');

INSERT INTO camera_controls (id) VALUES ('controlroom_hallway_1');
INSERT INTO camera_controls (id) VALUES ('controlroom_hallway_2');

INSERT INTO camera_controls (id) VALUES ('bridge_1');
INSERT INTO camera_controls (id) VALUES ('bridge_2');
INSERT INTO camera_controls (id) VALUES ('bridge_3');

INSERT INTO camera_controls (id) VALUES ('bridge_hallway_1');
INSERT INTO camera_controls (id) VALUES ('bridge_hallway_2');
INSERT INTO camera_controls (id) VALUES ('bridge_hallway_3');

INSERT INTO camera_controls (id) VALUES ('quarters_hallway_1');
INSERT INTO camera_controls (id) VALUES ('quarters_hallway_2');
INSERT INTO camera_controls (id) VALUES ('quarters_hallway_3');
INSERT INTO camera_controls (id) VALUES ('quarters_hallway_4');
INSERT INTO camera_controls (id) VALUES ('quarters_hallway_5');
INSERT INTO camera_controls (id) VALUES ('quarters_hallway_6');
INSERT INTO camera_controls (id) VALUES ('quarters_hallway_7');
INSERT INTO camera_controls (id) VALUES ('quarters_hallway_8');
INSERT INTO camera_controls (id) VALUES ('quarters_hallway_9');
INSERT INTO camera_controls (id) VALUES ('quarters_hallway_10');
INSERT INTO camera_controls (id) VALUES ('quarters_hallway_11');
INSERT INTO camera_controls (id) VALUES ('quarters_hallway_12');
INSERT INTO camera_controls (id) VALUES ('quarters_hallway_13');
INSERT INTO camera_controls (id) VALUES ('quarters_hallway_14');
INSERT INTO camera_controls (id) VALUES ('quarters_hallway_15');
INSERT INTO camera_controls (id) VALUES ('quarters_hallway_16');

INSERT INTO camera_controls (id) VALUES ('mess_1');
INSERT INTO camera_controls (id) VALUES ('mess_2');
INSERT INTO camera_controls (id) VALUES ('mess_3');
INSERT INTO camera_controls (id) VALUES ('mess_4');

INSERT INTO camera_controls (id) VALUES ('mess_hallway_1');
INSERT INTO camera_controls (id) VALUES ('mess_hallway_2');

INSERT INTO camera_controls (id) VALUES ('medbay_1');
INSERT INTO camera_controls (id) VALUES ('medbay_2');

INSERT INTO camera_controls (id) VALUES ('medbay_hallway_1');
INSERT INTO camera_controls (id) VALUES ('medbay_hallway_2');
INSERT INTO camera_controls (id) VALUES ('medbay_hallway_3');

INSERT INTO camera_controls (id) VALUES ('engineering_1');
INSERT INTO camera_controls (id) VALUES ('engineering_2');
INSERT INTO camera_controls (id) VALUES ('engineering_3');
INSERT INTO camera_controls (id) VALUES ('engineering_4');
INSERT INTO camera_controls (id) VALUES ('engineering_5');
INSERT INTO camera_controls (id) VALUES ('engineering_6');

INSERT INTO camera_controls (id) VALUES ('engineering_hallway_1');
INSERT INTO camera_controls (id) VALUES ('engineering_hallway_2');
INSERT INTO camera_controls (id) VALUES ('engineering_hallway_3');
INSERT INTO camera_controls (id) VALUES ('engineering_hallway_4');

INSERT INTO camera_controls (id) VALUES ('sciencelab_1');
INSERT INTO camera_controls (id) VALUES ('sciencelab_2');
INSERT INTO camera_controls (id) VALUES ('sciencelab_3');

INSERT INTO camera_controls (id) VALUES ('sciencelab_hallway_1');

INSERT INTO camera_controls (id) VALUES ('cargohold_1');
INSERT INTO camera_controls (id) VALUES ('cargohold_2');
INSERT INTO camera_controls (id) VALUES ('cargohold_3');
INSERT INTO camera_controls (id) VALUES ('cargohold_4');
INSERT INTO camera_controls (id) VALUES ('cargohold_5');
INSERT INTO camera_controls (id) VALUES ('cargohold_6');

INSERT INTO camera_controls (id) VALUES ('cargohold_hallway_1');
INSERT INTO camera_controls (id) VALUES ('cargohold_hallway_2');

INSERT INTO camera_controls (id) VALUES ('recreation_1');
INSERT INTO camera_controls (id) VALUES ('recreation_2');
INSERT INTO camera_controls (id) VALUES ('recreation_3');
INSERT INTO camera_controls (id) VALUES ('recreation_4');

INSERT INTO camera_controls (id) VALUES ('recreation_hallway_1');
INSERT INTO camera_controls (id) VALUES ('recreation_hallway_2');

INSERT INTO camera_controls (id) VALUES ('observationdeck_1');
INSERT INTO camera_controls (id) VALUES ('observationdeck_2');
INSERT INTO camera_controls (id) VALUES ('observationdeck_3');

INSERT INTO camera_controls (id) VALUES ('observationdeck_hallway_1');
INSERT INTO camera_controls (id) VALUES ('observationdeck_hallway_2');
INSERT INTO camera_controls (id) VALUES ('observationdeck_hallway_3');

INSERT INTO camera_controls (id) VALUES ('airlock_docking');
INSERT INTO camera_controls (id) VALUES ('airlock_aft');
INSERT INTO camera_controls (id) VALUES ('airlock_port');
INSERT INTO camera_controls (id) VALUES ('airlock_cargo');

INSERT INTO camera_controls (id) VALUES ('maintenancebay_port_1');
INSERT INTO camera_controls (id) VALUES ('maintenancebay_port_2');
INSERT INTO camera_controls (id) VALUES ('maintenancebay_port_3');

INSERT INTO camera_controls (id) VALUES ('maintenancebay_port_hallway_1');

INSERT INTO camera_controls (id) VALUES ('maintenancebay_starboard_1');
INSERT INTO camera_controls (id) VALUES ('maintenancebay_starboard_2');
INSERT INTO camera_controls (id) VALUES ('maintenancebay_starboard_3');

INSERT INTO camera_controls (id) VALUES ('maintenancebay_starboard_hallway_1');
INSERT INTO camera_controls (id) VALUES ('maintenancebay_starboard_hallway_2');

-- Environment controls.
INSERT INTO environment_controls (id) VALUES ('controlroom');
INSERT INTO environment_controls (id) VALUES ('bridge');
INSERT INTO environment_controls (id) VALUES ('mess');
INSERT INTO environment_controls (id, temperature) VALUES ('medbay', 20);
INSERT INTO environment_controls (id, temperature) VALUES ('engineering', 20);
INSERT INTO environment_controls (id, temperature) VALUES ('sciencelab', 20);
INSERT INTO environment_controls (id) VALUES ('recreation');
INSERT INTO environment_controls (id) VALUES ('observationdeck');
INSERT INTO environment_controls (id) VALUES ('maintenancebay_port');
INSERT INTO environment_controls (id) VALUES ('maintenancebay_starboard');

-- Individual crew members.
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_1', 23);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_2', 22);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_3', 22);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_4', 23);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_5', 23);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_6', 23);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_7', 22);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_8', 24);
INSERT INTO environment_controls (id) VALUES ('quarters_9');
INSERT INTO environment_controls (id) VALUES ('quarters_10');
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_11', 23);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_12', 23);
INSERT INTO environment_controls (id) VALUES ('quarters_13');
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_14', 22);
INSERT INTO environment_controls (id) VALUES ('quarters_15');
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_16', 22);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_17', 22);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_18', 23);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_19', 20);
INSERT INTO environment_controls (id) VALUES ('quarters_20');
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_21', 20);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_22', 22);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_23', 22);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_24', 23);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_25', 20);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_26', 23);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_27', 24);
INSERT INTO environment_controls (id) VALUES ('quarters_28');
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_29', 23);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_30', 20);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_31', 22);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_32', 22);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_33', 24);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_34', 22);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_35', 22);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_36', 23);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_37', 20);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_38', 23);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_39', 23);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_40', 23);
INSERT INTO environment_controls (id) VALUES ('quarters_41');
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_42', 22);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_43', 23);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_44', 24);
INSERT INTO environment_controls (id) VALUES ('quarters_45');
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_46', 23);
INSERT INTO environment_controls (id) VALUES ('quarters_47');
INSERT INTO environment_controls (id) VALUES ('quarters_48');
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_49', 20);
INSERT INTO environment_controls (id) VALUES ('quarters_50');
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_51', 22);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_52', 23);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_53', 24);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_54', 22);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_55', 23);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_56', 20);
INSERT INTO environment_controls (id) VALUES ('quarters_57');
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_58', 23);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_59', 24);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_60', 22);
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_61', 22);
INSERT INTO environment_controls (id) VALUES ('quarters_62');
INSERT INTO environment_controls (id, temperature) VALUES ('quarters_63', 24);
INSERT INTO environment_controls (id) VALUES ('quarters_64');

-- Power.
INSERT INTO power_controls (id) VALUES ('primary');
INSERT INTO power_controls (id, active) VALUES ('emergency', false);

-- Comms.
INSERT INTO comm_controls (id) VALUES ('controlroom');
INSERT INTO comm_controls (id) VALUES ('bridge');
INSERT INTO comm_controls (id) VALUES ('mess');
INSERT INTO comm_controls (id) VALUES ('medbay');
INSERT INTO comm_controls (id) VALUES ('engineering');
INSERT INTO comm_controls (id) VALUES ('sciencelab');
INSERT INTO comm_controls (id, active) VALUES ('cargohold', false);
INSERT INTO comm_controls (id) VALUES ('recreation');
INSERT INTO comm_controls (id) VALUES ('observationdeck');
INSERT INTO comm_controls (id) VALUES ('airlock_aft');
INSERT INTO comm_controls (id) VALUES ('airlock_port');
INSERT INTO comm_controls (id) VALUES ('airlock_cargo');
INSERT INTO comm_controls (id) VALUES ('airlock_docking');
INSERT INTO comm_controls (id) VALUES ('maintenancebay_port');
INSERT INTO comm_controls (id) VALUES ('maintenancebay_starboard');
INSERT INTO comm_controls (id) VALUES ('quarters_1');
INSERT INTO comm_controls (id) VALUES ('quarters_2');
INSERT INTO comm_controls (id) VALUES ('quarters_3');
INSERT INTO comm_controls (id) VALUES ('quarters_4');
INSERT INTO comm_controls (id) VALUES ('quarters_5');
INSERT INTO comm_controls (id) VALUES ('quarters_6');
INSERT INTO comm_controls (id) VALUES ('quarters_7');
INSERT INTO comm_controls (id) VALUES ('quarters_8');
INSERT INTO comm_controls (id) VALUES ('quarters_9');
INSERT INTO comm_controls (id) VALUES ('quarters_10');
INSERT INTO comm_controls (id) VALUES ('quarters_11');
INSERT INTO comm_controls (id) VALUES ('quarters_12');
INSERT INTO comm_controls (id) VALUES ('quarters_13');
INSERT INTO comm_controls (id) VALUES ('quarters_14');
INSERT INTO comm_controls (id) VALUES ('quarters_15');
INSERT INTO comm_controls (id) VALUES ('quarters_16');
INSERT INTO comm_controls (id) VALUES ('quarters_17');
INSERT INTO comm_controls (id) VALUES ('quarters_18');
INSERT INTO comm_controls (id) VALUES ('quarters_19');
INSERT INTO comm_controls (id) VALUES ('quarters_20');
INSERT INTO comm_controls (id) VALUES ('quarters_21');
INSERT INTO comm_controls (id) VALUES ('quarters_22');
INSERT INTO comm_controls (id) VALUES ('quarters_23');
INSERT INTO comm_controls (id) VALUES ('quarters_24');
INSERT INTO comm_controls (id) VALUES ('quarters_25');
INSERT INTO comm_controls (id) VALUES ('quarters_26');
INSERT INTO comm_controls (id) VALUES ('quarters_27');
INSERT INTO comm_controls (id) VALUES ('quarters_28');
INSERT INTO comm_controls (id) VALUES ('quarters_29');
INSERT INTO comm_controls (id) VALUES ('quarters_30');
INSERT INTO comm_controls (id) VALUES ('quarters_31');
INSERT INTO comm_controls (id) VALUES ('quarters_32');
INSERT INTO comm_controls (id) VALUES ('quarters_33');
INSERT INTO comm_controls (id) VALUES ('quarters_34');
INSERT INTO comm_controls (id) VALUES ('quarters_35');
INSERT INTO comm_controls (id) VALUES ('quarters_36');
INSERT INTO comm_controls (id) VALUES ('quarters_37');
INSERT INTO comm_controls (id) VALUES ('quarters_38');
INSERT INTO comm_controls (id) VALUES ('quarters_39');
INSERT INTO comm_controls (id) VALUES ('quarters_40');
INSERT INTO comm_controls (id) VALUES ('quarters_41');
INSERT INTO comm_controls (id) VALUES ('quarters_42');
INSERT INTO comm_controls (id) VALUES ('quarters_43');
INSERT INTO comm_controls (id) VALUES ('quarters_44');
INSERT INTO comm_controls (id) VALUES ('quarters_45');
INSERT INTO comm_controls (id) VALUES ('quarters_46');
INSERT INTO comm_controls (id) VALUES ('quarters_47');
INSERT INTO comm_controls (id) VALUES ('quarters_48');
INSERT INTO comm_controls (id) VALUES ('quarters_49');
INSERT INTO comm_controls (id) VALUES ('quarters_50');
INSERT INTO comm_controls (id) VALUES ('quarters_51');
INSERT INTO comm_controls (id) VALUES ('quarters_52');
INSERT INTO comm_controls (id) VALUES ('quarters_53');
INSERT INTO comm_controls (id) VALUES ('quarters_54');
INSERT INTO comm_controls (id) VALUES ('quarters_55');
INSERT INTO comm_controls (id) VALUES ('quarters_56');
INSERT INTO comm_controls (id) VALUES ('quarters_57');
INSERT INTO comm_controls (id) VALUES ('quarters_58');
INSERT INTO comm_controls (id) VALUES ('quarters_59');
INSERT INTO comm_controls (id) VALUES ('quarters_60');
INSERT INTO comm_controls (id) VALUES ('quarters_61');
INSERT INTO comm_controls (id) VALUES ('quarters_62');
INSERT INTO comm_controls (id) VALUES ('quarters_63');
INSERT INTO comm_controls (id) VALUES ('quarters_64');

-- Doors.
INSERT INTO door_controls (id) VALUES ('controlroom');
INSERT INTO door_controls (id) VALUES ('bridge');
INSERT INTO door_controls (id) VALUES ('mess');
INSERT INTO door_controls (id) VALUES ('medbay');
INSERT INTO door_controls (id) VALUES ('engineering');
INSERT INTO door_controls (id) VALUES ('sciencelab');
INSERT INTO door_controls (id) VALUES ('cargobay');
INSERT INTO door_controls (id) VALUES ('recreation');
INSERT INTO door_controls (id) VALUES ('observationdeck');
INSERT INTO door_controls (id) VALUES ('maintenancebay_port');
INSERT INTO door_controls (id) VALUES ('maintenancebay_starboard');
INSERT INTO door_controls (id) VALUES ('quarters_1');
INSERT INTO door_controls (id) VALUES ('quarters_2');
INSERT INTO door_controls (id) VALUES ('quarters_3');
INSERT INTO door_controls (id) VALUES ('quarters_4');
INSERT INTO door_controls (id) VALUES ('quarters_5');
INSERT INTO door_controls (id) VALUES ('quarters_6');
INSERT INTO door_controls (id) VALUES ('quarters_7');
INSERT INTO door_controls (id) VALUES ('quarters_8');
INSERT INTO door_controls (id) VALUES ('quarters_9');
INSERT INTO door_controls (id) VALUES ('quarters_10');
INSERT INTO door_controls (id) VALUES ('quarters_11');
INSERT INTO door_controls (id) VALUES ('quarters_12');
INSERT INTO door_controls (id) VALUES ('quarters_13');
INSERT INTO door_controls (id) VALUES ('quarters_14');
INSERT INTO door_controls (id) VALUES ('quarters_15');
INSERT INTO door_controls (id) VALUES ('quarters_16');
INSERT INTO door_controls (id) VALUES ('quarters_17');
INSERT INTO door_controls (id) VALUES ('quarters_18');
INSERT INTO door_controls (id) VALUES ('quarters_19');
INSERT INTO door_controls (id) VALUES ('quarters_20');
INSERT INTO door_controls (id) VALUES ('quarters_21');
INSERT INTO door_controls (id) VALUES ('quarters_22');
INSERT INTO door_controls (id) VALUES ('quarters_23');
INSERT INTO door_controls (id) VALUES ('quarters_24');
INSERT INTO door_controls (id) VALUES ('quarters_25');
INSERT INTO door_controls (id) VALUES ('quarters_26');
INSERT INTO door_controls (id) VALUES ('quarters_27');
INSERT INTO door_controls (id) VALUES ('quarters_28');
INSERT INTO door_controls (id) VALUES ('quarters_29');
INSERT INTO door_controls (id) VALUES ('quarters_30');
INSERT INTO door_controls (id) VALUES ('quarters_31');
INSERT INTO door_controls (id) VALUES ('quarters_32');
INSERT INTO door_controls (id) VALUES ('quarters_33');
INSERT INTO door_controls (id) VALUES ('quarters_34');
INSERT INTO door_controls (id) VALUES ('quarters_35');
INSERT INTO door_controls (id) VALUES ('quarters_36');
INSERT INTO door_controls (id) VALUES ('quarters_37');
INSERT INTO door_controls (id) VALUES ('quarters_38');
INSERT INTO door_controls (id) VALUES ('quarters_39');
INSERT INTO door_controls (id) VALUES ('quarters_40');
INSERT INTO door_controls (id) VALUES ('quarters_41');
INSERT INTO door_controls (id) VALUES ('quarters_42');
INSERT INTO door_controls (id) VALUES ('quarters_43');
INSERT INTO door_controls (id) VALUES ('quarters_44');
INSERT INTO door_controls (id) VALUES ('quarters_45');
INSERT INTO door_controls (id) VALUES ('quarters_46');
INSERT INTO door_controls (id) VALUES ('quarters_47');
INSERT INTO door_controls (id) VALUES ('quarters_48');
INSERT INTO door_controls (id) VALUES ('quarters_49');
INSERT INTO door_controls (id) VALUES ('quarters_50');
INSERT INTO door_controls (id) VALUES ('quarters_51');
INSERT INTO door_controls (id) VALUES ('quarters_52');
INSERT INTO door_controls (id) VALUES ('quarters_53');
INSERT INTO door_controls (id) VALUES ('quarters_54');
INSERT INTO door_controls (id) VALUES ('quarters_55');
INSERT INTO door_controls (id) VALUES ('quarters_56');
INSERT INTO door_controls (id) VALUES ('quarters_57');
INSERT INTO door_controls (id) VALUES ('quarters_58');
INSERT INTO door_controls (id) VALUES ('quarters_59');
INSERT INTO door_controls (id) VALUES ('quarters_60');
INSERT INTO door_controls (id) VALUES ('quarters_61');
INSERT INTO door_controls (id) VALUES ('quarters_62');
INSERT INTO door_controls (id) VALUES ('quarters_63');
INSERT INTO door_controls (id) VALUES ('quarters_64');

-- Hydroponics
INSERT INTO hydroponics_controls (id) VALUES ('hydroponics_1');
INSERT INTO hydroponics_controls (id) VALUES ('hydroponics_2');
INSERT INTO hydroponics_controls (id) VALUES ('hydroponics_3');
INSERT INTO hydroponics_controls (id) VALUES ('hydroponics_4');
INSERT INTO hydroponics_controls (id) VALUES ('hydroponics_5');
INSERT INTO hydroponics_controls (id) VALUES ('hydroponics_6');
INSERT INTO hydroponics_controls (id) VALUES ('hydroponics_7');
INSERT INTO hydroponics_controls (id) VALUES ('hydroponics_8');
INSERT INTO hydroponics_controls (id) VALUES ('hydroponics_9');
INSERT INTO hydroponics_controls (id) VALUES ('hydroponics_10');
INSERT INTO hydroponics_controls (id) VALUES ('hydroponics_11');
INSERT INTO hydroponics_controls (id) VALUES ('hydroponics_12');
INSERT INTO hydroponics_controls (id) VALUES ('hydroponics_13');
INSERT INTO hydroponics_controls (id) VALUES ('hydroponics_14');
INSERT INTO hydroponics_controls (id) VALUES ('hydroponics_15');
INSERT INTO hydroponics_controls (id) VALUES ('hydroponics_16');
INSERT INTO hydroponics_controls (id) VALUES ('hydroponics_17');
INSERT INTO hydroponics_controls (id) VALUES ('hydroponics_18');
INSERT INTO hydroponics_controls (id) VALUES ('hydroponics_19');
INSERT INTO hydroponics_controls (id) VALUES ('hydroponics_20');
INSERT INTO hydroponics_controls (id) VALUES ('hydroponics_21');
INSERT INTO hydroponics_controls (id) VALUES ('hydroponics_22');
INSERT INTO hydroponics_controls (id) VALUES ('hydroponics_23');
INSERT INTO hydroponics_controls (id) VALUES ('hydroponics_24');
