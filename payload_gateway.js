const gateway_send = {
  transaction: "",
  device_id: 2001,
  batt: 0, // 0-100 %
  temp: 0, // °C
  charge: 0, // 0-1
  volt_in: 0, // V
  current_in: 0, //mA
  volt_out: 0, // V
  current_out: 0, //mA
  batt_volt: 0, //V
  capacity: 0, // Ah
  batt_health: 0, // 0-100 %
  cycle_count: 0, //count
  timestamp: "20250917 172400",
};

// Ctrl = 0; // online // 0-1
// Ctrl = 1; // bright // 0-100 %
// Ctrl = 2; // status // 0-1
// Ctrl = 10; // batt  // 0-100 %
// Ctrl = 11; // temp // °C
// Ctrl = 12; // charge // 0-1
// Ctrl = 13; // volt_in // V
// Ctrl = 14; // current_in //mA
// Ctrl = 15; // volt_out // V
// Ctrl = 16; // current_out //mA
// Ctrl = 17; // batt_volt //V
// Ctrl = 18; // capacity // Ah
// Ctrl = 19; // batt_health // 0-100 %
// Ctrl = 20; // cycle_count //count
