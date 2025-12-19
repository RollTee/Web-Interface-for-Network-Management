// back.js
const snmp = require("net-snmp");
const fs = require("fs");
const path = require("path");
const express = require("express");
const csv = require("csv-parser");
const { createObjectCsvWriter } = require("csv-writer");
const cors = require("cors");




const app = express();
const PORT = 3001;




/* ===================== CONFIG ===================== */




const COMMUNITY = "management";
const POLL_INTERVAL = 5000; // 5 sec
const MAX_LOGS = 25000;




const DEVICE_IP = "10.20.1.254";




// Device inventory for multi-target queries (edit to match your network)
const DEVICES = [
  { name: "Router_Cisco_1800", ip: "192.168.100.2", role: "router" },
  { name: "Router_Cisco_2800", ip: "192.168.100.1", role: "router" },
  { name: "Switch_Catalyst_3560G", ip: "192.168.200.2", role: "l3-switch" },
  { name: "Switch_Catalyst_2960", ip: "10.99.1.2", role: "l2-switch" },
];




app.use(cors());
app.use(express.json());




/* ===================== OIDS (GROUP 2) ===================== */




/* system */
const SYS_OIDS = {
  sysName: "1.3.6.1.2.1.1.5.0",
  sysUpTime: "1.3.6.1.2.1.1.3.0",
};




/* icmp */
const ICMP_OIDS = {
  inEchos: "1.3.6.1.2.1.5.8.0",
  inEchoReps: "1.3.6.1.2.1.5.14.0",
  outEchos: "1.3.6.1.2.1.5.21.0",
  outEchoReps: "1.3.6.1.2.1.5.22.0",
};




/* ipRouteTable */
const IP_ROUTE_BASE = "1.3.6.1.2.1.4.21";




/* ===================== CSV SETUP ===================== */


const icmpCsv = path.join(__dirname, "icmp_logs.csv");
const routeCsv = path.join(__dirname, "ipRouteTable.csv");


const ICMP_CSV_HEADERS = [
  "Timestamp",
  "IP",
  "SysName",
  "SysUpTime",
  "ICMP_In_Echos",
  "ICMP_In_Echo_Replies",
  "ICMP_Out_Echos",
  "ICMP_Out_Echo_Replies",
];


const ROUTE_CSV_HEADERS = [
  "Timestamp",
  "IP",
  "Destination",
  "Mask",
  "NextHop",
  "IfIndex",
];


function ensureCsvWithHeader(filePath, headers) {
  try {
    if (!fs.existsSync(filePath)) {
      fs.writeFileSync(filePath, `${headers.join(",")}\n`, "utf8");
    }
  } catch (e) {
    console.error(`❌ Failed to init CSV ${filePath}:`, e && e.message ? e.message : e);
  }
}




const icmpWriter = createObjectCsvWriter({
  path: icmpCsv,
  header: [
    { id: "timestamp", title: "Timestamp" },
    { id: "ip", title: "IP" },
    { id: "sysName", title: "SysName" },
    { id: "sysUpTime", title: "SysUpTime" },
    { id: "inEchos", title: "ICMP_In_Echos" },
    { id: "inEchoReps", title: "ICMP_In_Echo_Replies" },
    { id: "outEchos", title: "ICMP_Out_Echos" },
    { id: "outEchoReps", title: "ICMP_Out_Echo_Replies" },
  ],
  append: true,
});




const routeWriter = createObjectCsvWriter({
  path: routeCsv,
  header: [
    { id: "timestamp", title: "Timestamp" },
    { id: "ip", title: "IP" },
    { id: "dest", title: "Destination" },
    { id: "mask", title: "Mask" },
    { id: "nextHop", title: "NextHop" },
    { id: "ifIndex", title: "IfIndex" },
  ],
  append: true,
});




let logCount = 0;




/* ===================== SNMP FUNCTIONS ===================== */




// ฟังก์ชัน GET - ดึงค่า OID เฉพาะ (รองรับ IP เป้าหมาย)
function snmpGet(targetIp, oid, callback) {
  const ip = targetIp || DEVICE_IP;
  const session = snmp.createSession(ip, COMMUNITY, { timeout: 5000 });
 
  const timeoutHandle = setTimeout(() => {
    session.close();
    callback(new Error(`SNMP timeout: No response from ${ip}`), null);
  }, 6000);




  session.get([oid], (err, vb) => {
    clearTimeout(timeoutHandle);
    session.close();
    if (err) {
      callback(err, null);
    } else if (!vb || !vb[0]) {
      callback(new Error("Invalid response from SNMP agent"), null);
    } else {
      callback(null, vb[0]);
    }
  });
}
// ฟังก์ชัน GET NEXT - ดึง OID ถัดไป (รองรับ IP เป้าหมาย)
function snmpGetNext(targetIp, oid, callback) {
  const ip = targetIp || DEVICE_IP;
  const session = snmp.createSession(ip, COMMUNITY, { timeout: 5000 });
 
  const timeoutHandle = setTimeout(() => {
    session.close();
    callback(new Error(`SNMP timeout: No response from ${ip}`), null);
  }, 6000);




  session.getNext([oid], (err, vb) => {
    clearTimeout(timeoutHandle);
    session.close();
    if (err) {
      callback(err, null);
    } else if (!vb || !vb[0]) {
      callback(new Error("Invalid response from SNMP agent"), null);
    } else {
      callback(null, vb[0]);
    }
  });
}




// ฟังก์ชัน GET BULK - ดึง OID หลายตัวครั้งเดียว (เร็วกว่า) (รองรับ IP เป้าหมาย)
function snmpGetBulk(targetIp, oid, maxRepetitions = 10, callback) {
  const ip = targetIp || DEVICE_IP;
  const session = snmp.createSession(ip, COMMUNITY, { timeout: 5000 });
 
  const timeoutHandle = setTimeout(() => {
    session.close();
    callback(new Error(`SNMP timeout: No response from ${ip}`), null);
  }, 6000);




  session.getBulk(0, maxRepetitions, [oid], (err, vb) => {
    clearTimeout(timeoutHandle);
    session.close();
    if (err) {
      callback(err, null);
    } else if (!vb || vb.length === 0) {
      callback(new Error("No data returned from SNMP agent"), null);
    } else {
      callback(null, vb);
    }
  });
}




/* ===================== SNMP POLL ===================== */


let icmpPollInProgress = false;
let routePollInProgress = false;




function pollICMP() {
  if (icmpPollInProgress) return;
  icmpPollInProgress = true;


  const oids = [
    SYS_OIDS.sysName,
    SYS_OIDS.sysUpTime,
    ICMP_OIDS.inEchos,
    ICMP_OIDS.inEchoReps,
    ICMP_OIDS.outEchos,
    ICMP_OIDS.outEchoReps,
  ];




  Promise.all(
    DEVICES.map(
      (dev) =>
        new Promise((resolve) => {
          const session = snmp.createSession(dev.ip, COMMUNITY);
          session.on("error", (err) => {
            console.error(`SNMP Session Error (${dev.ip}):`, err?.message || err);
            try {
              session.close();
            } catch {}
            resolve();
          });


          session.get(oids, async (err, vb) => {
            if (err) {
              console.error(`SNMP Error (${dev.ip}):`, err.message);
              session.close();
              return resolve();
            }


            const record = {
              timestamp: new Date().toISOString(),
              ip: dev.ip,
              sysName: vb[0]?.value?.toString?.() ?? "",
              sysUpTime: vb[1]?.value ?? 0,
              inEchos: vb[2]?.value ?? 0,
              inEchoReps: vb[3]?.value ?? 0,
              outEchos: vb[4]?.value ?? 0,
              outEchoReps: vb[5]?.value ?? 0,
            };


            try {
              await icmpWriter.writeRecords([record]);
              logCount++;


              if (logCount >= MAX_LOGS) {
                console.warn("⚠️ Log limit reached (20,000)");
              }


              console.log(`✅ ICMP logged from ${dev.ip}`);
            } catch (writeErr) {
              console.error(`❌ ICMP CSV write error (${dev.ip}):`, writeErr?.message || writeErr);
            } finally {
              session.close();
              resolve();
            }
          });
        })
    )
  )
    .catch(() => {})
    .finally(() => {
      icmpPollInProgress = false;
    });
}




/* ===================== ROUTE TABLE POLL ===================== */


function formatIpValue(value) {
  if (Buffer.isBuffer(value) && value.length === 4) {
    return Array.from(value).join(".");
  }
  if (Array.isArray(value) && value.length === 4 && value.every((v) => Number.isInteger(v))) {
    return value.join(".");
  }
  if (value && typeof value === "object" && typeof value.toString === "function") {
    return value.toString();
  }
  return String(value ?? "");
}


function parseIpRouteOid(oid) {
  const prefix = `${IP_ROUTE_BASE}.1.`;
  if (!oid || typeof oid !== "string" || !oid.startsWith(prefix)) return null;
  const rest = oid.slice(prefix.length); // <column>.<index...>
  const parts = rest.split(".");
  if (parts.length < 2) return null;
  const column = Number(parts[0]);
  if (!Number.isFinite(column)) return null;
  const index = parts.slice(1).join(".");
  return { column, index };
}




async function pollRouteTable() {
  if (routePollInProgress) return;
  routePollInProgress = true;


  try {
    const allRecords = [];


    await Promise.all(
      DEVICES.map(
        (dev) =>
          new Promise((resolve) => {
            const session = snmp.createSession(dev.ip, COMMUNITY, { timeout: 5000 });
            const rowsByIndex = new Map();


            session.on("error", (err) => {
              console.error(`❌ Route walk error from ${dev.ip}:`, err?.message || err);
              try {
                session.close();
              } catch {}
              resolve();
            });


            console.log(`🔍 Starting route table walk for ${dev.ip}...`);


            session.subtree(
              IP_ROUTE_BASE,
              (varbinds) => {
                if (!Array.isArray(varbinds)) {
                  console.warn(`⚠️  Invalid varbinds from ${dev.ip}`);
                  return;
                }


                console.log(`📦 Received ${varbinds.length} varbinds from ${dev.ip}`);


                for (const vb of varbinds) {
                  const parsed = vb?.oid ? parseIpRouteOid(vb.oid) : null;
                  if (!parsed) continue;


                  const { column, index } = parsed;
                  const current = rowsByIndex.get(index) || { dest: "", mask: "", nextHop: "", ifIndex: "" };


                  switch (column) {
                    case 1:
                      current.dest = formatIpValue(vb.value);
                      break;
                    case 2:
                      current.ifIndex = String(vb.value ?? "");
                      break;
                    case 7:
                      current.nextHop = formatIpValue(vb.value);
                      break;
                    case 11:
                      current.mask = formatIpValue(vb.value);
                      break;
                    default:
                      break;
                  }


                  rowsByIndex.set(index, current);
                }
              },
              (err) => {
                if (err) {
                  console.error(`❌ Route subtree walk error from ${dev.ip}:`, err?.message || err);
                  session.close();
                  resolve();
                  return;
                }


                const timestamp = new Date().toISOString();
                const deviceRecords = Array.from(rowsByIndex.values())
                  .filter((r) => r.dest)
                  .map((r) => ({
                    timestamp,
                    ip: dev.ip,
                    dest: r.dest,
                    mask: r.mask || "-",
                    nextHop: r.nextHop || "-",
                    ifIndex: r.ifIndex || "-",
                  }));


                if (deviceRecords.length > 0) {
                  allRecords.push(...deviceRecords);
                  console.log(`✅ Route table polled from ${dev.ip} (${deviceRecords.length} rows)`);
                } else {
                  console.warn(`⚠️  No route data found for ${dev.ip}`);
                }


                session.close();
                resolve();
              }
            );
          })
      )
    );


    console.log(`📝 Total route records collected: ${allRecords.length}`);


    if (allRecords.length > 0) {
      try {
        // Overwrite with latest snapshot (all devices)
        await routeWriter.writeRecords(allRecords);
        console.log(`✅ Successfully wrote ${allRecords.length} route records to CSV`);
      } catch (writeErr) {
        console.error("❌ Route CSV write error:", writeErr?.message || writeErr);
      }
    } else {
      console.warn("⚠️  No route records to write - CSV will remain empty or with headers only");
    }
  } finally {
    routePollInProgress = false;
  }
}




/* ===================== AUTO POLL ===================== */




// Ensure CSV files exist before any API reads (prevents crashes on missing files)
ensureCsvWithHeader(icmpCsv, ICMP_CSV_HEADERS);
ensureCsvWithHeader(routeCsv, ROUTE_CSV_HEADERS);


// Initial poll on startup
console.log("🔄 Starting initial poll...");
pollICMP();
pollRouteTable();


setInterval(() => {
  pollICMP();
  pollRouteTable();
}, POLL_INTERVAL);




/* ===================== API ===================== */




app.get("/status", (req, res) => {
  res.json({
    server: "SNMP Network Management Server",
    ip: DEVICE_IP,
    logs: logCount,
    files: {
      icmp: icmpCsv,
      route: routeCsv,
    },
  });
});




app.get("/stats/:field", (req, res) => {
  const values = [];




  fs.createReadStream(icmpCsv)
    .pipe(csv())
    .on("data", row => {
      if (row[req.params.field])
        values.push(Number(row[req.params.field]));
    })
    .on("end", () => {
      res.json({
        current: values.at(-1),
        average: values.reduce((a, b) => a + b, 0) / values.length,
        max: Math.max(...values),
        min: Math.min(...values),
      });
    });
});




// Get all ICMP logs
app.get("/api/icmp-logs", (req, res) => {
  if (!fs.existsSync(icmpCsv)) return res.json([]);
  const logs = [];
  fs.createReadStream(icmpCsv)
    .pipe(csv())
    .on("data", row => logs.push(row))
    .on("end", () => res.json(logs))
    .on("error", () => res.json([]));
});




// Get all route table logs
app.get("/api/route-logs", (req, res) => {
  if (!fs.existsSync(routeCsv)) return res.json([]);
  const logs = [];
  fs.createReadStream(routeCsv)
    .pipe(csv())
    .on("data", row => logs.push(row))
    .on("end", () => res.json(logs))
    .on("error", () => res.json([]));
});




/* ===================== SNMP GET/GETNEXT APIs ===================== */




// API สำหรับ GET OID เฉพาะ
// ตัวอย่าง: GET /api/snmp/get?oid=1.3.6.1.2.1.1.5.0
app.get("/api/snmp/get", (req, res) => {
  const oid = req.query.oid;
  const ip = req.query.ip || DEVICE_IP;
  if (!oid) {
    return res.status(400).json({ error: "OID is required" });
  }




  snmpGet(ip, oid, (err, result) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({
      oid: result.oid,
      value: result.value.toString(),
      type: result.type
    });
  });
});




// API สำหรับ GET NEXT
// ตัวอย่าง: GET /api/snmp/getnext?oid=1.3.6.1.2.1.1.5
app.get("/api/snmp/getnext", (req, res) => {
  const oid = req.query.oid;
  const ip = req.query.ip || DEVICE_IP;
  if (!oid) {
    return res.status(400).json({ error: "OID is required" });
  }




  snmpGetNext(ip, oid, (err, result) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({
      oid: result.oid,
      value: result.value.toString(),
      type: result.type
    });
  });
});




// API สำหรับ GET BULK (ดึงหลายตัวพร้อมกัน)
// ตัวอย่าง: GET /api/snmp/getbulk?oid=1.3.6.1.2.1.1&maxreps=10
app.get("/api/snmp/getbulk", (req, res) => {
  const oid = req.query.oid;
  const maxReps = parseInt(req.query.maxreps) || 10;
  const ip = req.query.ip || DEVICE_IP;
 
  if (!oid) {
    return res.status(400).json({ error: "OID is required" });
  }




  snmpGetBulk(ip, oid, maxReps, (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    const data = results.map(vb => ({
      oid: vb.oid,
      value: vb.value.toString(),
      type: vb.type
    }));
    res.json(data);
  });
});




// รายการอุปกรณ์ให้ UI ดึงไปแสดง
app.get("/api/devices", (req, res) => {
  res.json(DEVICES);
});




app.listen(PORT, () => {
  console.log(`✅ SNMP Server running on http://localhost:${PORT}`);
});




// Global error logging to diagnose unexpected exits
process.on('uncaughtException', (err) => {
  console.error('❌ Uncaught Exception:', err && err.stack || err);
});




process.on('unhandledRejection', (reason) => {
  console.error('❌ Unhandled Rejection:', reason);
});

























