// Wi-Fi AC remote: an ESP32/ESP8266 + IR LED that you control from your phone's browser.
// Uses IRremoteESP8266's IRac class, which speaks the full-state protocols of 80+ AC brands.

#include <Arduino.h>
#if defined(ESP8266)
#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
typedef ESP8266WebServer WebServerT;
#else
#include <WiFi.h>
#include <WebServer.h>
typedef WebServer WebServerT;
#endif
#include <IRremoteESP8266.h>
#include <IRac.h>
#include <IRutils.h>

// ---- Settings -------------------------------------------------------------
const uint16_t kIrLedPin = 4;            // GPIO driving the IR LED (via transistor)
const char *kApName = "AC-Remote";       // Wi-Fi network the board creates
const char *kApPass = "coolbreeze";      // min 8 chars; "" for an open network
// ---------------------------------------------------------------------------

#include "page.h"

IRac ac(kIrLedPin);
WebServerT server(80);

stdAc::opmode_t parseMode(const String &m) {
  if (m == "cool") return stdAc::opmode_t::kCool;
  if (m == "heat") return stdAc::opmode_t::kHeat;
  if (m == "dry") return stdAc::opmode_t::kDry;
  if (m == "fan") return stdAc::opmode_t::kFan;
  return stdAc::opmode_t::kAuto;
}

stdAc::fanspeed_t parseFan(const String &f) {
  if (f == "low") return stdAc::fanspeed_t::kLow;
  if (f == "medium") return stdAc::fanspeed_t::kMedium;
  if (f == "high") return stdAc::fanspeed_t::kHigh;
  return stdAc::fanspeed_t::kAuto;
}

void handleProtocols() {
  String json = "[";
  bool first = true;
  for (int i = 0; i <= kLastDecodeType; i++) {
    decode_type_t p = (decode_type_t)i;
    if (!IRac::isProtocolSupported(p)) continue;
    if (!first) json += ",";
    json += "\"" + typeToString(p) + "\"";
    first = false;
  }
  json += "]";
  server.send(200, "application/json", json);
}

// /send?brand=DAIKIN&model=-1&power=1&mode=cool&temp=24&fan=auto&swing=1&turbo=0&eco=0
void handleSend() {
  decode_type_t proto = strToDecodeType(server.arg("brand").c_str());
  if (!IRac::isProtocolSupported(proto)) {
    server.send(400, "text/plain", "Unsupported brand");
    return;
  }
  ac.next.protocol = proto;
  ac.next.model = server.hasArg("model") ? server.arg("model").toInt() : -1;
  ac.next.power = server.arg("power") == "1";
  ac.next.mode = parseMode(server.arg("mode"));
  ac.next.celsius = true;
  ac.next.degrees = constrain(server.arg("temp").toFloat(), 16, 30);
  ac.next.fanspeed = parseFan(server.arg("fan"));
  ac.next.swingv = server.arg("swing") == "1" ? stdAc::swingv_t::kAuto
                                              : stdAc::swingv_t::kOff;
  ac.next.swingh = stdAc::swingh_t::kOff;
  ac.next.turbo = server.arg("turbo") == "1";
  ac.next.econo = server.arg("eco") == "1";
  ac.next.light = true;
  ac.next.beep = true;
  ac.next.quiet = false;
  ac.next.filter = false;
  ac.next.clean = false;
  ac.next.sleep = -1;
  ac.next.clock = -1;
  ac.sendAc();
  server.send(200, "text/plain", "OK");
}

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_AP);
  WiFi.softAP(kApName, kApPass);
  Serial.print("Join Wi-Fi \"");
  Serial.print(kApName);
  Serial.print("\" and open http://");
  Serial.println(WiFi.softAPIP());

  server.on("/", []() { server.send_P(200, "text/html", kPage); });
  server.on("/protocols", handleProtocols);
  server.on("/send", handleSend);
  server.begin();
}

void loop() { server.handleClient(); }
