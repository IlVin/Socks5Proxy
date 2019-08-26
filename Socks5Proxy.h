#pragma once

#include <cctype>
#include <client.h>
#include <Arduino.h>
#include <ArduinoJson.h>
#include "IPAddress.h"

#ifndef UNSECURE_CLIENT
#include <ESP8266WiFi.h>
#include <WiFiClientSecure.h> 
#include <ESP8266WebServer.h>
#define UNSECURE_CLIENT WiFiClient
#endif

#ifndef SOCKS5_TIMEOUT
#define SOCKS5_TIMEOUT 30000
#endif


class Socks5Proxy : public Client {
private:
    Client & client;
    IPAddress socks5Host;
    uint16_t socks5Port;
    UNSECURE_CLIENT s5Client; 

public:
    Socks5Proxy (IPAddress proxyIP, uint16_t proxyPort, Client & client)
        : client(client)
        , socks5Host(proxyIP)
        , socks5Port(proxyPort){
    }  

    virtual int connect(IPAddress destIp, uint16_t destPort){
        Serial.println("Socks5Proxy: connect with destIP");
        int s5ConnectResult = client.connect(socks5Host, socks5Port);
        if (!s5ConnectResult){
            return s5ConnectResult;
        }
        Serial.println("Socks5Proxy: connected to Socks5");
        return Socks5ConnectToDestination(destIp, destPort);
    }

    virtual int connect(const char* destHost, uint16_t destPort){
        Serial.println("Socks5Proxy: connect with destHost");
        int s5ConnectResult = client.connect(socks5Host, socks5Port);
        if (!s5ConnectResult){
            return s5ConnectResult;
        }
        Serial.println("Socks5Proxy: connected to Socks5");
        return Socks5ConnectToDestination(destHost, destPort);
    }
    virtual size_t write(uint8_t data){
        return client.write(data);
    }
    virtual size_t write(const uint8_t* buf, size_t size){
        return client.write(buf, size);
    }
    virtual int available(){
        return client.available();
    }
    virtual int read(){
        return client.read();
    }
    virtual int read(uint8_t* buf, size_t size){
        return client.read(buf, size);
    }
    virtual int peek(){
        return client.peek();
    }
    virtual void flush(){
        client.flush();
    }
    virtual void stop(){
        client.stop();
    }
    virtual uint8_t connected(){
        return client.connected();
    }
    virtual operator bool(){
        return client == true;
    }

protected:
    int Socks5ConnectToDestination(const char* destHost, uint16_t& destPort){
        if (!Socks5Auth() 
            || !Socks5ConnectByHost(destHost, destPort)) {
            return 0;
        }
        return Socks5ConnectResponse();
    }
    
    int Socks5ConnectToDestination(IPAddress destIp, uint16_t destPort){
        if (!Socks5Auth() || !Socks5ConnectByIp(destIp, destPort)) {
            return 0;
        }
        return Socks5ConnectResponse();
    }

    size_t WriteAll(Client& cl, const uint8_t* buf, size_t size) {
        size_t offs = 0;
        unsigned long sTime = millis();
        while ((offs < size) && (SOCKS5_TIMEOUT > millis() - sTime)) {
            offs += cl.write((const uint8_t*)&buf[offs], size - offs);
            yield();
        }
        return offs;
    }

    size_t ReadAll(Client& cl, const uint8_t* buf, size_t size) {
        size_t offs = 0;
        unsigned long sTime = millis();
        while ((offs < size) && (SOCKS5_TIMEOUT > millis() - sTime)) {
            offs += cl.read((uint8_t*)&buf[offs], size - offs);
            yield();
        }
        return offs;
    }

    bool WaitClient(Client& cl) {
        unsigned long sTime = millis();
        while((!cl.available()) && (SOCKS5_TIMEOUT > millis() - sTime)) {
            yield();
        }
        return cl.available();
    }

    bool Socks5Auth() {
        Serial.println("Socks5Auth");
        struct TSocks5AuthRequest {
            uint8_t VER = 0x05;
            uint8_t NMETHODS = 0x01;
            uint8_t METHODS = 0x00;
        } __attribute__((packed)) s5AReq;
        Serial.println("TSocks5AuthRequest:");
        for (size_t i = 0; i < sizeof(s5AReq); ++i) {
            Serial.printf("%d:0x%x(%d) ", i, ((uint8_t*)&s5AReq)[i], ((uint8_t*)&s5AReq)[i]);
        }
        Serial.println("");

        Serial.printf("VER: %d; NMETHODS: %d; METHODS: %d\n", s5AReq.VER, s5AReq.NMETHODS, s5AReq.METHODS);
        if (WriteAll(client, (uint8_t*)&s5AReq, sizeof(TSocks5AuthRequest)) != sizeof(TSocks5AuthRequest)
            || !WaitClient(client)) {
                Serial.println("Socks4Auth failed");
            return false;
        }
        Serial.println("Socks4Auth read response");
        // Socks5 Auth Response
        struct TSocks5AuthResponse {
            uint8_t VER;
            uint8_t METHOD;
        } __attribute__((packed)) s5AResp;
        if (ReadAll(client, (uint8_t*)&s5AResp, sizeof(TSocks5AuthResponse)) != sizeof(TSocks5AuthResponse)
            || s5AResp.VER != 0x05
            || s5AResp.METHOD != 0x00) {
            Serial.printf("Socks5Auth failed response: VER=%d; METHOD=%d\n", s5AResp.VER, s5AResp.METHOD);
            return false;
        }
        Serial.printf("Socks5Auth success: VER=%d; METHOD=%d\n", s5AResp.VER, s5AResp.METHOD);
        return true;
    }

    int Socks5ConnectResponse() {
        Serial.println("Socks5 CONNECT RESPONSE");
        struct Socks5ConnResponse {
            uint8_t VER;
            uint8_t REP;
            uint8_t RSV;
            uint8_t ATYP;
            uint8_t ADDR[4];
            uint16_t PORT;
        } __attribute__((packed)) s5CResp;
        if (ReadAll(client, (uint8_t*)&s5CResp, sizeof(Socks5ConnResponse)) != sizeof(Socks5ConnResponse)
            || s5CResp.VER != 0x05
            || s5CResp.REP != 0x00
            || s5CResp.ATYP != 0x01) {
            Serial.printf("Socks5ConnectResponse failure: VAR=%d; REP=%d; ATYP=%d\n", s5CResp.VER, s5CResp.REP, s5CResp.ATYP);
            return 0;
        }
        Serial.printf("Socks5ConnectResponse success: VAR=%d; REP=%d; ATYP=%d\n", s5CResp.VER, s5CResp.REP, s5CResp.ATYP);
        //IPAddress destIp { s5CResp.ADDR[0], s5CResp.ADDR[1], s5CResp.ADDR[2], s5CResp.ADDR[3] };
        //uint16_t destPort = ntohs(s5CResp.PORT);

        return 1;
    }

    int Socks5ClientConnectWithRetry(const IPAddress& destIp, uint16_t destPort) {
        Serial.printf("\nSocks5ClientConnectWithRetry\n");
        Serial.printf("HOST: %s\n", destIp.toString().c_str());
        Serial.printf("PORT: %d\n", destPort);
        int r=0; //retry counter
        while((!client.connect(destIp, destPort)) && (r < 30)){
            yield();
            delay(100);
            Serial.print(".");
            r++;
        }
        if(r==30) {
            Serial.println("WiFi Client Connection failed");
            return 0;
        } else {
            Serial.println("WiFi Client Connected to web");
        }
        return 1;
    }

    bool Socks5ConnectByIp(IPAddress destIp, uint16_t destPort) {
        struct Socks5ConnRequest {
            uint8_t VER  = 0x05;
            uint8_t CMD  = 0x01;
            uint8_t RSV  = 0x00;
            uint8_t ATYP = 0x01; // IPv4 address
            uint32_t ADDR;
            uint16_t PORT;
        } __attribute__((packed)) s5CReq;
            s5CReq.ADDR = destIp;
            s5CReq.PORT = htons(destPort);
        Serial.println("Socks5ConnRequest:");
        for (size_t i = 0; i < sizeof(s5CReq); ++i) {
            Serial.printf("%d:0x%x(%d) ", i, ((uint8_t*)&s5CReq)[i], ((uint8_t*)&s5CReq)[i]);
        }
        Serial.println("");
        if (WriteAll(client, (uint8_t*)&s5CReq, sizeof(s5CReq)) != sizeof(s5CReq)
            || !WaitClient(client)) {
            return false;
        }
        return true;
    }

    bool Socks5ConnectByHost(const char* destHost, uint16_t& destPort){
        size_t dnLen = strlen(destHost);
        if (dnLen > 255) {
            return false;
        }
        Serial.printf("\nDN: %s; LEN: %d\n", destHost, dnLen);
        // Socks5 Connect Request
        struct Socks5ConnRequest {
            uint8_t VER  = 0x05;
            uint8_t CMD  = 0x01;
            uint8_t RSV  = 0x00;
            uint8_t ATYP = 0x03; // Domain name method
            uint8_t DN_LEN;      // Domain Name length;
        } __attribute__((packed)) s5CReq;
        s5CReq.DN_LEN = uint8_t(dnLen);
        if (WriteAll(client, (uint8_t*)&s5CReq, sizeof(Socks5ConnRequest)) != sizeof(Socks5ConnRequest)) {
            return false;
        };
        for (uint8_t i = 0; i < s5CReq.DN_LEN; ++i) {
            Serial.printf("DN[%d]='%c'\n", i, destHost[i]);
        }
        if (WriteAll(client, (uint8_t*)destHost, s5CReq.DN_LEN) != s5CReq.DN_LEN) {
            Serial.println("Socks5 bad send DN to socks5");
            return false;
        };
        uint16_t port = htons(destPort);
        Serial.printf("PORT = %d\n", destPort);

        if (WriteAll(client, (uint8_t*)&port, 2) != 2) {
            return false;
        };
        Serial.printf("Send CONNECT REQUEST\n");
        return true;
    }
};
