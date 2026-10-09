#pragma once
#include <cstdint>

// AnoSDK bypass — neutralize Free Fire's anti-cheat reporting
// libanogs.so exports: AnoSDKIoctl, AnoSDKGetReportData(2/3/4), ms_scan_start
namespace AnoBypass {
    bool install();    // hook all AnoSDK report functions
    void remove();     // clean up before app exits
}
