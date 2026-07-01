/*
 * Copyright (C) 2022 The LineageOS Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "android.hardware.biometrics.fingerprint@2.3-service.oplus"

#include "BiometricsFingerprint.h"
#include <sys/ioctl.h>
#include <unistd.h>

namespace android {
namespace hardware {
namespace biometrics {
namespace fingerprint {
namespace V2_3 {
namespace implementation {

BiometricsFingerprint::BiometricsFingerprint()
    : mOplusDisplayFd(open("/dev/oplus_display", O_RDWR)) {
    mOplusBiometricsFingerprint = IOplusBiometricsFingerprint::getService();
    mOplusBiometricsFingerprint->setHalCallback(this);
}

Return<uint64_t> BiometricsFingerprint::setNotify(
        const sp<V2_1::IBiometricsFingerprintClientCallback>& clientCallback) {
    mClientCallback = std::move(clientCallback);
    return mOplusBiometricsFingerprint->setNotify(this);
}

Return<uint64_t> BiometricsFingerprint::preEnroll() {
    setDimlayerHbm(1);
    return mOplusBiometricsFingerprint->preEnroll();
}

Return<RequestStatus> BiometricsFingerprint::enroll(const hidl_array<uint8_t, 69>& hat,
                                                    uint32_t gid, uint32_t timeoutSec) {
    return mOplusBiometricsFingerprint->enroll(hat, gid, timeoutSec);
}

Return<RequestStatus> BiometricsFingerprint::postEnroll() {
    setDimlayerHbm(0);
    return mOplusBiometricsFingerprint->postEnroll();
}

Return<uint64_t> BiometricsFingerprint::getAuthenticatorId() {
    return mOplusBiometricsFingerprint->getAuthenticatorId();
}

Return<RequestStatus> BiometricsFingerprint::cancel() {
    setDimlayerHbm(0);
    return mOplusBiometricsFingerprint->cancel();
}

Return<RequestStatus> BiometricsFingerprint::enumerate() {
    return mOplusBiometricsFingerprint->enumerate();
}

Return<RequestStatus> BiometricsFingerprint::remove(uint32_t gid, uint32_t fid) {
    return mOplusBiometricsFingerprint->remove(gid, fid);
}

Return<RequestStatus> BiometricsFingerprint::setActiveGroup(uint32_t gid,
                                                            const hidl_string& storePath) {
    return mOplusBiometricsFingerprint->setActiveGroup(gid, storePath);
}

Return<RequestStatus> BiometricsFingerprint::authenticate(uint64_t operationId, uint32_t gid) {
    ALOGE("[UDFPS HAL] authenticate called: operationId=%lu, gid=%u", operationId, gid);
    if (mOplusDisplayFd >= 0) {
        unsigned int enable = 1;
        // Preventivně probudíme dimlayer v kernelu, aby techpack věděl, že se blíží skenování
        ioctl(mOplusDisplayFd, PANEL_IOCTL_SET_DIMLAYER_BL_EN, &enable);
    }
    setDimlayerHbm(1);
    return mOplusBiometricsFingerprint->authenticate(operationId, gid);
}

Return<bool> BiometricsFingerprint::isUdfps(uint32_t sensorID) {
    return mOplusBiometricsFingerprint->isUdfps(sensorID);
}

Return<void> BiometricsFingerprint::onFingerDown(uint32_t x, uint32_t y, float minor, float major) {
    ALOGE("[UDFPS HAL] onFingerDown called: x=%u, y=%u", x, y);
    if (mOplusDisplayFd >= 0) {
        unsigned int enable = 1;
        unsigned int hbm_udfps_mode = 2;

        // 1. Probudíme hardwarově panely displeje
        ioctl(mOplusDisplayFd, PANEL_IOCTL_SET_DIMLAYER_BL_EN, &enable);
        ioctl(mOplusDisplayFd, PANEL_IOCTL_SET_HBM, &hbm_udfps_mode);
        ioctl(mOplusDisplayFd, PANEL_IOCTL_SET_FP_PRESS, &enable);

        // 2. KLÍČOVÉ: Zvýšíme zpoždění na 30-50 ms.
        // To dá Keyguardu dostatek času na to, aby zpracoval přechod z AOD stavu,
        // a panel stabilizoval gamma křivku pro focení prstu.
        usleep(15000);

        ALOGE("[UDFPS HAL] Hardwarová sekvence stabilizována (40ms sleep).");
    }
    setFpPress(1);
    mOplusBiometricsFingerprint->onFingerDown(x, y, minor, major);
    return Void();
}

Return<void> BiometricsFingerprint::onFingerUp() {
    ALOGE("[UDFPS HAL] onFingerUp called");
    setFpPress(0);
    if (mOplusDisplayFd >= 0) {
        unsigned int disable = 0;
        ioctl(mOplusDisplayFd, PANEL_IOCTL_SET_FP_PRESS, &disable);
        ioctl(mOplusDisplayFd, PANEL_IOCTL_SET_HBM, &disable);
        ioctl(mOplusDisplayFd, PANEL_IOCTL_SET_DIMLAYER_BL_EN, &disable);
    }
    mOplusBiometricsFingerprint->onFingerUp();
    return Void();
}

Return<void> BiometricsFingerprint::onEnrollResult(uint64_t deviceId, uint32_t fingerId,
                                                   uint32_t groupId, uint32_t remaining) {
    return mClientCallback->onEnrollResult(deviceId, fingerId, groupId, remaining);
}

Return<void> BiometricsFingerprint::onAcquired(uint64_t deviceId,
                                               V2_1::FingerprintAcquiredInfo acquiredInfo,
                                               int32_t vendorCode) {
    return mClientCallback->onAcquired(deviceId, acquiredInfo, vendorCode);
}

Return<void> BiometricsFingerprint::onAuthenticated(uint64_t deviceId, uint32_t fingerId,
                                                    uint32_t groupId,
                                                    const hidl_vec<uint8_t>& token) {
    ALOGE("[UDFPS HAL] onAuthenticated called: deviceId=%lu, fingerId=%u", deviceId, fingerId);
    if (fingerId != 0) {
        setDimlayerHbm(0);
    }
    setFpPress(0);
    if (mOplusDisplayFd >= 0) {
        unsigned int disable = 0;
        ioctl(mOplusDisplayFd, PANEL_IOCTL_SET_FP_PRESS, &disable);
        ioctl(mOplusDisplayFd, PANEL_IOCTL_SET_HBM, &disable);
        ioctl(mOplusDisplayFd, PANEL_IOCTL_SET_DIMLAYER_BL_EN, &disable);
    }
    return mClientCallback->onAuthenticated(deviceId, fingerId, groupId, token);
}

Return<void> BiometricsFingerprint::onError(uint64_t deviceId, FingerprintError error,
                                            int32_t vendorCode) {
    ALOGE("[UDFPS HAL] onError called: deviceId=%lu, error=%d, vendorCode=%d",
          deviceId, static_cast<int>(error), vendorCode);
    setDimlayerHbm(0);
    setFpPress(0);
    if (mOplusDisplayFd >= 0) {
        unsigned int disable = 0;
        ioctl(mOplusDisplayFd, PANEL_IOCTL_SET_FP_PRESS, &disable);
        ioctl(mOplusDisplayFd, PANEL_IOCTL_SET_HBM, &disable);
        ioctl(mOplusDisplayFd, PANEL_IOCTL_SET_DIMLAYER_BL_EN, &disable);
    }
    return mClientCallback->onError(deviceId, error, vendorCode);
}

Return<void> BiometricsFingerprint::onRemoved(uint64_t deviceId, uint32_t fingerId,
                                              uint32_t groupId, uint32_t remaining) {
    return mClientCallback->onRemoved(deviceId, fingerId, groupId, remaining);
}

Return<void> BiometricsFingerprint::onEnumerate(uint64_t deviceId, uint32_t fingerId,
                                                uint32_t groupId, uint32_t remaining) {
    return mClientCallback->onEnumerate(deviceId, fingerId, groupId, remaining);
}

Return<void> BiometricsFingerprint::onAcquired_2_2(uint64_t deviceId,
                                                   FingerprintAcquiredInfo acquiredInfo,
                                                   int32_t vendorCode) {
    return reinterpret_cast<V2_2::IBiometricsFingerprintClientCallback*>(mClientCallback.get())
            ->onAcquired_2_2(deviceId, acquiredInfo, vendorCode);
}

Return<void> BiometricsFingerprint::onEngineeringInfoUpdated(
        uint32_t /*lenth*/, const hidl_vec<uint32_t>& /*keys*/,
        const hidl_vec<hidl_string>& /*values*/) {
    return Void();
}

Return<void> BiometricsFingerprint::onFingerprintCmd(int32_t /*cmdId*/,
                                                     const hidl_vec<uint32_t>& /*result*/,
                                                     uint32_t /*resultLen*/) {
    return Void();
}

}  // namespace implementation
}  // namespace V2_3
}  // namespace fingerprint
}  // namespace biometrics
}  // namespace hardware
}  // namespace android
