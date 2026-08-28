# SentinelX Mobile App - Google Play Store Build & Submission Guide

This directory contains the **Flutter Cross-Platform Mobile Application** for SentinelX SOC.

---

## 🚀 Quick Setup & Local Testing

### Prerequisites
1. Install [Flutter SDK](https://docs.flutter.dev/get-started/install).
2. Install [Android Studio](https://developer.android.com/studio) with Android SDK 34 (Android 14).

### Steps to Run
```bash
# 1. Navigate to mobile directory
cd C:\SOC_AUTOMATION_PROJECT_FINAL\sentinelx_mobile

# 2. Install dependencies
flutter pub get

# 3. Run on connected Android device or emulator
flutter run
```

---

## 📦 Building Play Store Releases (.aab / .apk)

Google Play Store requires an **Android App Bundle (.aab)** file compiled with Target SDK 34.

### 1. Generate an Android Release Key (Keystore)
Run the following command in PowerShell / Terminal:
```powershell
keytool -genkey -v -keystore android/app/upload-keystore.jks -keyalg RSA -keysize 2048 -validity 10000 -alias upload
```

### 2. Configure Key Credentials
Create `android/key.properties`:
```properties
storePassword=<your-keystore-password>
keyPassword=<your-key-password>
keyAlias=upload
storeFile=upload-keystore.jks
```

### 3. Build Android App Bundle (.aab)
```bash
flutter build appbundle --release
```
The compiled Play Store bundle will be generated at:
`build/app/outputs/bundle/release/app-release.aab`

### 4. Build Standalone APK (Optional for direct installation)
```bash
flutter build apk --release
```
The APK will be generated at:
`build/app/outputs/flutter-apk/app-release.apk`

---

## 📱 Google Play Console Submission Steps

1. Log in to [Google Play Console](https://play.google.com/console).
2. Create a new app entry titled **SentinelX SOC Platform**.
3. Upload `app-release.aab` under **Production / Internal Testing**.
4. Fill in standard metadata:
   - App Category: **Tools / Security**
   - Screenshots: Take screenshots from running Flutter app on tablet/phone viewports.
   - Privacy Policy & Target Audience: Select Security Operations.
5. Click **Submit for Review**.
