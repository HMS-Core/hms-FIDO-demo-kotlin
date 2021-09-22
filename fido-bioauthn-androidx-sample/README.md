# FIDO BioAuthn AndroidX Sample
[![License](https://img.shields.io/badge/Docs-hmsguides-brightgreen)](https://developer.huawei.com/consumer/en/doc/development/HMSCore-Guides/introduction-0000001051069988)

English | [中文](README_ZH.md)

## Table of Contents

 * [Introduction](#introduction)
 * [Getting Started](#getting-started)
 * [Installation](#installation)
 * [Configuration ](#configuration )
 * [Supported Environments](#supported-environments)
 * [Sample Code](#sample-code)
 * [License](#license)


## Introduction
FIDO BioAuthn AndroidX Sample provides many sample programs for your reference or usage.

## Getting Started
For more development details, please refer to the following link:
[Development Guide](https://developer.huawei.com/consumer/en/doc/development/Security-Guides/introduction-0000001051069988) & [API References](https://developer.huawei.com/consumer/en/doc/development/Security-References/overview-0000001077338138)

We also provide an example to demonstrate the use of BioAuthn Androidx SDK for Android.
This sample uses the Gradle build system.
First download the demo by cloning this repository or downloading an archived snapshot.

In Android Studio, use the "Open an existing Android Studio project", and select the directory of "fido-bioauthn-androidx-sample".
You should create an app in AppGallery Connect, and obtain the file of agconnect-services.json and add to the project. You should also generate a signing certificate fingerprint and add the certificate file to the project, and add configuration to build.gradle. See the [Configuring App Information in AppGallery Connect](https://developer.huawei.com/consumer/en/doc/development/Security-Guides/config-agc-0000001050262772) guide to configure app in AppGallery Connect.

Replace "com.huawei.hms.fido.sample.bioauthn" in build.gradle with you own applicationId.

You can use the "gradlew build" command to build the project

## Installation
Before using FIDO BioAuthn AndroidX Sample code, check whether the java environment and Android Studio have been installed.
Decompress the FIDO BioAuthn AndroidX Sample code package.

## Supported Environments
Java 1.7 or a later version is recommended.

## Configuration
No additional configuration is required. 

## Sample Code
1). Shows the fingerprint prompt without CryptoObject and allows the user to use the device PIN and password for authentication.

2). Shows the fingerprint prompt with CryptoObject.

3). Sends a facial authentication request to the user device.


## Result
<center class="half">
<img src="images/result.png" width=250 />
</center>

##  License
FIDO2 Sample is licensed under the [Apache License, version 2.0](http://www.apache.org/licenses/LICENSE-2.0).
