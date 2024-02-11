#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <iostream>
#include <iphlpapi.h>
#include <nlohmann/json.hpp>
#include <chrono>

using json = nlohmann::json;

#include <locale>
#include <codecvt>
#include <algorithm>

json GetRegistryValue(HKEY key, const wchar_t* subKey, const wchar_t* valueName) {
    json value;
    HKEY keyHandle;
    std::wstring result;
    DWORD size = 1023;
    DWORD type;

    if (RegOpenKeyExW(key, subKey, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &keyHandle) == ERROR_SUCCESS) {
        if (RegQueryValueExW(keyHandle, valueName, nullptr, &type, nullptr, &size) == ERROR_SUCCESS) {
            result.resize(size / sizeof(wchar_t));

            if (RegQueryValueExW(keyHandle, valueName, nullptr, &type, reinterpret_cast<LPBYTE>(&result[0]), &size) == ERROR_SUCCESS) {
                RegCloseKey(keyHandle);

                switch (type) {
                case REG_SZ:
                case REG_EXPAND_SZ:
                    value = json(std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(result).c_str());
                    break;

                case REG_MULTI_SZ:
                    std::replace(result.begin(), result.end(), L'\0', L' ');
                    value = json(std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(result).c_str());
                    break;

                case REG_DWORD:
                    value = *reinterpret_cast<const DWORD*>(&result[0]);
                    break;

                case REG_QWORD:
                    value = *reinterpret_cast<const DWORDLONG*>(&result[0]);
                    break;

                default:
                    value = json(std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(result).c_str());
                }

                return value;
            }
        }
        RegCloseKey(keyHandle);
    }
    return value;
}

json GetRegistryFolder(HKEY key, const wchar_t* subKey) {
    json folderContent;

    HKEY keyHandle;
    DWORD size = 1023;
    DWORD index = 0;
    wchar_t valueName[1024];
    DWORD valueNameSize = sizeof(valueName) / sizeof(valueName[0]);
    DWORD type;
    std::wstring result;

    if (RegOpenKeyExW(key, subKey, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &keyHandle) == ERROR_SUCCESS) {
        while (RegEnumValueW(keyHandle, index++, valueName, &valueNameSize, nullptr, &type, nullptr, &size) == ERROR_SUCCESS) {
            result.resize(size / sizeof(wchar_t));

            if (RegQueryValueExW(keyHandle, valueName, nullptr, &type, reinterpret_cast<LPBYTE>(&result[0]), &size) == ERROR_SUCCESS) {
                switch (type) {
                case REG_SZ:
                case REG_EXPAND_SZ:
                    //folderContent[std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(valueName).c_str()] = std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(result);
                {
                    std::string stringValue = std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(result);
                    std::replace(stringValue.begin(), stringValue.end(), L'\0', L' ');
                    stringValue.erase(std::find_if(stringValue.rbegin(), stringValue.rend(), [](int ch) {
                        return !std::isspace(ch);
                        }).base(), stringValue.end());
                    folderContent[std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(valueName).c_str()] = stringValue;
                }
                break;

                case REG_MULTI_SZ:
                    std::replace(result.begin(), result.end(), L'\0', L' ');
                    folderContent[std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(valueName).c_str()] = result;
                    break;

                case REG_DWORD:
                    folderContent[std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(valueName).c_str()] = *reinterpret_cast<const DWORD*>(&result[0]);
                    break;

                case REG_QWORD:
                    folderContent[std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(valueName).c_str()] = *reinterpret_cast<const DWORDLONG*>(&result[0]);
                    break;

                default:
                    folderContent[std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(valueName).c_str()] = json(std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(result).c_str());
                }
            }

            valueNameSize = sizeof(valueName) / sizeof(valueName[0]);
        }

        RegCloseKey(keyHandle);
    }

    return folderContent;
}

#include <sstream>
std::string ConvertMacAddressToString(BYTE* macAddress) {
    std::stringstream macAddressString;
    macAddressString << std::hex << std::setfill('0');

    for (int i = 0; i < 6; ++i) {
        macAddressString << std::setw(2) << static_cast<int>(macAddress[i]);

        if (i < 5) {
            macAddressString << ':';
        }
    }

    return macAddressString.str();
}
json GetSoftwareInfo() {
    json softwareInfo;

    const wchar_t* registryLocationVolatileEnvironment = L"Volatile Environment";
    softwareInfo["username"] = GetRegistryValue(HKEY_CURRENT_USER, registryLocationVolatileEnvironment, L"USERNAME");
    softwareInfo["userdomain"] = GetRegistryValue(HKEY_CURRENT_USER, registryLocationVolatileEnvironment, L"USERDOMAIN");

    const wchar_t* registryLocationComputerName = L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName";
    softwareInfo["computername"] = GetRegistryValue(HKEY_LOCAL_MACHINE, registryLocationComputerName, L"ComputerName");

    auto uptime = std::chrono::milliseconds(GetTickCount64());
    softwareInfo["uptime"] = std::chrono::duration_cast<std::chrono::seconds>(uptime).count();
    const auto systime = std::chrono::system_clock::now();
    softwareInfo["systemtime"] = std::chrono::duration_cast<std::chrono::seconds>(systime.time_since_epoch()).count();

    const wchar_t* registryLocationCurrentVersion = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    softwareInfo["current_version"] = GetRegistryValue(HKEY_LOCAL_MACHINE, registryLocationCurrentVersion, L"CurrentVersion");
    softwareInfo["edition_id"] = GetRegistryValue(HKEY_LOCAL_MACHINE, registryLocationCurrentVersion, L"EditionID");
    softwareInfo["display_version"] = GetRegistryValue(HKEY_LOCAL_MACHINE, registryLocationCurrentVersion, L"DisplayVersion");
    softwareInfo["product_id"] = GetRegistryValue(HKEY_LOCAL_MACHINE, registryLocationCurrentVersion, L"ProductID");
    softwareInfo["product_name"] = GetRegistryValue(HKEY_LOCAL_MACHINE, registryLocationCurrentVersion, L"ProductName");
    softwareInfo["registered_owner"] = GetRegistryValue(HKEY_LOCAL_MACHINE, registryLocationCurrentVersion, L"RegisteredOwner");
    softwareInfo["install_date"] = GetRegistryValue(HKEY_LOCAL_MACHINE, registryLocationCurrentVersion, L"InstallDate");
    softwareInfo["install_time"] = GetRegistryValue(HKEY_LOCAL_MACHINE, registryLocationCurrentVersion, L"InstallTime");

    const wchar_t* registryLocationControlSet = L"SYSTEM\\CurrentControlSet\\Control";
    softwareInfo["dirty_shutdown_count"] = GetRegistryValue(HKEY_LOCAL_MACHINE, registryLocationControlSet, L"DirtyShutdownCount");
    softwareInfo["early_start_services"] = GetRegistryValue(HKEY_LOCAL_MACHINE, registryLocationControlSet, L"EarlyStartServices");
    softwareInfo["last_boot_succeeded"] = GetRegistryValue(HKEY_LOCAL_MACHINE, registryLocationControlSet, L"LastBootSucceeded");
    softwareInfo["system_boot_device"] = GetRegistryValue(HKEY_LOCAL_MACHINE, registryLocationControlSet, L"SystemBootDevice");
    softwareInfo["system_start_options"] = GetRegistryValue(HKEY_LOCAL_MACHINE, registryLocationControlSet, L"SystemStartOptions");

    const wchar_t* registryLocationThemePreferences = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize";
    softwareInfo["apps_use_light_theme"] = GetRegistryValue(HKEY_CURRENT_USER, registryLocationThemePreferences, L"AppsUseLightTheme");
    softwareInfo["system_uses_light_theme"] = GetRegistryValue(HKEY_CURRENT_USER, registryLocationThemePreferences, L"SystemUsesLightTheme");

    const wchar_t* registryLocationTimeZone = L"SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation";
    softwareInfo["TimeZoneKeyName"] = GetRegistryValue(HKEY_LOCAL_MACHINE, registryLocationTimeZone, L"TimeZoneKeyName");

    const wchar_t* registryLocationDisplayResolution = L"SYSTEM\\CurrentControlSet\\Control\\UnitedVideo\\SERVICES\\BASICDISPLAY";
    softwareInfo["XResolution"] = GetRegistryValue(HKEY_LOCAL_MACHINE, registryLocationDisplayResolution, L"DefaultSettings.XResolution");
    softwareInfo["YResolution"] = GetRegistryValue(HKEY_CURRENT_USER, registryLocationDisplayResolution, L"DefaultSettings.YResolution");

    const wchar_t* registryLocationShutdown = L"SYSTEM\\CurrentControlSet\\Control\\Windows";
    softwareInfo["ShutdownTime"] = GetRegistryValue(HKEY_LOCAL_MACHINE, registryLocationShutdown, L"ShutdownTime");

    const wchar_t* registryFolderDisplayInterfaces = L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\";
    softwareInfo["display_interfaces"] = GetRegistryFolder(HKEY_LOCAL_MACHINE, registryFolderDisplayInterfaces);

    return softwareInfo;
}

json GetHardwareInfo() {
    json hardwareInfo;

    // Get hardware information
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    hardwareInfo["processor_architecture"] = sysInfo.wProcessorArchitecture;
    hardwareInfo["processor_level"] = sysInfo.wProcessorLevel;
    hardwareInfo["processor_revision"] = sysInfo.wProcessorRevision;
    hardwareInfo["number_of_processors"] = sysInfo.dwNumberOfProcessors;
    hardwareInfo["page_size"] = sysInfo.dwPageSize;
    hardwareInfo["processor_type"] = sysInfo.dwProcessorType;
    hardwareInfo["active_processor_mask"] = sysInfo.dwActiveProcessorMask;

    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);
    GlobalMemoryStatusEx(&memoryStatus);
    hardwareInfo["total_memory_in_byte"] = memoryStatus.ullTotalPhys;
    hardwareInfo["used_memory_in_percent"] = memoryStatus.dwMemoryLoad;

    const wchar_t* registryLocationHardwareConfig = L"SYSTEM\\HardwareConfig\\Current";
    hardwareInfo["base_board_manufacturer"] = GetRegistryValue(HKEY_LOCAL_MACHINE, registryLocationHardwareConfig, L"BaseBoardManufacturer");
    hardwareInfo["base_board_product"] = GetRegistryValue(HKEY_LOCAL_MACHINE, registryLocationHardwareConfig, L"BaseBoardProduct");
    hardwareInfo["bios_release_date"] = GetRegistryValue(HKEY_LOCAL_MACHINE, registryLocationHardwareConfig, L"BIOSReleaseDate");
    hardwareInfo["bios_vendor"] = GetRegistryValue(HKEY_LOCAL_MACHINE, registryLocationHardwareConfig, L"BIOSVendor");
    hardwareInfo["bios_version"] = GetRegistryValue(HKEY_LOCAL_MACHINE, registryLocationHardwareConfig, L"BIOSVersion");
    hardwareInfo["system_bios_version"] = GetRegistryValue(HKEY_LOCAL_MACHINE, registryLocationHardwareConfig, L"SystemBiosVersion");
    hardwareInfo["system_family"] = GetRegistryValue(HKEY_LOCAL_MACHINE, registryLocationHardwareConfig, L"SystemFamily");
    hardwareInfo["system_manufacturer"] = GetRegistryValue(HKEY_LOCAL_MACHINE, registryLocationHardwareConfig, L"SystemManufacturer");
    hardwareInfo["system_product_name"] = GetRegistryValue(HKEY_LOCAL_MACHINE, registryLocationHardwareConfig, L"SystemProductName");
    hardwareInfo["system_sku"] = GetRegistryValue(HKEY_LOCAL_MACHINE, registryLocationHardwareConfig, L"SystemSKU");

    const wchar_t* registryLocationCentralProcessor = L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0";
    hardwareInfo["processor_name_string"] = GetRegistryValue(HKEY_LOCAL_MACHINE, registryLocationCentralProcessor, L"ProcessorNameString");
    hardwareInfo["processor_identifier"] = GetRegistryValue(HKEY_LOCAL_MACHINE, registryLocationCentralProcessor, L"Identifier");

    const wchar_t* registryLocationDisplayParams = L"SYSTEM\\ControlSet001\\Hardware Profiles\\0001\\System\\CurrentControlSet\\Control\\VIDEO\\";
    hardwareInfo["display_video"] = GetRegistryFolder(HKEY_LOCAL_MACHINE, registryLocationCentralProcessor);

    const wchar_t* registryFolderDisplayControls = L"SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\\Configuration\\";
    hardwareInfo["display_controls"] = GetRegistryFolder(HKEY_LOCAL_MACHINE, registryFolderDisplayControls);

    const wchar_t* registryFolderDisplayInterfaces = L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\";
    hardwareInfo["display_interfaces"] = GetRegistryFolder(HKEY_LOCAL_MACHINE, registryFolderDisplayInterfaces);

    return hardwareInfo;
}

json GetNetworkInfo() {
    json networkInfo;

    // Get network adapter information
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD bufferSize = sizeof(adapterInfo);

    if (GetAdaptersInfo(adapterInfo, &bufferSize) == ERROR_SUCCESS) {
        for (PIP_ADAPTER_INFO adapter = adapterInfo; adapter != NULL; adapter = adapter->Next) {

            // Create a JSON object for each network adapter
            json adapterInfoJson;
            adapterInfoJson["adapter_name"] = adapter->AdapterName;
            adapterInfoJson["adapter_description"] = adapter->Description;
            adapterInfoJson["adapter_type"] = adapter->Type;
            adapterInfoJson["mac_address"] = ConvertMacAddressToString(adapter->Address);
            adapterInfoJson["dhcp_status"] = adapter->DhcpEnabled;

            IP_ADDR_STRING* ipAddress = &(adapter->IpAddressList);
            adapterInfoJson["ip_address"] = ipAddress->IpAddress.String;

            networkInfo.push_back(adapterInfoJson);
        }
    }
    else {
        networkInfo["NetworkInfo"] = "";
    }

    return networkInfo;
}

int main() {
    do {
        try {
            // Define API URL
            const char* URL = "http://api.domain.tld";

            // Gather System Information
            std::string user = GetRegistryValue(HKEY_CURRENT_USER, L"Volatile Environment", L"USERNAME");

            json completeJsonString;
            completeJsonString.update(user);
            completeJsonString.update(GetSoftwareInfo());
            completeJsonString.update(GetHardwareInfo());
            completeJsonString.update(GetNetworkInfo());

            std::cout << completeJsonString.dump(4) << std::endl;

        }
        catch (const std::exception& e) {
            std::cerr << "Exception caught: " << e.what() << std::endl;
        }

        std::cout << std::endl << "Hitting [RETURN] will retry.";
    } while (std::cin.get() == '\n');

    return 0;
}
