#pragma once

#define _WINSOCKAPI_
#include <Windows.h>
#include <TlHelp32.h>
#include <WS2tcpip.h>
#include <WinInet.h>
#include <MSWSock.h>
#include <SoftPub.h>
#include <strsafe.h>
#include <netfw.h>
#include <comutil.h>
#include <atlcomcli.h>

/* cryptopp */
#include <sha.h>
#include <rsa.h>
#include <osrng.h>
#include <base64.h>
#include <files.h>
#include <hex.h>
#include <modes.h>

/* std includes */
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>
#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <queue>
#include <shared_mutex>