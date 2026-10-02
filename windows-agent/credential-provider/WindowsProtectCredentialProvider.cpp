#define SECURITY_WIN32
#include <initguid.h>
#include <windows.h>
#include <credentialprovider.h>
#include <propkey.h>
#include <shlwapi.h>
#include <wincrypt.h>
#include <wincred.h>
#include <new>
#include "helpers.h"

// {7CE6877B-3F4A-4C5B-9201-61D486EF7B77}
DEFINE_GUID(CLSID_WindowsProtectUnlock, 0x7ce6877b, 0x3f4a, 0x4c5b, 0x92, 0x01, 0x61, 0xd4, 0x86, 0xef, 0x7b, 0x77);

static const wchar_t *kStore = L"SOFTWARE\\WindowsProtect\\RemoteUnlock";
static long g_dllRefs = 0;
static HINSTANCE g_instance = nullptr;

static ULONGLONG NowFileTime()
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    return (static_cast<ULONGLONG>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
}

static bool ReadString(HKEY key, const wchar_t *name, wchar_t *value, DWORD chars)
{
    DWORD type = 0, bytes = chars * sizeof(wchar_t);
    return RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<BYTE *>(value), &bytes) == ERROR_SUCCESS &&
           type == REG_SZ && value[0] != L'\0';
}

static bool RequestReady()
{
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kStore, 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) return false;
    ULONGLONG expires = 0;
    DWORD type = 0, bytes = sizeof(expires), secretBytes = 0;
    wchar_t nonce[65] = {};
    wchar_t sid[192] = {};
    const bool ok =
        RegQueryValueExW(key, L"RequestExpires", nullptr, &type, reinterpret_cast<BYTE *>(&expires), &bytes) == ERROR_SUCCESS &&
        type == REG_QWORD &&
        ReadString(key, L"RequestNonce", nonce, ARRAYSIZE(nonce)) &&
        ReadString(key, L"UserSid", sid, ARRAYSIZE(sid)) &&
        RegQueryValueExW(key, L"Secret", nullptr, nullptr, nullptr, &secretBytes) == ERROR_SUCCESS && secretBytes > 0;
    RegCloseKey(key);
    const ULONGLONG now = NowFileTime();
    const ULONGLONG fiveMinutes = 5ULL * 60ULL * 10000000ULL;
    return ok && expires > now && expires <= now + fiveMinutes;
}

static bool LoadStoredSid(wchar_t *sid, DWORD chars)
{
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kStore, 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) return false;
    const bool ok = ReadString(key, L"UserSid", sid, chars);
    RegCloseKey(key);
    return ok;
}

// Consumes the request before returning any plaintext. A failed sign-in cannot be replayed.
static HRESULT ConsumeRequestAndDecrypt(PWSTR *password)
{
    *password = nullptr;
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kStore, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &key) != ERROR_SUCCESS)
        return HRESULT_FROM_WIN32(GetLastError());

    ULONGLONG expires = 0;
    DWORD type = 0, bytes = sizeof(expires), encryptedBytes = 0;
    wchar_t nonce[65] = {};
    bool valid =
        RegQueryValueExW(key, L"RequestExpires", nullptr, &type, reinterpret_cast<BYTE *>(&expires), &bytes) == ERROR_SUCCESS &&
        type == REG_QWORD && ReadString(key, L"RequestNonce", nonce, ARRAYSIZE(nonce));
    const ULONGLONG now = NowFileTime();
    valid = valid && expires > now && expires <= now + (5ULL * 60ULL * 10000000ULL);

    // Delete first: this authorisation is single-use even if decryption or logon later fails.
    RegDeleteValueW(key, L"RequestExpires");
    RegDeleteValueW(key, L"RequestNonce");
    if (!valid || RegQueryValueExW(key, L"Secret", nullptr, nullptr, nullptr, &encryptedBytes) != ERROR_SUCCESS || !encryptedBytes) {
        RegCloseKey(key);
        return HRESULT_FROM_WIN32(ERROR_TIMEOUT);
    }

    BYTE *encrypted = static_cast<BYTE *>(LocalAlloc(LPTR, encryptedBytes));
    if (!encrypted) { RegCloseKey(key); return E_OUTOFMEMORY; }
    bytes = encryptedBytes;
    if (RegQueryValueExW(key, L"Secret", nullptr, &type, encrypted, &bytes) != ERROR_SUCCESS || type != REG_BINARY) {
        SecureZeroMemory(encrypted, encryptedBytes); LocalFree(encrypted); RegCloseKey(key); return E_FAIL;
    }
    RegCloseKey(key);

    DATA_BLOB input = { encryptedBytes, encrypted }, output = {};
    HRESULT hr = E_FAIL;
    if (CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output) &&
        output.cbData >= sizeof(wchar_t) && (output.cbData % sizeof(wchar_t)) == 0 &&
        reinterpret_cast<PWSTR>(output.pbData)[output.cbData / sizeof(wchar_t) - 1] == L'\0') {
        *password = static_cast<PWSTR>(CoTaskMemAlloc(output.cbData));
        if (*password) { CopyMemory(*password, output.pbData, output.cbData); hr = S_OK; }
        else hr = E_OUTOFMEMORY;
    } else {
        hr = HRESULT_FROM_WIN32(GetLastError());
    }
    if (output.pbData) { SecureZeroMemory(output.pbData, output.cbData); LocalFree(output.pbData); }
    SecureZeroMemory(encrypted, encryptedBytes); LocalFree(encrypted);
    return hr;
}

enum FIELD_ID { FI_LABEL, FI_STATUS, FI_PASSWORD, FI_COUNT };
static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR kFields[FI_COUNT] = {
    { FI_LABEL, CPFT_SMALL_TEXT, const_cast<PWSTR>(L"WindowsProtect unlock") },
    { FI_STATUS, CPFT_LARGE_TEXT, const_cast<PWSTR>(L"Authorised remote unlock") },
    { FI_PASSWORD, CPFT_PASSWORD_TEXT, const_cast<PWSTR>(L"Password") }
};
static const CREDENTIAL_PROVIDER_FIELD_STATE kStates[FI_COUNT] = { CPFS_HIDDEN, CPFS_DISPLAY_IN_BOTH, CPFS_HIDDEN };

class UnlockCredential final : public ICredentialProviderCredential2
{
public:
    UnlockCredential() : refs_(1), scenario_(CPUS_INVALID), sid_(nullptr), qualified_(nullptr), local_(false) { InterlockedIncrement(&g_dllRefs); }
    HRESULT Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario, ICredentialProviderUser *user)
    {
        scenario_ = scenario;
        GUID provider = {};
        HRESULT hr = user->GetProviderID(&provider);
        local_ = SUCCEEDED(hr) && provider == Identity_LocalUserProvider;
        if (SUCCEEDED(hr)) hr = user->GetSid(&sid_);
        if (SUCCEEDED(hr)) hr = user->GetStringValue(PKEY_Identity_QualifiedUserName, &qualified_);
        return hr;
    }
    IFACEMETHODIMP QueryInterface(REFIID iid, void **out) override
    {
        if (!out) return E_INVALIDARG;
        *out = nullptr;
        if (iid == IID_IUnknown || iid == IID_ICredentialProviderCredential) *out = static_cast<ICredentialProviderCredential *>(this);
        else if (iid == IID_ICredentialProviderCredential2) *out = static_cast<ICredentialProviderCredential2 *>(this);
        else return E_NOINTERFACE;
        AddRef(); return S_OK;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override { return InterlockedIncrement(&refs_); }
    IFACEMETHODIMP_(ULONG) Release() override { ULONG n = InterlockedDecrement(&refs_); if (!n) delete this; return n; }
    IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents *) override { return S_OK; }
    IFACEMETHODIMP UnAdvise() override { return S_OK; }
    IFACEMETHODIMP SetSelected(BOOL *autoLogon) override { *autoLogon = TRUE; return S_OK; }
    IFACEMETHODIMP SetDeselected() override { return S_OK; }
    IFACEMETHODIMP GetFieldState(DWORD id, CREDENTIAL_PROVIDER_FIELD_STATE *state, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE *interactive) override
    { if (id >= FI_COUNT) return E_INVALIDARG; *state = kStates[id]; *interactive = CPFIS_NONE; return S_OK; }
    IFACEMETHODIMP GetStringValue(DWORD id, PWSTR *value) override
    {
        if (!value || id >= FI_COUNT) return E_INVALIDARG;
        const wchar_t *text = id == FI_LABEL ? L"WindowsProtect" : id == FI_STATUS ? L"Owner-authorised unlock" : L"";
        return SHStrDupW(text, value);
    }
    IFACEMETHODIMP GetBitmapValue(DWORD, HBITMAP *) override { return E_NOTIMPL; }
    IFACEMETHODIMP GetCheckboxValue(DWORD, BOOL *, PWSTR *) override { return E_NOTIMPL; }
    IFACEMETHODIMP GetSubmitButtonValue(DWORD, DWORD *) override { return E_NOTIMPL; }
    IFACEMETHODIMP GetComboBoxValueCount(DWORD, DWORD *, DWORD *) override { return E_NOTIMPL; }
    IFACEMETHODIMP GetComboBoxValueAt(DWORD, DWORD, PWSTR *) override { return E_NOTIMPL; }
    IFACEMETHODIMP SetStringValue(DWORD, PCWSTR) override { return E_NOTIMPL; }
    IFACEMETHODIMP SetCheckboxValue(DWORD, BOOL) override { return E_NOTIMPL; }
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD, DWORD) override { return E_NOTIMPL; }
    IFACEMETHODIMP CommandLinkClicked(DWORD) override { return E_NOTIMPL; }
    IFACEMETHODIMP GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE *response,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *serialization, PWSTR *status,
        CREDENTIAL_PROVIDER_STATUS_ICON *icon) override
    {
        if (!response || !serialization || !status || !icon) return E_INVALIDARG;
        *response = CPGSR_NO_CREDENTIAL_NOT_FINISHED; *status = nullptr; *icon = CPSI_NONE;
        ZeroMemory(serialization, sizeof(*serialization));
        PWSTR password = nullptr;
        HRESULT hr = ConsumeRequestAndDecrypt(&password);
        if (FAILED(hr)) return hr;
        if (local_) {
            PWSTR protectedPassword = nullptr, domain = nullptr, username = nullptr;
            hr = ProtectIfNecessaryAndCopyPassword(password, scenario_, &protectedPassword);
            if (SUCCEEDED(hr)) hr = SplitDomainAndUsername(qualified_, &domain, &username);
            if (SUCCEEDED(hr)) {
                KERB_INTERACTIVE_UNLOCK_LOGON value;
                hr = KerbInteractiveUnlockLogonInit(domain, username, protectedPassword, scenario_, &value);
                if (SUCCEEDED(hr)) hr = KerbInteractiveUnlockLogonPack(value, &serialization->rgbSerialization, &serialization->cbSerialization);
            }
            if (protectedPassword) { SecureZeroMemory(protectedPassword, (wcslen(protectedPassword) + 1) * sizeof(wchar_t)); CoTaskMemFree(protectedPassword); }
            CoTaskMemFree(domain); CoTaskMemFree(username);
        } else {
            DWORD flags = CRED_PACK_PROTECTED_CREDENTIALS | CRED_PACK_ID_PROVIDER_CREDENTIALS;
            if (!CredPackAuthenticationBufferW(flags, qualified_, password, nullptr, &serialization->cbSerialization) && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                serialization->rgbSerialization = static_cast<BYTE *>(CoTaskMemAlloc(serialization->cbSerialization));
                if (!serialization->rgbSerialization) hr = E_OUTOFMEMORY;
                else if (CredPackAuthenticationBufferW(flags, qualified_, password, serialization->rgbSerialization, &serialization->cbSerialization)) hr = S_OK;
                else hr = HRESULT_FROM_WIN32(GetLastError());
            } else hr = HRESULT_FROM_WIN32(GetLastError());
        }
        SecureZeroMemory(password, (wcslen(password) + 1) * sizeof(wchar_t)); CoTaskMemFree(password);
        if (SUCCEEDED(hr)) {
            hr = RetrieveNegotiateAuthPackage(&serialization->ulAuthenticationPackage);
            serialization->clsidCredentialProvider = CLSID_WindowsProtectUnlock;
            if (SUCCEEDED(hr)) *response = CPGSR_RETURN_CREDENTIAL_FINISHED;
        }
        if (FAILED(hr) && serialization->rgbSerialization) { CoTaskMemFree(serialization->rgbSerialization); ZeroMemory(serialization, sizeof(*serialization)); }
        return hr;
    }
    IFACEMETHODIMP ReportResult(NTSTATUS, NTSTATUS, PWSTR *status, CREDENTIAL_PROVIDER_STATUS_ICON *icon) override
    { *status = nullptr; *icon = CPSI_NONE; return S_OK; }
    IFACEMETHODIMP GetUserSid(PWSTR *sid) override { return sid_ ? SHStrDupW(sid_, sid) : E_UNEXPECTED; }
private:
    ~UnlockCredential() { CoTaskMemFree(sid_); CoTaskMemFree(qualified_); InterlockedDecrement(&g_dllRefs); }
    long refs_; CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario_; PWSTR sid_; PWSTR qualified_; bool local_;
};

class UnlockProvider final : public ICredentialProvider, public ICredentialProviderSetUserArray
{
public:
    UnlockProvider() : refs_(1), scenario_(CPUS_INVALID), users_(nullptr), credential_(nullptr), events_(nullptr), context_(0), stop_(nullptr), thread_(nullptr), lastReady_(false)
    { InitializeCriticalSection(&lock_); InterlockedIncrement(&g_dllRefs); }
    IFACEMETHODIMP QueryInterface(REFIID iid, void **out) override
    {
        if (!out) return E_INVALIDARG; *out = nullptr;
        if (iid == IID_IUnknown || iid == IID_ICredentialProvider) *out = static_cast<ICredentialProvider *>(this);
        else if (iid == IID_ICredentialProviderSetUserArray) *out = static_cast<ICredentialProviderSetUserArray *>(this);
        else return E_NOINTERFACE;
        AddRef(); return S_OK;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override { return InterlockedIncrement(&refs_); }
    IFACEMETHODIMP_(ULONG) Release() override { ULONG n = InterlockedDecrement(&refs_); if (!n) delete this; return n; }
    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario, DWORD) override
    { if (scenario != CPUS_LOGON && scenario != CPUS_UNLOCK_WORKSTATION) return E_NOTIMPL; scenario_ = scenario; return S_OK; }
    IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *) override { return E_NOTIMPL; }
    IFACEMETHODIMP Advise(ICredentialProviderEvents *events, UINT_PTR context) override
    {
        if (!events) return E_INVALIDARG;
        UnAdvise();
        EnterCriticalSection(&lock_); events_ = events; context_ = context; events_->AddRef(); LeaveCriticalSection(&lock_);
        lastReady_ = RequestReady(); stop_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!stop_) { HRESULT hr = HRESULT_FROM_WIN32(GetLastError()); UnAdvise(); return hr; }
        AddRef(); // The polling thread owns a provider reference until it exits.
        thread_ = CreateThread(nullptr, 0, Poll, this, 0, nullptr);
        if (!thread_) { HRESULT hr = HRESULT_FROM_WIN32(GetLastError()); Release(); UnAdvise(); return hr; }
        return S_OK;
    }
    IFACEMETHODIMP UnAdvise() override
    {
        if (stop_) SetEvent(stop_);
        if (thread_) { WaitForSingleObject(thread_, 3000); CloseHandle(thread_); thread_ = nullptr; }
        if (stop_) { CloseHandle(stop_); stop_ = nullptr; }
        EnterCriticalSection(&lock_); if (events_) { events_->Release(); events_ = nullptr; } LeaveCriticalSection(&lock_);
        return S_OK;
    }
    IFACEMETHODIMP GetFieldDescriptorCount(DWORD *count) override { *count = FI_COUNT; return S_OK; }
    IFACEMETHODIMP GetFieldDescriptorAt(DWORD id, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR **field) override
    { return id < FI_COUNT ? FieldDescriptorCoAllocCopy(kFields[id], field) : E_INVALIDARG; }
    IFACEMETHODIMP GetCredentialCount(DWORD *count, DWORD *defaultIndex, BOOL *autoLogon) override
    {
        ReleaseCredential(); *count = 0; *defaultIndex = CREDENTIAL_PROVIDER_NO_DEFAULT; *autoLogon = FALSE;
        if (!RequestReady() || !users_) return S_OK;
        wchar_t storedSid[192] = {}; if (!LoadStoredSid(storedSid, ARRAYSIZE(storedSid))) return S_OK;
        DWORD userCount = 0; users_->GetCount(&userCount);
        for (DWORD i = 0; i < userCount; ++i) {
            ICredentialProviderUser *user = nullptr; PWSTR sid = nullptr;
            if (SUCCEEDED(users_->GetAt(i, &user)) && SUCCEEDED(user->GetSid(&sid)) && sid && _wcsicmp(sid, storedSid) == 0) {
                credential_ = new(std::nothrow) UnlockCredential();
                if (credential_ && FAILED(credential_->Initialize(scenario_, user))) ReleaseCredential();
            }
            CoTaskMemFree(sid); if (user) user->Release();
            if (credential_) break;
        }
        if (credential_) { *count = 1; *defaultIndex = 0; *autoLogon = TRUE; }
        return S_OK;
    }
    IFACEMETHODIMP GetCredentialAt(DWORD index, ICredentialProviderCredential **credential) override
    { if (index || !credential_ || !credential) return E_INVALIDARG; return credential_->QueryInterface(IID_PPV_ARGS(credential)); }
    IFACEMETHODIMP SetUserArray(ICredentialProviderUserArray *users) override
    { if (users_) users_->Release(); users_ = users; if (users_) users_->AddRef(); return S_OK; }
private:
    static DWORD WINAPI Poll(void *value)
    {
        UnlockProvider *self = static_cast<UnlockProvider *>(value);
        while (WaitForSingleObject(self->stop_, 1000) == WAIT_TIMEOUT) {
            const bool ready = RequestReady();
            if (ready != self->lastReady_) {
                self->lastReady_ = ready;
                ICredentialProviderEvents *events = nullptr;
                UINT_PTR context = 0;
                EnterCriticalSection(&self->lock_);
                if (self->events_) { events = self->events_; events->AddRef(); context = self->context_; }
                LeaveCriticalSection(&self->lock_);
                if (events) { events->CredentialsChanged(context); events->Release(); }
            }
        }
        self->Release();
        return 0;
    }
    void ReleaseCredential() { if (credential_) { credential_->Release(); credential_ = nullptr; } }
    ~UnlockProvider()
    { UnAdvise(); ReleaseCredential(); if (users_) users_->Release(); DeleteCriticalSection(&lock_); InterlockedDecrement(&g_dllRefs); }
    long refs_; CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario_; ICredentialProviderUserArray *users_; UnlockCredential *credential_;
    ICredentialProviderEvents *events_; UINT_PTR context_; HANDLE stop_, thread_; bool lastReady_; CRITICAL_SECTION lock_;
};

class Factory final : public IClassFactory
{
public:
    Factory() : refs_(1) { InterlockedIncrement(&g_dllRefs); }
    IFACEMETHODIMP QueryInterface(REFIID iid, void **out) override
    { if (!out) return E_INVALIDARG; *out = nullptr; if (iid != IID_IUnknown && iid != IID_IClassFactory) return E_NOINTERFACE; *out = this; AddRef(); return S_OK; }
    IFACEMETHODIMP_(ULONG) AddRef() override { return InterlockedIncrement(&refs_); }
    IFACEMETHODIMP_(ULONG) Release() override { ULONG n = InterlockedDecrement(&refs_); if (!n) delete this; return n; }
    IFACEMETHODIMP CreateInstance(IUnknown *outer, REFIID iid, void **out) override
    { if (outer) return CLASS_E_NOAGGREGATION; UnlockProvider *p = new(std::nothrow) UnlockProvider(); if (!p) return E_OUTOFMEMORY; HRESULT hr = p->QueryInterface(iid, out); p->Release(); return hr; }
    IFACEMETHODIMP LockServer(BOOL lock) override { lock ? InterlockedIncrement(&g_dllRefs) : InterlockedDecrement(&g_dllRefs); return S_OK; }
private: ~Factory() { InterlockedDecrement(&g_dllRefs); } long refs_;
};

STDAPI DllCanUnloadNow() { return g_dllRefs ? S_FALSE : S_OK; }
STDAPI DllGetClassObject(REFCLSID clsid, REFIID iid, void **out)
{
    if (clsid != CLSID_WindowsProtectUnlock) return CLASS_E_CLASSNOTAVAILABLE;
    Factory *factory = new(std::nothrow) Factory(); if (!factory) return E_OUTOFMEMORY;
    HRESULT hr = factory->QueryInterface(iid, out); factory->Release(); return hr;
}
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *)
{ if (reason == DLL_PROCESS_ATTACH) { g_instance = instance; DisableThreadLibraryCalls(instance); } return TRUE; }
