#include "util.h"
#include <windows.h>
#include <roapi.h>
#include <winerror.h>
#include <winstring.h>
#include <MddBootstrap.h>
#include <WindowsAppSDK-VersionInfo.h>
#include <stdint.h>

typedef struct IAppNotificationManagerStatics IAppNotificationManagerStatics;
typedef struct IAppNotificationManager IAppNotificationManager;
typedef struct IAppNotificationFactory IAppNotificationFactory;
typedef struct IAppNotification IAppNotification;

typedef struct {
	IInspectableVtbl iinspectable_vtbl;
	HRESULT (STDMETHODCALLTYPE *Default)(IAppNotificationManagerStatics *this, IAppNotificationManager **result);
} IAppNotificationManagerStaticsVtbl;

typedef struct {
	IInspectableVtbl iinspectable_vtbl;
	HRESULT (STDMETHODCALLTYPE *Register)(IAppNotificationManager *this);
	HRESULT (STDMETHODCALLTYPE *Unregister)(IAppNotificationManager *this);
	HRESULT (STDMETHODCALLTYPE *UnregisterAll)(IAppNotificationManager *this);
	HRESULT (STDMETHODCALLTYPE *NotificationInvoked)(IAppNotificationManager *this, void *handler, uint64_t *result);
	HRESULT (STDMETHODCALLTYPE *RemoveNotificationInvoked)(IAppNotificationManager *this, uint64_t token);
	HRESULT (STDMETHODCALLTYPE *Show)(IAppNotificationManager *this, IAppNotification *notification);
	HRESULT (STDMETHODCALLTYPE *UpdateAsync)(IAppNotificationManager *this, void *data, HSTRING tag, HSTRING group, void **result);
	HRESULT (STDMETHODCALLTYPE *UpdateAsync2)(IAppNotificationManager *this, void *data, HSTRING tag, void **result);
	HRESULT (STDMETHODCALLTYPE *Setting)(IAppNotificationManager *this, void *result);
	HRESULT (STDMETHODCALLTYPE *RemoveByIdAsync)(IAppNotificationManager *this, uint32_t notificationid, void **result);
	HRESULT (STDMETHODCALLTYPE *RemoveByTagAsync)(IAppNotificationManager *this, HSTRING tag, void **result);
	HRESULT (STDMETHODCALLTYPE *RemoveByTagAndGroupAsync)(IAppNotificationManager *this, HSTRING tag, HSTRING group, void **result);
	HRESULT (STDMETHODCALLTYPE *RemoveByGroupAsync)(IAppNotificationManager *this, HSTRING group, void **result);
	HRESULT (STDMETHODCALLTYPE *RemoveAllAsync)(IAppNotificationManager *this, void **result);
	HRESULT (STDMETHODCALLTYPE *GetAllAsync)(IAppNotificationManager *this, void **result);
} IAppNotificationManagerVtbl;

typedef struct {
	IInspectableVtbl iinspectable_vtbl;
	HRESULT (STDMETHODCALLTYPE *CreateInstance)(IAppNotificationFactory *this, HSTRING payload, IAppNotification **result);
} IAppNotificationFactoryVtbl;

typedef struct {
	IInspectableVtbl iinspectable_vtbl;
	HRESULT (STDMETHODCALLTYPE *Tag)(IAppNotification *this, HSTRING *result);
	HRESULT (STDMETHODCALLTYPE *SetTag)(IAppNotification *this, HSTRING value);
	HRESULT (STDMETHODCALLTYPE *Group)(IAppNotification *this, HSTRING *result);
	HRESULT (STDMETHODCALLTYPE *SetGroup)(IAppNotification *this, HSTRING value);
	HRESULT (STDMETHODCALLTYPE *Id)(IAppNotification *this, uint32_t *result);
	HRESULT (STDMETHODCALLTYPE *Payload)(IAppNotification *this, HSTRING *result);
	HRESULT (STDMETHODCALLTYPE *Progress)(IAppNotification *this, void **result);
	HRESULT (STDMETHODCALLTYPE *SetProgress)(IAppNotification *this, void *value);
	HRESULT (STDMETHODCALLTYPE *Expiration)(IAppNotification *this, int64_t *result);
	HRESULT (STDMETHODCALLTYPE *SetExpiration)(IAppNotification *this, int64_t value);
	HRESULT (STDMETHODCALLTYPE *ExpiresOnReboot)(IAppNotification *this, BOOL *result);
	HRESULT (STDMETHODCALLTYPE *SetExpiresOnReboot)(IAppNotification *this, BOOL value);
	HRESULT (STDMETHODCALLTYPE *Priority)(IAppNotification *this, void *result);
	HRESULT (STDMETHODCALLTYPE *SetPriority)(IAppNotification *this, int32_t value);
	HRESULT (STDMETHODCALLTYPE *SuppressDisplay)(IAppNotification *this, BOOL *result);
	HRESULT (STDMETHODCALLTYPE *SetSuppressDisplay)(IAppNotification *this, BOOL value);
} IAppNotificationVtbl;

struct IAppNotificationManagerStatics { IAppNotificationManagerStaticsVtbl *vtbl; };
struct IAppNotificationManager { IAppNotificationManagerVtbl *vtbl; };
struct IAppNotificationFactory { IAppNotificationFactoryVtbl *vtbl; };
struct IAppNotification { IAppNotificationVtbl *vtbl; };

static BOOL logging_enabled; // Logging enabled for the main thread (same as in gui.c).
static IAppNotificationManager *notif_manager;
static IAppNotificationFactory *notif_factory;

// Should be called exactly once, before sending any notifications.
HRESULT init_appnotifications(BOOL logging_enabled_) {
	logging_enabled = logging_enabled_;

	HRESULT result = RoInitialize(RO_INIT_SINGLETHREADED);
	if (!SUCCEEDED(result)) return LOG_PRINT_HRESULT(result, "RoInitialize failed");

	PACKAGE_VERSION min_version;
	min_version.Revision = 0;
	min_version.Build = 4;
	min_version.Minor = 6;
	min_version.Major = 2;

	result = MddBootstrapInitialize2(
		0x00020006,
		WINDOWSAPPSDK_RELEASE_VERSION_TAG_W,
		min_version,
		MddBootstrapInitializeOptions_OnNoMatch_ShowUI
	);
	if (!SUCCEEDED(result)) return LOG_PRINT_HRESULT(result, "MddBootstrapInitialize2 failed");

	uint16_t notifman_id_wstr[] = L"Microsoft.Windows.AppNotifications.AppNotificationManager";
	HSTRING_HEADER _notifman_id_head;
	HSTRING notifman_id;
	result = WindowsCreateStringReference(notifman_id_wstr, (sizeof(notifman_id_wstr) / 2) - 1, &_notifman_id_head, &notifman_id);
	if (!SUCCEEDED(result)) return LOG_PRINT_HRESULT(result, "WindowsCreateStringReference failed");

	GUID notifmanstatics_iid = { 0x6CFC0D8D, 0x84A3, 0x5592, { 0xB4, 0xC6, 0xE3, 0xE7, 0xE7, 0xC6, 0x80, 0xE4 } };

	IAppNotificationManagerStatics *statics;
	result = RoGetActivationFactory(notifman_id, &notifmanstatics_iid, (void **)&statics);
	if (!SUCCEEDED(result)) return LOG_PRINT_HRESULT(result, "RoGetActivationFactory failed for IAppNotificationManagerStatics");
	
	result = statics->vtbl->Default(statics, &notif_manager);
	if (!SUCCEEDED(result)) return LOG_PRINT_HRESULT(result, "Failed to get default IAppNotificationManager");

	result = notif_manager->vtbl->Register(notif_manager);
	if (!SUCCEEDED(result)) return LOG_PRINT_HRESULT(result, "Failed to register default AppNotificationManager");

	uint16_t notif_id_wstr[] = L"Microsoft.Windows.AppNotifications.AppNotification";
	HSTRING_HEADER _notif_id_head;
	HSTRING notif_id;
	result = WindowsCreateStringReference(notif_id_wstr, (sizeof(notif_id_wstr) / 2) - 1, &_notif_id_head, &notif_id);
	if (!SUCCEEDED(result)) return LOG_PRINT_HRESULT(result, "WindowsCreateStringReference failed");

	GUID notiffactory_iid = {0x9FFEE485, 0x184A, 0x5C65, { 0x87, 0xA9, 0xC1, 0xD9, 0x44, 0x69, 0xDB, 0xE7 } };

	result = RoGetActivationFactory(notif_id, &notiffactory_iid, (void **)&notif_factory);
	if (!SUCCEEDED(result)) return LOG_PRINT_HRESULT(result, "RoGetActivationFactory failed for IAppNotificationFactory");

	return result;
}

HRESULT send_threat_found_notification(const char *threat_path) {
	int threat_path_wstr_sz = MultiByteToWideChar(CP_UTF8, 0, threat_path, -1, NULL, 0) * 2;
	if (threat_path_wstr_sz == 0) {
		LOG_PRINT_WIN_ERR(GetLastError(), "Failed to get UTF-16 size of threat path");
		return E_UNEXPECTED;
	}

	const uint16_t payload_start[] = 
		L"<toast>" \
		L" <visual>" \
		L"  <binding template=\"ToastGeneric\">" \
		L"   <text>Threat found</text>" \
		L"   <text>";
	const uint16_t payload_end[] = 
		L"   </text>" \
		L"  </binding>" \
		L" </visual>" \
		L"</toast>";

	size_t payload_wstr_sz = sizeof(payload_start) - 2 + threat_path_wstr_sz - 2 + sizeof(payload_end);
	uint16_t *payload_wstr = malloc(payload_wstr_sz);

	memcpy(payload_wstr, payload_start, sizeof(payload_start) - 2);

	if (MultiByteToWideChar(CP_UTF8, 0, threat_path, -1, payload_wstr + sizeof(payload_start) / 2 - 1, threat_path_wstr_sz / 2) == 0) {
		LOG_PRINT_WIN_ERR(GetLastError(), "Failed to convert threat path to UTF-16");
		free(payload_wstr);
		return E_UNEXPECTED;
	}

	memcpy(payload_wstr + sizeof(payload_start) / 2 - 1 + threat_path_wstr_sz / 2 - 1, payload_end, sizeof(payload_end));

	HSTRING_HEADER _payload_head;
	HSTRING payload;
	HRESULT result = WindowsCreateStringReference(payload_wstr, payload_wstr_sz / 2 - 1, &_payload_head, &payload);
	if (!SUCCEEDED(result)) {
		free(payload_wstr);
		return LOG_PRINT_HRESULT(result, "WindowsCreateStringReference failed");
	}

	IAppNotification *notification;
	result = notif_factory->vtbl->CreateInstance(notif_factory, payload, &notification);
	// Undocumented (I think) error codes:
	// 	0xC00CE504: I got this when leaving a stray '"' in the payload.
	// 	0xC00CE508: I got this when trying to add text without a leading "<text>" and trailing "</text>".
	// 	0xC00CE556: Payload is invalid (just in general I think, for example if "<toast>" is missing).
	if (!SUCCEEDED(result)) {
		free(payload_wstr);
		return LOG_PRINT_HRESULT(result, "Failed to create notification");
	}

	result = notif_manager->vtbl->Show(notif_manager, notification);
	if (!SUCCEEDED(result)) {
		free(payload_wstr);
		return LOG_PRINT_HRESULT(result, "Failed to show notification");
	}
	return result;
}

// Should be called exactly once after no more notifications will be created
// (e.g. before the app exits).
void uninit_appnotifications() {
	MddBootstrapShutdown();
	RoUninitialize();
}
