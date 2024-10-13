#include "HandleGuard.h"

HandleGuard::HandleGuard(HANDLE h) : handle(h) {}

HandleGuard::~HandleGuard() {
	if (handle != INVALID_HANDLE_VALUE) {
		CloseHandle(handle);
	}
}

HANDLE HandleGuard::get() const {
	return handle;
}
