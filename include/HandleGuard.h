#pragma once
#include <windows.h>

class HandleGuard {
public:
	explicit HandleGuard(HANDLE h);
	~HandleGuard();

	HANDLE get() const;

private:
	HANDLE handle;
};
