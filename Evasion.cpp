#include "Evasion.h"

Evasion::Evasion() {};

BOOL Evasion::isBeingDebugging(void) {
	if (checkDebugger()) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}